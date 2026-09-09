/**
 * WebRTC Peer Transport Layer.
 *
 * Coordinates WebSocket signaling negotiation with local WebRTCConnection.
 * Pure signaling switchboard integration: strictly zero file data or cryptographic keys
 * are ever transmitted through the signaling server.
 */

import { WebRTCConnection, WebRTCStates, DEFAULT_RTC_CONFIG } from './webrtcConnection.js';
import { SignalingMessageTypes } from '../protocol/types.js';

/**
 * High-level WebRTC Peer Transport.
 */
export class WebRTCPeerTransport {
  /**
   * @param {Object} options
   * @param {'initiator' | 'responder'} options.role - Local peer role
   * @param {string} options.sessionId - Ephemeral session identifier
   * @param {string} options.peerId - Unique local peer identifier
   * @param {string} options.token - Session authentication token
   * @param {string} [options.targetPeerId] - Target peer identifier
   * @param {string} [options.signalingUrl] - WebSocket signaling URL (e.g. ws://localhost:3000)
   * @param {WebSocket} [options.ws] - Pre-existing WebSocket instance
   * @param {Function} [options.WebSocketClass] - Custom WebSocket constructor
   * @param {Function} [options.RTCPeerConnection] - Custom RTCPeerConnection constructor
   * @param {Object} [options.rtcConfig] - WebRTC configuration (defaults to Google STUN servers)
   * @param {number} [options.highWaterMark] - Flow control high water mark
   * @param {number} [options.lowWaterMark] - Flow control low water mark
   */
  constructor({
    role = 'initiator',
    sessionId,
    peerId,
    token,
    targetPeerId,
    signalingUrl,
    ws,
    WebSocketClass = globalThis.WebSocket,
    RTCPeerConnection = globalThis.RTCPeerConnection,
    rtcConfig = DEFAULT_RTC_CONFIG,
    highWaterMark,
    lowWaterMark
  }) {
    if (!sessionId || !peerId || !token) {
      throw new Error('sessionId, peerId, and token are required to initialize WebRTCPeerTransport');
    }

    this.role = role;
    this.isInitiator = role === 'initiator';
    this.sessionId = sessionId;
    this.peerId = peerId;
    this.token = token;
    this.targetPeerId = targetPeerId || null;

    this.signalingUrl = signalingUrl;
    this.WebSocketClass = WebSocketClass;
    this.ws = ws || null;

    this.webrtcConn = new WebRTCConnection({
      isInitiator: this.isInitiator,
      RTCPeerConnection,
      rtcConfig,
      highWaterMark,
      lowWaterMark
    });

    this.listeners = new Map();
    this.closed = false;
    this.heartbeatTimer = null;
    this.pendingLocalCandidates = [];

    this._bindWebRTCListeners();
  }

  on(event, fn) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(fn);
    return () => this.removeListener(event, fn);
  }

  removeListener(event, fn) {
    this.listeners.get(event)?.delete(fn);
  }

  emit(event, ...args) {
    const handlers = this.listeners.get(event);
    if (!handlers) return;
    for (const handler of handlers) {
      try {
        handler(...args);
      } catch (err) {
        console.error(`Unhandled error in WebRTCPeerTransport '${event}' listener:`, err);
      }
    }
  }

  getState() {
    return this.webrtcConn.getState();
  }

  isOpen() {
    return this.webrtcConn.isOpen();
  }

  /**
   * Connect to signaling server and join session room.
   *
   * @returns {Promise<void>} Resolves when signaling connection is open and JOIN is sent.
   */
  async connect() {
    if (!this.ws) {
      if (!this.signalingUrl) {
        throw new Error('Neither pre-existing WebSocket nor signalingUrl was provided');
      }
      if (!this.WebSocketClass) {
        throw new Error('WebSocket implementation is not available in this environment');
      }

      this.ws = new this.WebSocketClass(this.signalingUrl);
    }

    this._setupSignalingListeners();

    if (this.ws.readyState === 1 /* OPEN */) {
      this._sendSignalingMessage({
        type: SignalingMessageTypes.JOIN,
        sessionId: this.sessionId,
        peerId: this.peerId,
        token: this.token
      });
      this._startSignalingHeartbeat();
      return;
    }

    return new Promise((resolve, reject) => {
      const onOpen = () => {
        cleanup();
        this._sendSignalingMessage({
          type: SignalingMessageTypes.JOIN,
          sessionId: this.sessionId,
          peerId: this.peerId,
          token: this.token
        });
        this._startSignalingHeartbeat();
        resolve();
      };

      const onError = (err) => {
        cleanup();
        reject(new Error(`Signaling connection failed: ${err?.message || 'unknown error'}`));
      };

      const cleanup = () => {
        if (typeof this.ws.removeEventListener === 'function') {
          this.ws.removeEventListener('open', onOpen);
          this.ws.removeEventListener('error', onError);
        } else if (typeof this.ws.removeListener === 'function') {
          this.ws.removeListener('open', onOpen);
          this.ws.removeListener('error', onError);
        }
      };

      if (typeof this.ws.addEventListener === 'function') {
        this.ws.addEventListener('open', onOpen);
        this.ws.addEventListener('error', onError);
      } else if (typeof this.ws.on === 'function') {
        this.ws.on('open', onOpen);
        this.ws.on('error', onError);
      }
    });
  }

  /**
   * Send a binary Phase 3 protocol frame across the WebRTC DataChannel.
   *
   * @param {Uint8Array|ArrayBuffer} frame
   * @returns {Promise<void>}
   */
  async send(frame) {
    return this.webrtcConn.send(frame);
  }

  /**
   * Close peer transport, DataChannel, RTCPeerConnection, and signaling connection.
   */
  close() {
    if (this.closed) return;
    this.closed = true;

    this._stopSignalingHeartbeat();
    this.pendingLocalCandidates = [];
    this.webrtcConn.close();

    if (this.ws) {
      try {
        if (this.ws.readyState === 1 /* OPEN */) {
          this.ws.close(1000, 'Peer closed transport');
        }
      } catch {
        // Ignored
      }
      this.ws = null;
    }

    this.emit('close');
  }

  // --- Private Signaling & WebRTC Wiring ---

  _bindWebRTCListeners() {
    this.webrtcConn.on('open', () => this.emit('open'));
    this.webrtcConn.on('frame', (data) => this.emit('frame', data));
    this.webrtcConn.on('error', (err) => this.emit('error', err));
    this.webrtcConn.on('stateChange', (st) => this.emit('stateChange', st));

    // Forward local ICE candidate across signaling, buffering if target peer not yet bound
    this.webrtcConn.on('icecandidate', (candidate) => {
      if (!candidate) return;
      if (this.targetPeerId) {
        this._sendSignalingMessage({
          type: SignalingMessageTypes.ICE_CANDIDATE,
          sessionId: this.sessionId,
          peerId: this.peerId,
          targetPeerId: this.targetPeerId,
          token: this.token,
          payload: candidate
        });
      } else {
        this.pendingLocalCandidates.push(candidate);
      }
    });
  }

  _flushPendingLocalCandidates() {
    if (this.targetPeerId && this.pendingLocalCandidates.length > 0) {
      for (const candidate of this.pendingLocalCandidates) {
        this._sendSignalingMessage({
          type: SignalingMessageTypes.ICE_CANDIDATE,
          sessionId: this.sessionId,
          peerId: this.peerId,
          targetPeerId: this.targetPeerId,
          token: this.token,
          payload: candidate
        });
      }
      this.pendingLocalCandidates = [];
    }
  }

  _setupSignalingListeners() {
    const ws = this.ws;

    const on = (event, fn) => {
      if (typeof ws.addEventListener === 'function') {
        ws.addEventListener(event, fn);
      } else if (typeof ws.on === 'function') {
        ws.on(event, fn);
      }
    };

    on('message', (event) => {
      let rawData = event?.data !== undefined ? event.data : event;
      if (typeof rawData !== 'string') {
        // Signaling server strictly uses JSON text frames
        return;
      }

      try {
        const msg = JSON.parse(rawData);
        this._handleSignalingMessage(msg);
      } catch (err) {
        this.emit('error', new Error(`Malformed signaling message JSON: ${err.message}`));
      }
    });

    on('open', () => {
      this._startSignalingHeartbeat();
    });

    on('close', (event) => {
      this._stopSignalingHeartbeat();
      if (!this.closed) {
        this.emit('signalingClose', {
          code: event?.code || 1000,
          reason: event?.reason?.toString() || 'Signaling connection closed'
        });
      }
    });

    on('error', (err) => {
      this._stopSignalingHeartbeat();
      if (!this.closed) {
        // If WebRTC connection is already established and open, non-fatal signaling errors shouldn't crash P2P transfer
        if (this.webrtcConn && this.webrtcConn.isOpen()) {
          console.warn('[Signaling] Non-fatal signaling socket error while DataChannel is open:', err?.message || 'unknown');
          return;
        }
        this.emit('error', new Error(`Signaling error: ${err?.message || 'unknown'}`));
      }
    });
  }

  async _handleSignalingMessage(msg) {
    if (!msg || typeof msg !== 'object') return;

    if (msg.type === SignalingMessageTypes.PONG || msg.type === 'PONG') {
      return;
    }

    // If counterpart peer joins or reconnects, bind the new target peer ID
    if (msg.type === SignalingMessageTypes.PEER_JOINED && msg.peerId !== this.peerId) {
      this.targetPeerId = msg.peerId;
      this._flushPendingLocalCandidates();
    }

    // Allow renegotiated SDP offer from legitimate sender reconnecting to update targetPeerId
    if (msg.type === SignalingMessageTypes.SDP_OFFER && !this.isInitiator && typeof msg.peerId === 'string' && msg.peerId.startsWith('tx-')) {
      this.targetPeerId = msg.peerId;
      this._flushPendingLocalCandidates();
    }

    // Reject rogue SDP/ICE messages from unexpected peers or messages lacking peerId once target peer is established
    const isMediaNegotiation =
      msg.type === SignalingMessageTypes.SDP_OFFER ||
      msg.type === SignalingMessageTypes.SDP_ANSWER ||
      msg.type === SignalingMessageTypes.ICE_CANDIDATE;

    if (isMediaNegotiation) {
      if (!this.targetPeerId) {
        this.targetPeerId = msg.peerId;
        this._flushPendingLocalCandidates();
      } else if (msg.peerId !== this.targetPeerId) {
        this.emit(
          'error',
          new Error(
            `Unauthorized signaling message: missing or mismatched sender peerId '${msg.peerId}' does not match bound peer '${this.targetPeerId}'`
          )
        );
        return;
      }
    }

    switch (msg.type) {
      case SignalingMessageTypes.PEER_JOINED: {
        // Notification that a peer joined
        if (msg.peerId !== this.peerId) {
          this.targetPeerId = msg.peerId;
          this.emit('peerJoined', msg.peerId);

          if (this.isInitiator) {
            // Initiator creates DataChannel and sends SDP offer
            try {
              this.webrtcConn.initDataChannel();
              const offer = await this.webrtcConn.createOffer();
              this._sendSignalingMessage({
                type: SignalingMessageTypes.SDP_OFFER,
                sessionId: this.sessionId,
                peerId: this.peerId,
                targetPeerId: this.targetPeerId,
                token: this.token,
                payload: offer
              });
            } catch (err) {
              this.emit('error', new Error(`Failed to create/send SDP offer: ${err.message}`));
            }
          }
        }
        break;
      }

      case SignalingMessageTypes.SDP_OFFER: {
        if (!this.isInitiator && msg.payload) {
          if (!this.targetPeerId) {
            this.targetPeerId = msg.peerId;
          }
          try {
            await this.webrtcConn.setRemoteDescription(msg.payload);
            const answer = await this.webrtcConn.createAnswer();
            this._sendSignalingMessage({
              type: SignalingMessageTypes.SDP_ANSWER,
              sessionId: this.sessionId,
              peerId: this.peerId,
              targetPeerId: this.targetPeerId,
              token: this.token,
              payload: answer
            });
          } catch (err) {
            this.emit('error', new Error(`Failed to handle SDP offer/answer: ${err.message}`));
          }
        }
        break;
      }

      case SignalingMessageTypes.SDP_ANSWER: {
        if (this.isInitiator && msg.payload) {
          try {
            await this.webrtcConn.setRemoteDescription(msg.payload);
          } catch (err) {
            this.emit('error', new Error(`Failed to set remote SDP answer: ${err.message}`));
          }
        }
        break;
      }

      case SignalingMessageTypes.ICE_CANDIDATE: {
        if (msg.payload && msg.payload.candidate) {
          try {
            await this.webrtcConn.addIceCandidate(msg.payload);
          } catch (err) {
            console.warn('[Signaling] Ignored non-fatal incoming ICE candidate error:', err.message);
          }
        }
        break;
      }

      case SignalingMessageTypes.PEER_LEFT: {
        this.emit('peerLeft', msg.peerId);
        if (this.targetPeerId === msg.peerId) {
          this.targetPeerId = null;
        }
        if (!this.webrtcConn.isOpen() && this.role !== 'responder') {
          this.close();
        }
        break;
      }

      case SignalingMessageTypes.ERROR: {
        this.emit('error', new Error(`Signaling server error: ${msg.error}`));
        break;
      }
    }
  }

  _sendSignalingMessage(obj) {
    if (!this.ws || this.ws.readyState !== 1 /* OPEN */) {
      return;
    }
    this.ws.send(JSON.stringify(obj));
  }

  _startSignalingHeartbeat() {
    this._stopSignalingHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (!this.closed && this.ws && this.ws.readyState === 1 /* OPEN */) {
        try {
          this._sendSignalingMessage({
            type: SignalingMessageTypes.PING,
            sessionId: this.sessionId,
            peerId: this.peerId,
            token: this.token
          });
        } catch {
          // Ignored
        }
      }
    }, 15000);
    if (this.heartbeatTimer && typeof this.heartbeatTimer.unref === 'function') {
      this.heartbeatTimer.unref();
    }
  }

  _stopSignalingHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}
