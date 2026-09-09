/**
 * WebRTC Peer Transport Layer.
 *
 * Coordinates WebSocket signaling negotiation with local WebRTCConnection.
 * Pure signaling switchboard integration: strictly zero file data or cryptographic keys
 * are ever transmitted through the signaling server.
 */

import { WebRTCConnection, WebRTCStates, DEFAULT_RTC_CONFIG } from './webrtcConnection.js';
import { SignalingMessageTypes } from '../protocol/types.js';

function uint8ArrayToBase64(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  }
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(base64) {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

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
   * @param {boolean} [options.forceTunnel=false] - Force zero-knowledge WebSocket tunnel mode
   * @param {number} [options.iceFallbackTimeoutMs=6000] - Timeout before fallback to tunnel
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
    lowWaterMark,
    forceTunnel = false,
    iceFallbackTimeoutMs = 6000
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

    // Dual-mode transport: 'p2p' (direct WebRTC DataChannel) or 'tunnel' (zero-knowledge WebSocket relay)
    this.transportMode = forceTunnel ? 'tunnel' : 'p2p';
    this.tunnelOpen = forceTunnel;
    this.fallbackTimer = null;
    this.iceFallbackTimeoutMs = iceFallbackTimeoutMs;
    this.incomingFragments = new Map();

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
    if (this.transportMode === 'tunnel') {
      return this.isOpen() ? WebRTCStates.CONNECTED : WebRTCStates.CONNECTING;
    }
    return this.webrtcConn.getState();
  }

  isOpen() {
    if (this.transportMode === 'tunnel') {
      return !this.closed && this.tunnelOpen && this.ws?.readyState === 1 && !!this.targetPeerId;
    }
    return this.webrtcConn.isOpen();
  }

  getTransportMode() {
    return this.transportMode;
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
   * Send a binary Phase 3 protocol frame across the active transport (DataChannel or Tunnel).
   *
   * @param {Uint8Array|ArrayBuffer} frame
   * @returns {Promise<void>}
   */
  async send(frame) {
    if (this.closed) {
      throw new Error('Cannot send data: transport is closed');
    }

    if (this.transportMode === 'tunnel') {
      return this._sendTunnelFrame(frame);
    }

    try {
      return await this.webrtcConn.send(frame);
    } catch (err) {
      const msg = (err?.message || '').toLowerCase();
      // If DataChannel closed mid-transfer, drain failed, or connection reset
      if (
        !this.closed &&
        (msg.includes('datachannel closed') ||
         msg.includes('connection closed') ||
         msg.includes('datachannel is not open') ||
         msg.includes('drain') ||
         msg.includes('rtcpeerconnection failed') ||
         msg.includes('ice connection failed'))
      ) {
        console.warn(
          `[Transport] WebRTC DataChannel failed during send (${err.message}); switching seamlessly to zero-knowledge WebSocket tunnel`
        );
        this._switchToTunnelMode(err.message);
        return this._sendTunnelFrame(frame);
      }
      throw err;
    }
  }

  _sendTunnelFrame(frame) {
    if (!this.ws || this.ws.readyState !== 1 /* OPEN */ || !this.targetPeerId) {
      throw new Error('Cannot send data: Tunnel WebSocket is not connected to peer');
    }

    const bytes = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
    const FRAGMENT_SIZE = 32 * 1024; // 32 KB binary -> ~43 KB base64 (strictly under 64 KB)

    if (bytes.byteLength <= FRAGMENT_SIZE) {
      this._sendSignalingMessage({
        type: SignalingMessageTypes.TUNNEL_FRAME,
        sessionId: this.sessionId,
        peerId: this.peerId,
        targetPeerId: this.targetPeerId,
        token: this.token,
        payload: {
          frame: uint8ArrayToBase64(bytes),
          frag: 0,
          total: 1
        }
      });
    } else {
      const total = Math.ceil(bytes.byteLength / FRAGMENT_SIZE);
      const frameId = Math.random().toString(36).slice(2, 8);
      for (let i = 0; i < total; i++) {
        const slice = bytes.subarray(i * FRAGMENT_SIZE, Math.min((i + 1) * FRAGMENT_SIZE, bytes.byteLength));
        this._sendSignalingMessage({
          type: SignalingMessageTypes.TUNNEL_FRAME,
          sessionId: this.sessionId,
          peerId: this.peerId,
          targetPeerId: this.targetPeerId,
          token: this.token,
          payload: {
            frame: uint8ArrayToBase64(slice),
            id: frameId,
            frag: i,
            total
          }
        });
      }
    }
  }

  /**
   * Close peer transport, DataChannel, RTCPeerConnection, and signaling connection.
   */
  close() {
    if (this.closed) return;
    this.closed = true;

    this._stopSignalingHeartbeat();
    this._stopFallbackWatchdog();
    this.tunnelOpen = false;
    this.incomingFragments.clear();
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
    this.webrtcConn.on('open', () => {
      if (this.transportMode === 'p2p') {
        this._stopFallbackWatchdog();
        this.emit('open');
      }
    });

    this.webrtcConn.on('frame', (data) => {
      if (this.transportMode === 'p2p') {
        this.emit('frame', data);
      }
    });

    this.webrtcConn.on('channelClose', () => {
      if (this.transportMode === 'p2p' && !this.closed) {
        console.warn('[Transport] WebRTC DataChannel closed; activating zero-knowledge WebSocket tunnel fallback');
        this._switchToTunnelMode('DataChannel closed');
      }
    });

    this.webrtcConn.on('error', (err) => {
      const msg = (err?.message || '').toLowerCase();
      if (
        this.transportMode === 'p2p' &&
        !this.closed &&
        (msg.includes('rtcpeerconnection failed') ||
         msg.includes('ice connection failed') ||
         msg.includes('datachannel') ||
         msg.includes('connection closed') ||
         msg.includes('drain'))
      ) {
        console.warn(`[Transport] WebRTC error (${err.message}); activating zero-knowledge WebSocket tunnel fallback`);
        this._switchToTunnelMode(err.message);
        return;
      }
      this.emit('error', err);
    });

    this.webrtcConn.on('stateChange', (st) => {
      if (this.transportMode === 'tunnel') return;
      if (st === WebRTCStates.FAILED) {
        console.warn('[Transport] WebRTC connection state changed to FAILED; activating tunnel fallback');
        this._switchToTunnelMode('WebRTC state FAILED');
        return;
      }
      this.emit('stateChange', st);
    });

    // Forward local ICE candidate across signaling, buffering if target peer not yet bound
    this.webrtcConn.on('icecandidate', (candidate) => {
      if (!candidate || this.transportMode === 'tunnel') return;
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

  _startFallbackWatchdog() {
    if (this.fallbackTimer || this.transportMode === 'tunnel' || this.closed) return;
    this.fallbackTimer = setTimeout(() => {
      if (this.transportMode === 'p2p' && !this.webrtcConn.isOpen() && !this.closed) {
        console.warn('[Transport] WebRTC connection timeout reached; activating tunnel fallback');
        this._switchToTunnelMode('ICE negotiation timeout');
      }
    }, this.iceFallbackTimeoutMs);
    if (this.fallbackTimer && typeof this.fallbackTimer.unref === 'function') {
      this.fallbackTimer.unref();
    }
  }

  _stopFallbackWatchdog() {
    if (this.fallbackTimer) {
      clearTimeout(this.fallbackTimer);
      this.fallbackTimer = null;
    }
  }

  _switchToTunnelMode(reason) {
    if (this.transportMode === 'tunnel' || this.closed) return;
    this.transportMode = 'tunnel';
    this._stopFallbackWatchdog();

    console.log(`[Transport] Active transport mode switched to TUNNEL (${reason})`);

    try {
      this.webrtcConn.close();
    } catch {}

    this.tunnelOpen = true;
    this.emit('modeChange', 'tunnel');
    this.emit('stateChange', WebRTCStates.CONNECTED);

    if (this.targetPeerId && this.ws && this.ws.readyState === 1 /* OPEN */) {
      queueMicrotask(() => {
        if (!this.closed && this.tunnelOpen) {
          this.emit('open');
        }
      });
    }
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

    // Reject rogue SDP/ICE/TUNNEL messages from unexpected peers or messages lacking peerId once target peer is established
    const isMediaNegotiation =
      msg.type === SignalingMessageTypes.SDP_OFFER ||
      msg.type === SignalingMessageTypes.SDP_ANSWER ||
      msg.type === SignalingMessageTypes.ICE_CANDIDATE ||
      msg.type === SignalingMessageTypes.TUNNEL_FRAME;

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

          if (this.transportMode === 'tunnel') {
            queueMicrotask(() => {
              if (!this.closed && this.tunnelOpen) {
                this.emit('open');
              }
            });
            return;
          }

          this._startFallbackWatchdog();

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
          if (this.transportMode === 'tunnel') return;
          this._startFallbackWatchdog();
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

      case SignalingMessageTypes.TUNNEL_FRAME: {
        if (this.transportMode !== 'tunnel') {
          this._switchToTunnelMode('Received TUNNEL_FRAME from peer');
        }
        if (msg.payload && typeof msg.payload.frame === 'string') {
          try {
            const partBytes = base64ToUint8Array(msg.payload.frame);
            const total = msg.payload.total || 1;
            const frag = msg.payload.frag || 0;
            const frameId = msg.payload.id || 'single';

            if (total === 1) {
              this.emit('frame', partBytes);
            } else {
              if (!this.incomingFragments.has(frameId)) {
                this.incomingFragments.set(frameId, { total, parts: new Map() });
              }
              const record = this.incomingFragments.get(frameId);
              record.parts.set(frag, partBytes);

              if (record.parts.size === total) {
                this.incomingFragments.delete(frameId);
                let totalLen = 0;
                for (let i = 0; i < total; i++) {
                  totalLen += record.parts.get(i).byteLength;
                }
                const merged = new Uint8Array(totalLen);
                let offset = 0;
                for (let i = 0; i < total; i++) {
                  const part = record.parts.get(i);
                  merged.set(part, offset);
                  offset += part.byteLength;
                }
                this.emit('frame', merged);
              }
            }
          } catch (err) {
            console.error('[Transport] Failed to decode TUNNEL_FRAME payload:', err);
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
