/**
 * WebRTC Connection and DataChannel Abstraction.
 *
 * Manages RTCPeerConnection, RTCDataChannel, ICE candidate queueing,
 * connection state machine, backpressure flow control, and binary framing limits.
 */

import { FlowController } from './flowControl.js';
import { MAX_CHUNK_SIZE } from '../protocol/types.js';

export const WebRTCStates = Object.freeze({
  NEW: 'NEW',
  CONNECTING: 'CONNECTING',
  CONNECTED: 'CONNECTED',
  DISCONNECTED: 'DISCONNECTED',
  FAILED: 'FAILED',
  CLOSED: 'CLOSED'
});

// Maximum allowable frame size: 18-byte chunk header + 256KB chunk payload + 16-byte AES-GCM tag
export const MAX_TRANSPORT_FRAME_SIZE = 18 + MAX_CHUNK_SIZE + 16;

// Maximum number of ICE candidates permitted per session to prevent queue/memory exhaustion
export const MAX_ICE_CANDIDATES = 100;

// Default public STUN servers for NAT traversal across different networks
export const DEFAULT_RTC_CONFIG = Object.freeze({
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
});

/**
 * Isomorphic Event Emitter suitable for both Browser and Node.js environments.
 */
class IsomorphicEventEmitter {
  constructor() {
    this._listeners = new Map();
  }

  on(event, fn) {
    if (!this._listeners.has(event)) {
      this._listeners.set(event, new Set());
    }
    this._listeners.get(event).add(fn);
    return () => this.removeListener(event, fn);
  }

  removeListener(event, fn) {
    this._listeners.get(event)?.delete(fn);
  }

  emit(event, ...args) {
    const handlers = this._listeners.get(event);
    if (!handlers) return;
    for (const handler of handlers) {
      try {
        handler(...args);
      } catch (err) {
        // Prevent listener failures from crashing connection loop
        console.error(`Unhandled error in WebRTCConnection '${event}' listener:`, err);
      }
    }
  }

  removeAllListeners(event) {
    if (event) {
      this._listeners.delete(event);
    } else {
      this._listeners.clear();
    }
  }
}

export class WebRTCConnection extends IsomorphicEventEmitter {
  /**
   * @param {Object} [options]
   * @param {boolean} [options.isInitiator=false] - Whether this peer creates the DataChannel & offer
   * @param {Object} [options.rtcConfig] - RTCConfiguration (defaults to Google STUN servers)
   * @param {Function} [options.RTCPeerConnection] - Custom/mock RTCPeerConnection constructor
   * @param {string} [options.channelLabel='file-transfer'] - Label for DataChannel
   * @param {number} [options.highWaterMark] - Buffer high-water mark for backpressure
   * @param {number} [options.lowWaterMark] - Buffer low-water mark for backpressure
   */
  constructor({
    isInitiator = false,
    rtcConfig = DEFAULT_RTC_CONFIG,
    RTCPeerConnection = globalThis.RTCPeerConnection,
    channelLabel = 'file-transfer',
    highWaterMark,
    lowWaterMark
  } = {}) {
    super();

    if (!RTCPeerConnection) {
      throw new Error('RTCPeerConnection implementation is not available in this environment');
    }

    this.isInitiator = isInitiator;
    this.channelLabel = channelLabel;
    this.state = WebRTCStates.NEW;

    this.flowController = new FlowController({
      highWaterMark: highWaterMark !== undefined ? highWaterMark : undefined,
      lowWaterMark: lowWaterMark !== undefined ? lowWaterMark : undefined
    });

    this.pc = new RTCPeerConnection(rtcConfig);
    this.channel = null;
    this.remoteDescriptionSet = false;
    this.iceCandidateQueue = [];
    this.seenCandidates = new Set();
    this.closed = false;

    this._setupPeerConnectionListeners();
  }

  getState() {
    return this.state;
  }

  isOpen() {
    return this.state === WebRTCStates.CONNECTED && this.channel?.readyState === 'open';
  }

  getQueuedCandidateCount() {
    return this.iceCandidateQueue.length;
  }

  /**
   * Initialize DataChannel (called by initiator).
   *
   * @param {string} [label]
   * @returns {RTCDataChannel}
   */
  initDataChannel(label = this.channelLabel) {
    if (!this.isInitiator) {
      throw new Error('Responder should not initiate DataChannel; wait for ondatachannel event');
    }

    this.channel = this.pc.createDataChannel(label, {
      ordered: true,
      maxRetransmits: undefined,
      maxPacketLifeTime: undefined
    });

    this._setupDataChannel(this.channel);
    return this.channel;
  }

  /**
   * Create SDP Offer (initiator).
   * @returns {Promise<RTCSessionDescriptionInit>}
   */
  async createOffer() {
    this._setState(WebRTCStates.CONNECTING);
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    return offer;
  }

  /**
   * Create SDP Answer (responder).
   * @returns {Promise<RTCSessionDescriptionInit>}
   */
  async createAnswer() {
    this._setState(WebRTCStates.CONNECTING);
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    return answer;
  }

  /**
   * Set Remote Description (SDP offer or answer).
   * Flushes queued ICE candidates upon completion.
   *
   * @param {RTCSessionDescriptionInit} desc
   */
  async setRemoteDescription(desc) {
    if (!desc || typeof desc !== 'object' || typeof desc.sdp !== 'string' || !desc.type) {
      throw new Error('Invalid remote session description');
    }

    await this.pc.setRemoteDescription(desc);
    this.remoteDescriptionSet = true;

    await this._flushQueuedCandidates();
  }

  /**
   * Add ICE candidate received from peer.
   * Queues candidates if remote description is not yet set.
   *
   * @param {RTCIceCandidateInit} candidate
   */
  async addIceCandidate(candidate) {
    if (this.closed) return;

    if (!candidate || typeof candidate !== 'object') {
      throw new Error('Invalid ICE candidate: must be an object');
    }

    // Modern WebRTC end-of-candidates candidate can be null or empty string
    if (candidate.candidate === undefined) {
      throw new Error('Invalid ICE candidate: missing candidate property');
    }

    // Safely ignore end-of-candidates empty string in browser
    if (candidate.candidate === '' || candidate.candidate === null) {
      return;
    }

    // Guard against candidate flooding / resource exhaustion
    if (this.seenCandidates.size >= MAX_ICE_CANDIDATES || this.iceCandidateQueue.length >= MAX_ICE_CANDIDATES) {
      throw new Error(`ICE candidate limit exceeded (maximum ${MAX_ICE_CANDIDATES} candidates allowed)`);
    }

    // Deduplicate candidate
    const candidateKey = `${candidate.candidate}|${candidate.sdpMid}|${candidate.sdpMLineIndex}`;
    if (this.seenCandidates.has(candidateKey)) {
      return; // Safely ignore duplicate
    }
    this.seenCandidates.add(candidateKey);

    if (!this.remoteDescriptionSet) {
      // Remote description not yet set; queue for later
      this.iceCandidateQueue.push(candidate);
      return;
    }

    try {
      await this.pc.addIceCandidate(candidate);
    } catch (err) {
      console.warn('[WebRTC] Ignored non-fatal addIceCandidate error:', err.message);
    }
  }

  /**
   * Send binary protocol frame through DataChannel with flow control backpressure.
   *
   * @param {Uint8Array|ArrayBuffer} data
   * @returns {Promise<void>}
   */
  async send(data) {
    if (this.closed || !this.channel || this.channel.readyState !== 'open') {
      throw new Error(`Cannot send data: DataChannel is not open (readyState: '${this.channel?.readyState}')`);
    }

    if (!(data instanceof Uint8Array) && !(data instanceof ArrayBuffer)) {
      throw new Error('Payload must be a Uint8Array or ArrayBuffer');
    }

    const byteLength = data.byteLength;
    if (byteLength > MAX_TRANSPORT_FRAME_SIZE) {
      throw new Error(
        `Frame exceeds maximum allowed WebRTC transport size of ${MAX_TRANSPORT_FRAME_SIZE} bytes (got ${byteLength} bytes)`
      );
    }

    // Flow control backpressure: pause if buffer is full
    if (this.flowController.shouldWait(this.channel)) {
      await this.flowController.waitForDrain(this.channel);
    }

    if (this.closed || this.channel.readyState !== 'open') {
      throw new Error('Connection closed while waiting for backpressure drain');
    }

    this.channel.send(data);
  }

  /**
   * Close all connection and channel resources idempotently.
   */
  close() {
    if (this.closed) return;
    this.closed = true;

    this._setState(WebRTCStates.CLOSED);

    // Clean up candidate queue
    this.iceCandidateQueue = [];
    this.seenCandidates.clear();

    // Close data channel
    if (this.channel) {
      try {
        this.channel.close();
      } catch {
        // Ignored
      }
      this.channel = null;
    }

    // Close RTCPeerConnection
    try {
      this.pc.close();
    } catch {
      // Ignored
    }

    this.emit('close');
  }

  // --- Private Helpers ---

  _setState(nextState) {
    if (this.state === nextState) return;
    this.state = nextState;
    this.emit('stateChange', nextState);
  }

  _setupPeerConnectionListeners() {
    const pc = this.pc;

    const on = (event, fn) => {
      if (typeof pc.addEventListener === 'function') {
        pc.addEventListener(event, fn);
      } else if (typeof pc.on === 'function') {
        pc.on(event, fn);
      }
    };

    on('icecandidate', (event) => {
      if (event?.candidate && event.candidate.candidate) {
        const plain = event.candidate.toJSON ? event.candidate.toJSON() : {
          candidate: event.candidate.candidate,
          sdpMid: event.candidate.sdpMid,
          sdpMLineIndex: event.candidate.sdpMLineIndex,
          usernameFragment: event.candidate.usernameFragment
        };
        this.emit('icecandidate', plain);
      }
    });

    on('connectionstatechange', () => {
      const pcState = pc.connectionState;
      if (pcState === 'connected') {
        if (this.channel?.readyState === 'open') {
          this._setState(WebRTCStates.CONNECTED);
        } else {
          this._setState(WebRTCStates.CONNECTING);
        }
      } else if (pcState === 'connecting') {
        this._setState(WebRTCStates.CONNECTING);
      } else if (pcState === 'disconnected') {
        this._setState(WebRTCStates.DISCONNECTED);
      } else if (pcState === 'failed') {
        this._setState(WebRTCStates.FAILED);
        this.emit('error', new Error('RTCPeerConnection failed'));
      } else if (pcState === 'closed') {
        this._setState(WebRTCStates.CLOSED);
      }
    });

    on('iceconnectionstatechange', () => {
      const iceState = pc.iceConnectionState;
      if (iceState === 'failed') {
        this._setState(WebRTCStates.FAILED);
        this.emit('error', new Error('ICE connection failed'));
      } else if (iceState === 'disconnected') {
        this._setState(WebRTCStates.DISCONNECTED);
      }
    });

    // Handle incoming DataChannel on responder
    on('datachannel', (event) => {
      if (event?.channel) {
        this.channel = event.channel;
        this._setupDataChannel(this.channel);
      }
    });
  }

  _setupDataChannel(channel) {
    if (!channel) return;

    channel.binaryType = 'arraybuffer';
    this.flowController.configureChannel(channel);

    const on = (event, fn) => {
      if (typeof channel.addEventListener === 'function') {
        channel.addEventListener(event, fn);
      } else if (typeof channel.on === 'function') {
        channel.on(event, fn);
      }
    };

    const handleOpen = () => {
      this._setState(WebRTCStates.CONNECTED);
      this.emit('open');
    };

    if (channel.readyState === 'open') {
      queueMicrotask(handleOpen);
    } else {
      on('open', handleOpen);
    }

    on('close', () => {
      if (!this.closed) {
        this._setState(WebRTCStates.DISCONNECTED);
        this.emit('channelClose');
      }
    });

    on('error', (err) => {
      const errorObj = err?.error || err || new Error('DataChannel error');
      const msg = (errorObj?.message || String(errorObj || '')).toLowerCase();
      if (this.closed || msg.includes('user-initiated abort') || msg.includes('close called')) {
        console.warn('[WebRTC] Ignored harmless DataChannel close/abort event:', errorObj.message);
        return;
      }
      this.emit('error', errorObj);
    });

    on('message', (event) => {
      const data = event?.data;
      if (typeof data === 'string') {
        this.emit('error', new Error(`Unexpected non-binary DataChannel message: expected ArrayBuffer/Uint8Array`));
        return;
      }

      const byteLength = data?.byteLength || 0;
      if (byteLength > MAX_TRANSPORT_FRAME_SIZE) {
        this.emit(
          'error',
          new Error(
            `Incoming DataChannel frame exceeds maximum allowed size of ${MAX_TRANSPORT_FRAME_SIZE} bytes (received ${byteLength} bytes)`
          )
        );
        return;
      }

      if (data instanceof ArrayBuffer) {
        this.emit('frame', new Uint8Array(data));
      } else if (data instanceof Uint8Array) {
        this.emit('frame', data);
      } else {
        this.emit('error', new Error('Unsupported DataChannel message payload type'));
      }
    });
  }

  async _flushQueuedCandidates() {
    if (this.iceCandidateQueue.length === 0) return;

    const queued = [...this.iceCandidateQueue];
    this.iceCandidateQueue = [];

    for (const candidate of queued) {
      if (!candidate || !candidate.candidate) continue;
      try {
        await this.pc.addIceCandidate(candidate);
      } catch (err) {
        console.warn('[WebRTC] Ignored non-fatal flush queued candidate error:', err.message);
      }
    }
  }
}
