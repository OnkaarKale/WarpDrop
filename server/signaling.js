/**
 * Local WebSocket Signaling Server.
 *
 * Facilitates ephemeral peer discovery and WebRTC SDP/ICE negotiation.
 * Strictly zero-file-knowledge: prohibits binary data and file payloads.
 * Hardened with connection-state validation and ping/pong heartbeats.
 */

import { WebSocketServer, WebSocket } from 'ws';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MAX_SIGNALING_MESSAGE_SIZE,
  SignalingMessageTypes,
  validateOrigin,
  validateSignalingMessage,
  RateLimiter
} from './security.js';

export class SignalingServer {
  /**
   * @param {Object} options
   * @param {import('http').Server} [options.server] - Existing HTTP server to attach to
   * @param {number} [options.port] - Port to bind if standalone
   * @param {number} [options.sessionTimeoutMs=600000] - 10 min session expiry
   * @param {string} [options.persistFilePath] - Optional path to session persistence file
   */
  constructor({ server, port, sessionTimeoutMs = 600000, persistFilePath } = {}) {
    this.sessionTimeoutMs = sessionTimeoutMs;
    this.rateLimiter = new RateLimiter({ maxTokens: 40, refillRatePerSec: 15 });

    // In-memory ephemeral sessions: sessionId -> { token, peers: Map<peerId, { ws, peerId }>, lastActive }
    this.sessions = new Map();
    this.persistFilePath = persistFilePath !== undefined
      ? persistFilePath
      : (server ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../.active_sessions.json') : null);
    this._loadPersistedSessions();

    const wssOptions = {
      maxPayload: MAX_SIGNALING_MESSAGE_SIZE
    };

    if (server) {
      wssOptions.server = server;
    } else if (port) {
      wssOptions.port = port;
    }

    this.wss = new WebSocketServer(wssOptions);
    this.wss.on('error', (err) => {
      // Prevent unhandled error crashes on WebSocketServer instance
      if (err.code !== 'EADDRINUSE') {
        console.error('WebSocketServer error:', err.message);
      }
    });
    this._setupServer();

    // Periodic sweep for abandoned or expired sessions
    this.cleanupInterval = setInterval(() => this._cleanupExpiredSessions(), 30000);
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();

    // WebSocket Heartbeat / Liveness Ping-Pong (every 30s)
    this.heartbeatInterval = setInterval(() => this._pingClients(), 30000);
    if (this.heartbeatInterval.unref) this.heartbeatInterval.unref();
  }

  /**
   * Create a new ephemeral pairing session.
   * Generates cryptographically secure session ID and auth token.
   *
   * @returns {{ sessionId: string, token: string }}
   */
  createSession() {
    const sessionId = `session-${crypto.randomBytes(12).toString('hex')}`;
    const token = `tok-${crypto.randomBytes(16).toString('base64url')}`;

    this.sessions.set(sessionId, {
      token,
      peers: new Map(),
      createdAt: Date.now(),
      lastActive: Date.now()
    });

    this._savePersistedSessions();
    console.log(`[Signaling] Created session: ${sessionId} (Active sessions: ${this.sessions.size})`);

    return { sessionId, token };
  }

  _loadPersistedSessions() {
    if (!this.persistFilePath) return;
    try {
      if (fs.existsSync(this.persistFilePath)) {
        const raw = fs.readFileSync(this.persistFilePath, 'utf8');
        const data = JSON.parse(raw);
        const now = Date.now();
        for (const [sessionId, item] of Object.entries(data)) {
          if (item && item.token && (now - item.lastActive < this.sessionTimeoutMs)) {
            this.sessions.set(sessionId, {
              token: item.token,
              peers: new Map(),
              createdAt: item.createdAt || now,
              lastActive: item.lastActive || now,
              everHadTwoPeers: false
            });
          }
        }
        if (this.sessions.size > 0) {
          console.log(`[Signaling] Loaded ${this.sessions.size} active session(s) from persistent store.`);
        }
      }
    } catch (err) {
      console.warn('[Signaling] Failed to load persisted sessions:', err.message);
    }
  }

  _savePersistedSessions() {
    if (!this.persistFilePath) return;
    try {
      const serializable = {};
      for (const [id, s] of this.sessions.entries()) {
        serializable[id] = {
          token: s.token,
          createdAt: s.createdAt,
          lastActive: s.lastActive
        };
      }
      fs.writeFileSync(this.persistFilePath, JSON.stringify(serializable, null, 2), 'utf8');
    } catch (err) {
      console.warn('[Signaling] Failed to save persisted sessions:', err.message);
    }
  }

  hasSession(sessionId) {
    return this.sessions.has(sessionId);
  }

  _setupServer() {
    this.wss.on('connection', (ws, req) => {
      const origin = req.headers.origin;
      const serverHost = req.headers['x-forwarded-host'] || req.headers.host;

      // 1. Origin verification
      if (!validateOrigin(origin, serverHost)) {
        ws.close(4003, 'Forbidden: untrusted origin');
        return;
      }

      // Track peer context and liveness on socket
      ws.peerContext = null;
      ws.isAlive = true;
      const clientIp = req.socket.remoteAddress || 'unknown';

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('message', (data, isBinary) => {
        // 2. Binary frame check: NEVER allow binary frames (file chunks) on signaling channel
        if (isBinary) {
          this._sendError(ws, 'Binary data is strictly prohibited: Signaling channel cannot transfer files');
          ws.close(4400, 'Binary transfer prohibited on signaling');
          return;
        }

        // 3. Rate limiting
        if (!this.rateLimiter.tryConsume(clientIp)) {
          this._sendError(ws, 'Rate limit exceeded. Slow down.');
          return;
        }

        // 4. Message size check
        if (data.length > MAX_SIGNALING_MESSAGE_SIZE) {
          this._sendError(ws, 'Message size exceeds maximum limit');
          return;
        }

        // 5. Parse JSON
        let msg;
        try {
          msg = JSON.parse(data.toString());
        } catch {
          this._sendError(ws, 'Malformed JSON message');
          return;
        }

        // 6. Schema validation
        const validation = validateSignalingMessage(msg);
        if (!validation.valid) {
          this._sendError(ws, `Validation error: ${validation.error}`);
          return;
        }

        this._handleMessage(ws, msg);
      });

      ws.on('close', () => {
        if (ws.peerContext) {
          this._handlePeerDisconnect(ws.peerContext);
        }
      });

      ws.on('error', () => {
        if (ws.peerContext) {
          this._handlePeerDisconnect(ws.peerContext);
        }
      });
    });
  }

  _handleMessage(ws, msg) {
    const { type, sessionId, peerId, token, payload } = msg;

    // Check session existence
    let session = this.sessions.get(sessionId);
    if (!session) {
      // If peer joins with valid token & sessionId (rx or tx from direct pairing link), auto-restore/register
      if (sessionId && typeof sessionId === 'string' && sessionId.startsWith('session-') &&
          token && typeof token === 'string' && token.startsWith('tok-')) {
        session = {
          token,
          peers: new Map(),
          createdAt: Date.now(),
          lastActive: Date.now(),
          everHadTwoPeers: false
        };
        this.sessions.set(sessionId, session);
        this._savePersistedSessions();
        console.log(`[Signaling] Auto-restored session '${sessionId}' for peer '${peerId}'`);
      } else {
        console.warn(`[Signaling] REJECT: Session not found! Received sessionId: "${sessionId}". Active sessions in memory: [${Array.from(this.sessions.keys()).join(', ')}]`);
        this._sendError(ws, 'Session not found or expired', sessionId);
        return;
      }
    }

    // Verify token
    if (session.token !== token) {
      console.warn(`[Signaling] REJECT: Invalid token provided for session '${sessionId}'`);
      this._sendError(ws, 'Invalid session token', sessionId);
      return;
    }

    session.lastActive = Date.now();
    ws.isAlive = true;

    // Handle keepalive ping from client
    if (type === SignalingMessageTypes.PING || type === 'PING') {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: SignalingMessageTypes.PONG,
          sessionId
        }));
      }
      return;
    }

    if (type === SignalingMessageTypes.JOIN) {
      console.log(`[Signaling] Peer '${peerId}' joined session '${sessionId}'. Total peers in room: ${session.peers.size + 1}`);
      this._handleJoin(ws, session, sessionId, peerId);
      return;
    }

    // Enforce connection state: sender must have joined and own the claimed peerId
    if (!ws.peerContext || ws.peerContext.sessionId !== sessionId || ws.peerContext.peerId !== peerId) {
      this._sendError(ws, 'Unauthorized: peer identity mismatch or not joined to session', sessionId);
      return;
    }

    // Forwarding SDP and ICE messages between peers
    const otherPeer = this._getOtherPeer(session, peerId);
    if (!otherPeer || otherPeer.ws.readyState !== WebSocket.OPEN) {
      this._sendError(ws, 'Peer not present in session to receive message', sessionId);
      return;
    }

    console.log(`[Signaling] Forwarded ${type} from ${peerId} to ${otherPeer.peerId}`);
    // Forward message strictly to the counterpart peer
    otherPeer.ws.send(JSON.stringify({
      type,
      sessionId,
      peerId,
      payload
    }));
  }

  _handleJoin(ws, session, sessionId, peerId) {
    // 1. Prune any dead, closed, or non-open sockets in this session
    for (const [existingId, record] of session.peers.entries()) {
      if (!record.ws || record.ws.readyState !== WebSocket.OPEN) {
        session.peers.delete(existingId);
      }
    }

    // 2. If the same WebSocket is re-joining under a new peerId, remove its old registration
    for (const [existingId, record] of session.peers.entries()) {
      if (record.ws === ws && existingId !== peerId) {
        session.peers.delete(existingId);
      }
    }

    // 3. Self-healing role replacement:
    // Receiver peer IDs are prefixed with 'rx-' and sender peer IDs with 'tx-'.
    // If a new 'rx-' or 'tx-' peer joins with the valid session token, replace any stale connection of that same role.
    const isRx = typeof peerId === 'string' && peerId.startsWith('rx-');
    const isTx = typeof peerId === 'string' && peerId.startsWith('tx-');
    if (isRx || isTx) {
      const prefix = isRx ? 'rx-' : 'tx-';
      for (const [existingId, record] of session.peers.entries()) {
        if (existingId !== peerId && existingId.startsWith(prefix)) {
          console.log(`[Signaling] Replacing stale ${prefix} peer '${existingId}' with new peer '${peerId}'`);
          try {
            record.ws.close(4000, 'Replaced by newer peer connection');
          } catch {}
          session.peers.delete(existingId);
        }
      }
    }

    // 4. Room capacity limit: max 2 peers
    if (session.peers.size >= 2 && !session.peers.has(peerId)) {
      this._sendError(ws, 'Session is full (maximum 2 peers)', sessionId);
      return;
    }

    // 5. Duplicate peer ID check in same session
    if (session.peers.has(peerId) && session.peers.get(peerId).ws !== ws) {
      try {
        session.peers.get(peerId).ws.close(4000, 'Replaced by duplicate peerId connection');
      } catch {}
      session.peers.delete(peerId);
    }

    // Register peer
    const peerRecord = { ws, peerId };
    session.peers.set(peerId, peerRecord);
    ws.peerContext = { sessionId, peerId };
    if (session.peers.size === 2) {
      session.everHadTwoPeers = true;
    }

    // Confirm join to the connecting peer
    ws.send(JSON.stringify({
      type: SignalingMessageTypes.PEER_JOINED,
      sessionId,
      peerId
    }));

    // If a counterpart peer is already in the session, cross-notify BOTH peers
    const otherPeer = this._getOtherPeer(session, peerId);
    if (otherPeer && otherPeer.ws.readyState === WebSocket.OPEN) {
      // 1. Notify the existing peer that the new peer joined
      otherPeer.ws.send(JSON.stringify({
        type: SignalingMessageTypes.PEER_JOINED,
        sessionId,
        peerId
      }));

      // 2. Notify the connecting peer that the counterpart peer is already present
      ws.send(JSON.stringify({
        type: SignalingMessageTypes.PEER_JOINED,
        sessionId,
        peerId: otherPeer.peerId
      }));
    }
  }

  _handlePeerDisconnect({ sessionId, peerId }) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.peers.delete(peerId);
    session.lastActive = Date.now();
    console.log(`[Signaling] Peer '${peerId}' left session '${sessionId}'. Remaining peers: ${session.peers.size}`);

    // Notify remaining peer
    const otherPeer = this._getOtherPeer(session, peerId);
    if (otherPeer && otherPeer.ws.readyState === WebSocket.OPEN) {
      otherPeer.ws.send(JSON.stringify({
        type: SignalingMessageTypes.PEER_LEFT,
        sessionId,
        peerId
      }));
    }

    // Clean up empty session if both peers were in the session and left.
    // Otherwise keep it alive so peers can join/reconnect until sessionTimeoutMs.
    if (session.peers.size === 0 && session.everHadTwoPeers) {
      console.log(`[Signaling] Cleaned up completed session '${sessionId}'`);
      this.sessions.delete(sessionId);
      this._savePersistedSessions();
    }
  }

  _getOtherPeer(session, currentPeerId) {
    for (const [id, peer] of session.peers.entries()) {
      if (id !== currentPeerId) {
        return peer;
      }
    }
    return null;
  }

  _sendError(ws, errorMessage, sessionId = '') {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: SignalingMessageTypes.ERROR,
        sessionId,
        error: errorMessage
      }));
    }
  }

  _pingClients() {
    for (const ws of this.wss.clients) {
      if (ws.isAlive === false) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      ws.ping();
    }
  }

  _cleanupExpiredSessions() {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions.entries()) {
      if (now - session.lastActive > this.sessionTimeoutMs) {
        // Disconnect any lingering peers
        for (const peer of session.peers.values()) {
          if (peer.ws.readyState === WebSocket.OPEN) {
            peer.ws.close(4001, 'Session expired');
          }
        }
        this.sessions.delete(sessionId);
      }
    }
    this._savePersistedSessions();
    this.rateLimiter.cleanup();
  }

  close() {
    clearInterval(this.cleanupInterval);
    clearInterval(this.heartbeatInterval);
    return new Promise((resolve) => {
      this.wss.close(resolve);
    });
  }
}

export function createSignalingServer(options) {
  return new SignalingServer(options);
}
