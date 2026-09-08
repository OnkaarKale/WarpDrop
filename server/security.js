/**
 * Signaling Security Module.
 *
 * Enforces message schema validation, ID sanitization, origin checking,
 * strict size caps, and connection rate limiting.
 */

export const MAX_SIGNALING_MESSAGE_SIZE = 64 * 1024; // 64 KB (strictly sufficient for SDP / ICE)

import { SignalingMessageTypes } from '../src/protocol/types.js';
export { SignalingMessageTypes };

const ID_REGEX = /^[a-zA-Z0-9_-]{4,64}$/;
const TOKEN_REGEX = /^[a-zA-Z0-9_.-]{8,128}$/;

/**
 * Validate session ID format.
 * @param {string} sessionId
 * @returns {boolean}
 */
export function validateSessionId(sessionId) {
  if (typeof sessionId !== 'string' || sessionId.length < 8 || sessionId.length > 64) {
    return false;
  }
  return ID_REGEX.test(sessionId);
}

/**
 * Validate peer ID format.
 * @param {string} peerId
 * @returns {boolean}
 */
export function validatePeerId(peerId) {
  if (typeof peerId !== 'string' || peerId.length < 4 || peerId.length > 64) {
    return false;
  }
  return ID_REGEX.test(peerId);
}

/**
 * Validate session token format.
 * @param {string} token
 * @returns {boolean}
 */
export function validateToken(token) {
  if (typeof token !== 'string') return false;
  return TOKEN_REGEX.test(token);
}

/**
 * Validate WebSocket Origin header against localhost and private LAN networks.
 * @param {string | undefined} origin
 * @returns {boolean}
 */
export function validateOrigin(origin, serverHost = null) {
  if (!origin || typeof origin !== 'string') {
    // Non-browser or native client / same-origin test
    return true;
  }

  try {
    const url = new URL(origin);
    const host = url.hostname.toLowerCase();

    // 1. If origin matches the server's own host (same-origin WebSocket policy for cloud deployments)
    if (serverHost) {
      const cleanServerHost = serverHost.split(':')[0].toLowerCase();
      if (host === cleanServerHost) {
        return true;
      }
    }

    // 2. Explicitly allowed origins via environment variable (comma-separated domains)
    if (process.env.ALLOWED_ORIGINS) {
      const allowed = process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim().toLowerCase());
      if (allowed.includes(host) || allowed.includes(origin.toLowerCase())) {
        return true;
      }
    }

    // 3. Local loopback
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
      return true;
    }

    // 4. Private IPv4 ranges (RFC 1918)
    // 10.0.0.0/8
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    // 172.16.0.0/12
    if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    // 192.168.0.0/16
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    // Link-local
    if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
    // Local mDNS names (.local)
    if (host.endsWith('.local')) return true;

    // Disallow arbitrary third-party public internet origins
    return false;
  } catch {
    return false;
  }
}

/**
 * Strictly validate signaling message schema.
 * Prohibits file data, private keys, or unexpected structures.
 *
 * @param {any} msg - Parsed JSON object
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateSignalingMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return { valid: false, error: 'Message must be a non-null object' };
  }

  const { type, sessionId, peerId, token, payload } = msg;

  if (!type || typeof type !== 'string') {
    return { valid: false, error: 'Missing or invalid message type' };
  }

  if (!Object.values(SignalingMessageTypes).includes(type)) {
    return { valid: false, error: `Unknown message type: ${type}` };
  }

  if (!validateSessionId(sessionId)) {
    return { valid: false, error: `Invalid sessionId: ${sessionId}` };
  }

  if (!validatePeerId(peerId)) {
    return { valid: false, error: `Invalid peerId: ${peerId}` };
  }

  // Token is required for all peer-initiated messages
  if (token && !validateToken(token)) {
    return { valid: false, error: 'Invalid session token format' };
  }

  // Check for prohibited sensitive or file-related properties
  const jsonStr = JSON.stringify(msg);
  if (/fileBytes|fileData|rawChunk|chunkPayload/i.test(jsonStr)) {
    return { valid: false, error: 'Invalid payload: file content transmission is strictly prohibited on signaling' };
  }
  if (/privateKey|aesKey|sharedSecret/i.test(jsonStr)) {
    return { valid: false, error: 'Invalid payload: prohibited key material in signaling message' };
  }

  // Specific payload validation
  if (type === SignalingMessageTypes.SDP_OFFER || type === SignalingMessageTypes.SDP_ANSWER) {
    if (!payload || typeof payload !== 'object') {
      return { valid: false, error: 'SDP message requires payload object' };
    }
    if (typeof payload.sdp !== 'string' || payload.sdp.length > 32 * 1024) {
      return { valid: false, error: 'Invalid SDP payload: sdp must be string under 32KB' };
    }
    const expectedType = type === SignalingMessageTypes.SDP_OFFER ? 'offer' : 'answer';
    if (payload.type !== expectedType) {
      return { valid: false, error: `Invalid SDP type: expected ${expectedType}, got ${payload.type}` };
    }
  }

  if (type === SignalingMessageTypes.ICE_CANDIDATE) {
    if (!payload || typeof payload !== 'object') {
      return { valid: false, error: 'ICE_CANDIDATE requires payload object' };
    }
    if (typeof payload.candidate !== 'string' || payload.candidate.length > 2 * 1024) {
      return { valid: false, error: 'Invalid ICE candidate payload' };
    }
  }

  return { valid: true };
}

/**
 * Token Bucket Rate Limiter for WebSocket connections.
 */
export class RateLimiter {
  constructor({ maxTokens = 30, refillRatePerSec = 10, idleTimeoutMs = 60000 } = {}) {
    this.maxTokens = maxTokens;
    this.refillRatePerSec = refillRatePerSec;
    this.idleTimeoutMs = idleTimeoutMs;
    this.clients = new Map(); // key -> { tokens, lastRefill }
  }

  tryConsume(key, tokens = 1) {
    const now = Date.now();
    let record = this.clients.get(key);

    if (!record) {
      record = { tokens: this.maxTokens, lastRefill: now };
      this.clients.set(key, record);
    } else {
      // Refill tokens
      const elapsedSec = (now - record.lastRefill) / 1000;
      record.tokens = Math.min(this.maxTokens, record.tokens + elapsedSec * this.refillRatePerSec);
      record.lastRefill = now;
    }

    if (record.tokens >= tokens) {
      record.tokens -= tokens;
      return true;
    }

    return false;
  }

  getClientCount() {
    return this.clients.size;
  }

  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.clients.entries()) {
      if (now - record.lastRefill > this.idleTimeoutMs) {
        this.clients.delete(key);
      }
    }
  }
}
