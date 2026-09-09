/**
 * Protocol Definitions, Framing Constants & Input Sanitization.
 */

// Magic identifier for binary frames: ASCII 'P', '2'
export const FRAME_MAGIC_0 = 0x50;
export const FRAME_MAGIC_1 = 0x32;

// Frame Types
export const FRAME_TYPE_CONTROL = 0x01;
export const FRAME_TYPE_CHUNK = 0x02;

// Protocol Limits
export const MIN_CHUNK_SIZE = 16 * 1024; // 16 KB minimum chunk size
export const MAX_CHUNK_SIZE = 256 * 1024; // 256 KB max chunk payload
export const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KB default chunk size
export const MAX_CONTROL_PAYLOAD = 64 * 1024; // 64 KB max control payload
export const MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024; // 100 GB cap to prevent integer overflow
export const MAX_TOTAL_CHUNKS = 1_000_000; // 1 million chunks max (supports up to 256 GB)
export const MAX_FILENAME_LENGTH = 255;

// Control Message Actions
export const ControlActions = Object.freeze({
  MANIFEST: 'MANIFEST',
  ACCEPT: 'ACCEPT',
  REJECT: 'REJECT',
  CHUNK_ACK: 'CHUNK_ACK',
  PAUSE: 'PAUSE',
  RESUME: 'RESUME',
  CANCEL: 'CANCEL',
  COMPLETE: 'COMPLETE',
  DOWNLOAD_ACK: 'DOWNLOAD_ACK'
});

// Signaling Message Types (shared across transport and signaling)
export const SignalingMessageTypes = Object.freeze({
  JOIN: 'JOIN',
  PEER_JOINED: 'PEER_JOINED',
  SDP_OFFER: 'SDP_OFFER',
  SDP_ANSWER: 'SDP_ANSWER',
  ICE_CANDIDATE: 'ICE_CANDIDATE',
  TUNNEL_FRAME: 'TUNNEL_FRAME',
  PEER_LEFT: 'PEER_LEFT',
  PING: 'PING',
  PONG: 'PONG',
  ERROR: 'ERROR'
});

/**
 * Sanitize a filename received from a peer.
 * Strips path traversal sequences, directory components, control chars, and limits length.
 *
 * @param {string} rawName
 * @returns {string} Safe basename
 */
export function sanitizeFileName(rawName) {
  if (typeof rawName !== 'string') {
    return 'unnamed_file';
  }

  // Strip path traversal and normalize separators
  let clean = rawName.replace(/\\/g, '/');
  // Take last path component
  const parts = clean.split('/');
  clean = parts[parts.length - 1].trim();

  // Strip control characters (ASCII 0-31, 127) and illegal characters
  clean = clean.replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, '');

  // Strip leading dots to prevent hidden files or traversal artifacts
  clean = clean.replace(/^\.+/, '');

  if (!clean || clean.length === 0) {
    return 'unnamed_file';
  }

  // Enforce max length (preserve extension if possible)
  if (clean.length > MAX_FILENAME_LENGTH) {
    const extIdx = clean.lastIndexOf('.');
    if (extIdx > 0 && clean.length - extIdx <= 10) {
      const ext = clean.slice(extIdx);
      clean = clean.slice(0, MAX_FILENAME_LENGTH - ext.length) + ext;
    } else {
      clean = clean.slice(0, MAX_FILENAME_LENGTH);
    }
  }

  return clean;
}

/**
 * Sanitize and validate MIME types.
 *
 * @param {string} rawMime
 * @returns {string} Safe MIME string
 */
export function sanitizeMimeType(rawMime) {
  if (typeof rawMime !== 'string') {
    return 'application/octet-stream';
  }

  const trimmed = rawMime.split(';')[0].trim().toLowerCase();
  const mimeRegex = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

  if (mimeRegex.test(trimmed)) {
    return trimmed;
  }

  return 'application/octet-stream';
}

/**
 * Strictly validate and sanitize file manifest metadata from peer.
 * Protects against integer overflow, negative values, excessive chunk counts,
 * and requires a mandatory cryptographic SHA-256 digest.
 *
 * @param {Object} meta
 * @returns {Object} Validated metadata
 */
export function validateFileMetadata(meta) {
  if (!meta || typeof meta !== 'object') {
    throw new Error('File metadata must be an object');
  }

  const name = sanitizeFileName(meta.name);

  // Validate file size
  const size = meta.size;
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error(`Invalid file size: ${size}. Must be a safe non-negative integer.`);
  }
  if (size > MAX_FILE_SIZE) {
    throw new Error(`File size ${size} exceeds maximum allowable limit of ${MAX_FILE_SIZE} bytes.`);
  }

  // Validate chunk size
  const chunkSize = typeof meta.chunkSize === 'number' ? meta.chunkSize : DEFAULT_CHUNK_SIZE;
  if (!Number.isSafeInteger(chunkSize) || chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error(`Invalid chunk size: ${chunkSize}. Must be between ${MIN_CHUNK_SIZE} and ${MAX_CHUNK_SIZE} bytes.`);
  }

  // Validate total chunks
  const totalChunks = meta.totalChunks;
  if (!Number.isSafeInteger(totalChunks) || totalChunks <= 0) {
    throw new Error(`Invalid total chunks: ${totalChunks}.`);
  }
  if (totalChunks > MAX_TOTAL_CHUNKS) {
    throw new Error(`Total chunks exceeds maximum allowable chunk count limit of ${MAX_TOTAL_CHUNKS}.`);
  }

  const expectedTotalChunks = size === 0 ? 1 : Math.ceil(size / chunkSize);
  if (totalChunks !== expectedTotalChunks) {
    throw new Error(
      `Total chunks mismatch: metadata claims ${totalChunks}, but size ${size} with chunkSize ${chunkSize} expects ${expectedTotalChunks}.`
    );
  }

  const mimeType = sanitizeMimeType(meta.mimeType);

  // MANDATORY SHA-256 verification enforcement: prevent peer from omitting hash
  if (!meta.sha256 || typeof meta.sha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(meta.sha256)) {
    throw new Error('Missing or invalid mandatory SHA-256 digest in transfer metadata');
  }
  const sha256 = meta.sha256.toLowerCase();

  return {
    name,
    size,
    chunkSize,
    totalChunks,
    mimeType,
    sha256
  };
}
