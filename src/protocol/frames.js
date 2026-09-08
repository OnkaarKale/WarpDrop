/**
 * Binary Framing Layer for WebRTC DataChannel.
 *
 * Implements deterministic network-byte-order binary serialization:
 * - Chunk Frame: 18-byte header + ciphertext (with GCM tag)
 * - Control Frame: 12-byte header + encrypted JSON payload
 */

import {
  FRAME_MAGIC_0,
  FRAME_MAGIC_1,
  FRAME_TYPE_CONTROL,
  FRAME_TYPE_CHUNK,
  MAX_CHUNK_SIZE,
  MAX_CONTROL_PAYLOAD
} from './types.js';

const CHUNK_HEADER_SIZE = 18;
const CONTROL_HEADER_SIZE = 12;

/**
 * Pack an encrypted chunk into a binary frame.
 *
 * @param {Object} params
 * @param {number} params.fileIndex - uint16 (0..65535)
 * @param {number} params.chunkIndex - uint32 (0..4,294,967,295)
 * @param {number} params.totalChunks - uint32
 * @param {Uint8Array} params.ciphertext - Encrypted chunk bytes with GCM tag
 * @returns {Uint8Array}
 */
export function packChunkFrame({ fileIndex = 0, chunkIndex, totalChunks, ciphertext }) {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) {
    throw new Error(`Invalid chunkIndex: ${chunkIndex}`);
  }
  if (!Number.isSafeInteger(totalChunks) || totalChunks <= 0) {
    throw new Error(`Invalid totalChunks: ${totalChunks}`);
  }
  if (!(ciphertext instanceof Uint8Array)) {
    throw new Error('Ciphertext must be a Uint8Array');
  }

  const payloadLength = ciphertext.byteLength;
  const frame = new Uint8Array(CHUNK_HEADER_SIZE + payloadLength);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

  // Header serialization
  frame[0] = FRAME_MAGIC_0;
  frame[1] = FRAME_MAGIC_1;
  frame[2] = FRAME_TYPE_CHUNK;
  frame[3] = 0x00; // Reserved

  view.setUint16(4, fileIndex, false);
  view.setUint32(6, chunkIndex, false);
  view.setUint32(10, totalChunks, false);
  view.setUint32(14, payloadLength, false);

  // Copy ciphertext payload
  frame.set(ciphertext, CHUNK_HEADER_SIZE);

  return frame;
}

/**
 * Unpack and validate an incoming binary chunk frame.
 *
 * @param {Uint8Array | ArrayBuffer} rawBuffer
 * @returns {{
 *   fileIndex: number,
 *   chunkIndex: number,
 *   totalChunks: number,
 *   ciphertext: Uint8Array,
 *   headerAad: Uint8Array
 * }}
 */
export function unpackChunkFrame(rawBuffer) {
  const bytes = rawBuffer instanceof Uint8Array ? rawBuffer : new Uint8Array(rawBuffer);

  if (bytes.byteLength < CHUNK_HEADER_SIZE) {
    throw new Error(`Frame too short: received ${bytes.byteLength} bytes, expected at least ${CHUNK_HEADER_SIZE}`);
  }

  // Verify Magic
  if (bytes[0] !== FRAME_MAGIC_0 || bytes[1] !== FRAME_MAGIC_1) {
    throw new Error(`Invalid frame magic: 0x${bytes[0].toString(16)} 0x${bytes[1].toString(16)}`);
  }

  // Verify Frame Type
  if (bytes[2] !== FRAME_TYPE_CHUNK) {
    throw new Error(`Expected CHUNK frame (0x02), received 0x0${bytes[2].toString(16)}`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fileIndex = view.getUint16(4, false);
  const chunkIndex = view.getUint32(6, false);
  const totalChunks = view.getUint32(10, false);
  const payloadLength = view.getUint32(14, false);

  if (payloadLength > MAX_CHUNK_SIZE + 16) {
    throw new Error(`Payload length exceeds limit: ${payloadLength} > ${MAX_CHUNK_SIZE + 16}`);
  }

  if (bytes.byteLength !== CHUNK_HEADER_SIZE + payloadLength) {
    throw new Error(
      `Frame length mismatch: header claims ${CHUNK_HEADER_SIZE + payloadLength} bytes, but frame has ${bytes.byteLength}`
    );
  }

  const headerAad = bytes.subarray(0, CHUNK_HEADER_SIZE);
  const ciphertext = bytes.subarray(CHUNK_HEADER_SIZE);

  return {
    fileIndex,
    chunkIndex,
    totalChunks,
    ciphertext,
    headerAad
  };
}

/**
 * Pack an encrypted control message into a binary control frame.
 *
 * @param {Object} params
 * @param {number} params.controlSeq - Monotonic control sequence counter
 * @param {Uint8Array} params.ciphertext - Encrypted JSON bytes
 * @returns {Uint8Array}
 */
export function packControlFrame({ controlSeq = 0, ciphertext }) {
  if (!(ciphertext instanceof Uint8Array)) {
    throw new Error('Ciphertext must be a Uint8Array');
  }

  const payloadLength = ciphertext.byteLength;
  const frame = new Uint8Array(CONTROL_HEADER_SIZE + payloadLength);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);

  frame[0] = FRAME_MAGIC_0;
  frame[1] = FRAME_MAGIC_1;
  frame[2] = FRAME_TYPE_CONTROL;
  frame[3] = 0x00;

  view.setUint32(4, controlSeq, false);
  view.setUint32(8, payloadLength, false);

  frame.set(ciphertext, CONTROL_HEADER_SIZE);

  return frame;
}

/**
 * Unpack and validate an incoming binary control frame.
 *
 * @param {Uint8Array | ArrayBuffer} rawBuffer
 * @returns {{ controlSeq: number, ciphertext: Uint8Array, headerAad: Uint8Array }}
 */
export function unpackControlFrame(rawBuffer) {
  const bytes = rawBuffer instanceof Uint8Array ? rawBuffer : new Uint8Array(rawBuffer);

  if (bytes.byteLength < CONTROL_HEADER_SIZE) {
    throw new Error(`Frame too short: received ${bytes.byteLength} bytes, expected at least ${CONTROL_HEADER_SIZE}`);
  }

  if (bytes[0] !== FRAME_MAGIC_0 || bytes[1] !== FRAME_MAGIC_1) {
    throw new Error('Invalid frame magic in control frame');
  }

  if (bytes[2] !== FRAME_TYPE_CONTROL) {
    throw new Error(`Expected CONTROL frame (0x01), received 0x0${bytes[2].toString(16)}`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const controlSeq = view.getUint32(4, false);
  const payloadLength = view.getUint32(8, false);

  if (payloadLength > MAX_CONTROL_PAYLOAD + 16) {
    throw new Error(`Control payload exceeds limit: ${payloadLength}`);
  }

  if (bytes.byteLength !== CONTROL_HEADER_SIZE + payloadLength) {
    throw new Error('Control frame length mismatch');
  }

  const headerAad = bytes.subarray(0, CONTROL_HEADER_SIZE);
  const ciphertext = bytes.subarray(CONTROL_HEADER_SIZE);

  return {
    controlSeq,
    ciphertext,
    headerAad
  };
}
