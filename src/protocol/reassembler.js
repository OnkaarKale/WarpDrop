/**
 * Streaming Chunk Reassembler and Integrity Verifier.
 *
 * Security & Correctness guarantees:
 * 1. Strict Receiver Approval Enforcement: rejects chunks before explicit approve() call.
 * 2. File Index Binding: rejects chunks with unexpected fileIndex; binds fileIndex to AES-GCM AAD.
 * 3. Conflicting Duplicate Protection: tracks 16-byte authentication tag per chunk. Legitimate
 *    retransmissions (matching tag) are safely ignored; conflicting duplicates (mismatched tag) are rejected.
 * 4. Bounded-Memory Verification: streams chunks sequentially from sink for whole-file SHA-256 verification.
 * 5. Mandatory Integrity Check: unconditionally verifies final digest against manifest.
 */

import { validateFileMetadata } from './types.js';
import { unpackChunkFrame } from './frames.js';
import { decryptChunk } from '../crypto/cipher.js';
import { createStreamingHash } from '../crypto/hash.js';

function tagToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * In-Memory Chunk Sink.
 * Stores chunk references in an indexed Array and assembles into Blob (for large files)
 * or Uint8Array (for small payloads/tests) to prevent V8 heap exhaustion and tab crashes.
 */
export class MemoryChunkSink {
  constructor(totalChunks, fileSize, { mimeType = 'application/octet-stream', preferBlob = false } = {}) {
    this.totalChunks = totalChunks;
    this.fileSize = fileSize;
    this.mimeType = mimeType;
    this.preferBlob = preferBlob;
    this.chunks = new Array(totalChunks);
  }

  async writeChunk(chunkIndex, data) {
    this.chunks[chunkIndex] = data;
  }

  async readChunk(chunkIndex) {
    return this.chunks[chunkIndex] || null;
  }

  async finalize() {
    // For small files (<= 16MB) without preferBlob, return contiguous Uint8Array (100% test compatible).
    // For large files (> 16MB) or when preferBlob is enabled, assemble via Blob directly from parts
    // to prevent catastrophic V8 ArrayBuffer allocation failure / OOM tab crashes ("Aw, Snap!").
    if (typeof Blob === 'undefined' || (this.fileSize <= 16 * 1024 * 1024 && !this.preferBlob)) {
      const assembled = new Uint8Array(this.fileSize);
      let offset = 0;
      for (let i = 0; i < this.totalChunks; i++) {
        const chunk = this.chunks[i];
        if (chunk) {
          assembled.set(chunk, offset);
          offset += chunk.byteLength;
        }
      }
      return assembled;
    }

    const parts = [];
    for (let i = 0; i < this.totalChunks; i++) {
      const chunk = this.chunks[i];
      if (chunk) {
        parts.push(chunk);
      }
    }
    const blob = new Blob(parts, { type: this.mimeType || 'application/octet-stream' });
    this.chunks = []; // Immediately release references so GC can reclaim RAM
    return blob;
  }

  cleanup() {
    this.chunks = [];
  }
}

export class FileReassembler {
  /**
   * @param {Object} options
   * @param {Object} options.manifest - Validated transfer manifest from peer
   * @param {number} [options.fileIndex=0] - Expected file index for multi-file transfers
   * @param {CryptoKey} options.key - AES-256-GCM inbound key
   * @param {Uint8Array} options.staticIv - 12-byte inbound static IV salt
   * @param {Object} [options.sink] - Pluggable chunk sink (default: MemoryChunkSink)
   */
  constructor({ manifest, fileIndex = 0, key, staticIv, sink = null }) {
    if (!manifest || !key || !staticIv) {
      throw new Error('manifest, key, and staticIv are required for reassembler');
    }

    this.manifest = validateFileMetadata(manifest);
    this.fileIndex = fileIndex;
    this.key = key;
    this.staticIv = staticIv;

    this.totalChunks = this.manifest.totalChunks;
    this.fileSize = this.manifest.size;
    this.chunkSize = this.manifest.chunkSize;

    // Security: explicitly gate chunk processing on receiver approval
    this.isApproved = false;

    // Compact index tracking: only stores chunk indices (numbers)
    this.receivedChunkIndices = new Set();
    // Tracks 16-byte GCM authentication tag hex for accepted chunks to detect conflicting duplicates
    this.chunkTags = new Map();

    this.sink = sink || new MemoryChunkSink(this.totalChunks, this.fileSize, {
      mimeType: this.manifest.mimeType,
      preferBlob: typeof window !== 'undefined'
    });
    this.isFinalized = false;
  }

  /**
   * Explicitly authorize receiving chunks for this file transfer.
   */
  approve() {
    this.isApproved = true;
  }

  /**
   * Receive and process an incoming binary chunk frame.
   *
   * @param {Uint8Array | ArrayBuffer} rawFrame
   * @returns {Promise<{ chunkIndex: number, totalChunks: number, isComplete: boolean }>}
   */
  async receiveChunk(rawFrame) {
    if (!this.isApproved) {
      throw new Error('Cannot receive chunk: transfer not approved by receiver');
    }

    if (this.isFinalized) {
      throw new Error('Cannot receive chunks: transfer already finalized');
    }

    const { fileIndex, chunkIndex, totalChunks, ciphertext } = unpackChunkFrame(rawFrame);

    // Verify file index binding
    if (fileIndex !== this.fileIndex) {
      throw new Error(`File index mismatch: chunk claims fileIndex ${fileIndex}, expected ${this.fileIndex}`);
    }

    if (totalChunks !== this.totalChunks) {
      throw new Error(`Total chunks mismatch in frame: expected ${this.totalChunks}, got ${totalChunks}`);
    }

    if (chunkIndex < 0 || chunkIndex >= this.totalChunks) {
      throw new Error(`Chunk index out of bounds: ${chunkIndex} (total: ${this.totalChunks})`);
    }

    // Extract GCM authentication tag (last 16 bytes of ciphertext)
    if (ciphertext.byteLength < 16) {
      throw new Error('Invalid ciphertext: missing authentication tag');
    }
    const incomingTagHex = tagToHex(ciphertext.subarray(ciphertext.byteLength - 16));

    // Duplicate chunk handling policy:
    // 1. If chunk was already received with identical auth tag, it is a safe legitimate retransmission. Ignore safely.
    // 2. If chunk was already received with DIFFERENT auth tag, reject as conflicting duplicate!
    if (this.receivedChunkIndices.has(chunkIndex)) {
      const existingTag = this.chunkTags.get(chunkIndex);
      if (existingTag === incomingTagHex) {
        return {
          chunkIndex,
          totalChunks: this.totalChunks,
          isComplete: this.isComplete()
        };
      }
      throw new Error(`Conflicting duplicate chunk received for index ${chunkIndex}`);
    }

    // Construct expected 18-byte AAD
    const headerAad = new Uint8Array(18);
    const view = new DataView(headerAad.buffer);
    headerAad[0] = 0x50;
    headerAad[1] = 0x32;
    headerAad[2] = 0x02;
    view.setUint16(4, this.fileIndex, false);
    view.setUint32(6, chunkIndex, false);
    view.setUint32(10, totalChunks, false);

    // Decrypt chunk with inbound key & static IV (throws OperationError if tampered)
    const plaintext = await decryptChunk({
      key: this.key,
      staticIv: this.staticIv,
      chunkIndex,
      ciphertext,
      aad: headerAad
    });

    // Write to chunk sink and update indices
    await this.sink.writeChunk(chunkIndex, plaintext);
    this.receivedChunkIndices.add(chunkIndex);
    this.chunkTags.set(chunkIndex, incomingTagHex);

    return {
      chunkIndex,
      totalChunks: this.totalChunks,
      isComplete: this.isComplete()
    };
  }

  isComplete() {
    return this.receivedChunkIndices.size === this.totalChunks;
  }

  /**
   * Return array of missing chunk indices for selective retransmission / resume.
   * @returns {number[]}
   */
  getMissingChunkIndices() {
    const missing = [];
    for (let i = 0; i < this.totalChunks; i++) {
      if (!this.receivedChunkIndices.has(i)) {
        missing.push(i);
      }
    }
    return missing;
  }

  getProgress() {
    const count = this.receivedChunkIndices.size;
    return {
      receivedChunks: count,
      totalChunks: this.totalChunks,
      percentage: this.totalChunks === 0 ? 100 : Math.round((count / this.totalChunks) * 100)
    };
  }

  /**
   * Reassemble decrypted chunks in sequential order and strictly verify whole-file SHA-256 digest.
   *
   * @returns {Promise<{ verified: boolean, data: any, name: string, mimeType: string }>}
   */
  async finalize({ onProgress } = {}) {
    if (!this.isApproved) {
      throw new Error('Cannot finalize transfer: transfer not approved by receiver');
    }

    if (this.isFinalized) {
      throw new Error('Cannot finalize transfer: transfer already finalized');
    }

    if (!this.isComplete()) {
      throw new Error(
        `Cannot finalize incomplete transfer: missing ${this.totalChunks - this.receivedChunkIndices.size} chunks`
      );
    }

    // Stream chunks through SHA-256 hasher sequentially via readChunk
    const hasher = createStreamingHash();
    for (let i = 0; i < this.totalChunks; i++) {
      const chunk = await this.sink.readChunk(i);
      if (!chunk) {
        throw new Error(`Missing expected chunk at index ${i}`);
      }
      hasher.update(chunk);

      // Periodically yield to browser event loop (every 256 chunks = 16 MB)
      // Prevents UI freeze and prevents browser watchdog crash ("Aw, Snap!")
      if (i > 0 && i % 256 === 0) {
        if (typeof onProgress === 'function') {
          onProgress(Math.round((i / this.totalChunks) * 100));
        }
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    if (typeof onProgress === 'function') {
      onProgress(100);
    }

    const computedSha256 = hasher.digest('hex');

    // Mandatory integrity check against manifest
    if (this.manifest.sha256 !== computedSha256) {
      this.sink.cleanup?.();
      throw new Error(
        `Integrity verification failed: computed SHA-256 (${computedSha256}) does not match manifest (${this.manifest.sha256})`
      );
    }

    this.isFinalized = true;
    const finalData = await this.sink.finalize();

    return {
      verified: true,
      data: finalData,
      name: this.manifest.name,
      mimeType: this.manifest.mimeType
    };
  }

  abort() {
    this.sink.cleanup?.();
    this.receivedChunkIndices.clear();
    this.chunkTags.clear();
    this.isApproved = false;
  }
}
