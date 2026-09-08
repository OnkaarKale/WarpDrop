/**
 * Streaming File Chunker and Encrypted Frame Generator.
 *
 * Implements bounded-memory chunk processing using File/Blob slice or buffer slices.
 * Computes streaming SHA-256 on plaintext chunks and encrypts each chunk with AES-256-GCM.
 */

import { DEFAULT_CHUNK_SIZE, validateFileMetadata } from './types.js';
import { packChunkFrame } from './frames.js';
import { encryptChunk } from '../crypto/cipher.js';
import { createStreamingHash } from '../crypto/hash.js';

export class FileChunker {
  /**
   * @param {Object} options
   * @param {Uint8Array | ArrayBuffer | Blob | File} options.file - Source data or browser File/Blob
   * @param {string} [options.fileName='unnamed_file']
   * @param {string} [options.mimeType='application/octet-stream']
   * @param {number} [options.chunkSize=65536]
   * @param {number} [options.fileIndex=0]
   * @param {CryptoKey} options.key - AES-256-GCM outbound key
   * @param {Uint8Array} options.staticIv - 12-byte outbound static IV salt
   */
  constructor({
    file,
    fileName = 'unnamed_file',
    mimeType = 'application/octet-stream',
    chunkSize = DEFAULT_CHUNK_SIZE,
    fileIndex = 0,
    key,
    staticIv
  }) {
    if (!file) {
      throw new Error('File or data buffer is required for chunker');
    }
    if (!key || !staticIv) {
      throw new Error('Crypto key and staticIv are required for chunker');
    }

    this.file = file;
    this.fileName = fileName;
    this.mimeType = mimeType;
    this.chunkSize = chunkSize;
    this.fileIndex = fileIndex;
    this.key = key;
    this.staticIv = staticIv;

    // Detect size
    this.fileSize = typeof file.size === 'number' ? file.size : file.byteLength;
    if (typeof this.fileSize !== 'number') {
      throw new Error('Unable to determine file size');
    }

    this.totalChunks = this.fileSize === 0 ? 1 : Math.ceil(this.fileSize / this.chunkSize);
    this.currentChunkIndex = 0;
    this.manifestCache = null;

    // Streaming SHA-256 hasher for plaintext
    this.hasher = createStreamingHash();
  }

  /**
   * Compute metadata manifest including whole-file SHA-256 hash.
   * Processes chunks incrementally to calculate SHA-256 without loading entire file into memory.
   * @returns {Promise<Object>} Validated manifest
   */
  async getManifest() {
    if (this.manifestCache) {
      return this.manifestCache;
    }

    // Stream through file to compute plaintext SHA-256 using 2MB slices for speed
    const hash = createStreamingHash();
    const hashSliceSize = 2 * 1024 * 1024; // 2 MB slices for fast hashing
    let offset = 0;

    while (offset < this.fileSize) {
      const end = Math.min(offset + hashSliceSize, this.fileSize);
      const rawChunk = await this._readSlice(offset, end);
      hash.update(rawChunk);
      offset = end;
    }

    // If file is 0 bytes, hash empty buffer
    if (this.fileSize === 0) {
      hash.update(new Uint8Array(0));
    }

    const sha256 = hash.digest('hex');

    this.manifestCache = validateFileMetadata({
      name: this.fileName,
      size: this.fileSize,
      chunkSize: this.chunkSize,
      totalChunks: this.totalChunks,
      mimeType: this.mimeType,
      sha256
    });

    return this.manifestCache;
  }

  hasMoreChunks() {
    return this.currentChunkIndex < this.totalChunks;
  }

  getCurrentProgress() {
    return {
      chunkIndex: this.currentChunkIndex,
      totalChunks: this.totalChunks,
      bytesTransferred: Math.min(this.currentChunkIndex * this.chunkSize, this.fileSize),
      totalBytes: this.fileSize,
      percentage: this.totalChunks === 0 ? 100 : Math.round((this.currentChunkIndex / this.totalChunks) * 100)
    };
  }

  getProgress() {
    return {
      currentChunk: this.currentChunkIndex,
      chunkIndex: this.currentChunkIndex,
      totalChunks: this.totalChunks,
      bytesTransferred: Math.min(this.currentChunkIndex * this.chunkSize, this.fileSize),
      totalBytes: this.fileSize,
      percentage: this.totalChunks === 0 ? 100 : Math.round((this.currentChunkIndex / this.totalChunks) * 100)
    };
  }

  /**
   * Read, encrypt, and pack the next binary chunk frame.
   * @returns {Promise<Uint8Array>} Binary frame ready for WebRTC DataChannel send
   */
  async nextChunk() {
    if (!this.hasMoreChunks()) {
      throw new Error('No more chunks available in file');
    }

    const chunkIndex = this.currentChunkIndex;
    const startOffset = chunkIndex * this.chunkSize;
    const endOffset = Math.min(startOffset + this.chunkSize, this.fileSize);

    // Read slice (bounded memory)
    const plaintext = await this._readSlice(startOffset, endOffset);

    // Update ongoing stream hash
    this.hasher.update(plaintext);

    // Construct AAD: 18-byte header template
    const headerAad = new Uint8Array(18);
    const view = new DataView(headerAad.buffer);
    headerAad[0] = 0x50;
    headerAad[1] = 0x32;
    headerAad[2] = 0x02; // FRAME_TYPE_CHUNK
    view.setUint16(4, this.fileIndex, false);
    view.setUint32(6, chunkIndex, false);
    view.setUint32(10, this.totalChunks, false);

    // Encrypt chunk with AES-256-GCM
    const encrypted = await encryptChunk({
      key: this.key,
      staticIv: this.staticIv,
      chunkIndex,
      data: plaintext,
      aad: headerAad
    });

    // Pack into binary chunk frame
    const frame = packChunkFrame({
      fileIndex: this.fileIndex,
      chunkIndex,
      totalChunks: this.totalChunks,
      ciphertext: encrypted.ciphertext
    });

    this.currentChunkIndex++;
    return frame;
  }

  /**
   * Reset chunk index to specific position (for pause/resume).
   * @param {number} targetIndex
   */
  seek(targetIndex) {
    if (targetIndex < 0 || targetIndex > this.totalChunks) {
      throw new Error(`Invalid seek target: ${targetIndex}`);
    }
    this.currentChunkIndex = targetIndex;
  }

  async _readSlice(start, end) {
    if (typeof this.file.slice === 'function') {
      const blobSlice = this.file.slice(start, end);
      if (typeof blobSlice.arrayBuffer === 'function') {
        const buf = await blobSlice.arrayBuffer();
        return new Uint8Array(buf);
      }
    }

    // Node.js Buffer or Uint8Array slice
    if (this.file instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(this.file))) {
      return this.file.subarray(start, end);
    }

    throw new Error('Unsupported file/data type for slicing');
  }
}
