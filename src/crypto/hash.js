/**
 * Streaming SHA-256 File Integrity Hasher.
 *
 * Designed for chunked/streaming file processing without buffering entire large files in RAM.
 * Uses audited, zero-dependency streaming implementation (@noble/hashes/sha2.js).
 */

import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Creates an incremental SHA-256 streaming hasher.
 *
 * @returns {{
 *   update: (chunk: Uint8Array | ArrayBuffer) => void,
 *   digest: (format?: 'hex' | 'binary') => string | Uint8Array
 * }}
 */
export function createStreamingHash() {
  const hashInstance = sha256.create();

  return {
    /**
     * Feed an incremental chunk of bytes into the SHA-256 stream.
     * @param {Uint8Array | ArrayBuffer} chunk
     */
    update(chunk) {
      if (!chunk) return;
      const buffer = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      hashInstance.update(buffer);
    },

    /**
     * Finalize and output the computed SHA-256 digest.
     * @param {'hex' | 'binary'} [format='hex']
     * @returns {string | Uint8Array}
     */
    digest(format = 'hex') {
      const raw = hashInstance.digest();
      if (format === 'binary') {
        return raw;
      }
      return Array.from(raw)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    }
  };
}
