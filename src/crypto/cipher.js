/**
 * AES-256-GCM Authenticated Chunk Encryption & Safe Nonce Generation.
 *
 * Implements RFC 8446 / TLS 1.3 standard XOR nonce construction:
 * - Nonce (96 bits / 12 bytes) = staticIv XOR [0x00 0x00 0x00 0x00 | 64-bit BigEndian(sequenceNumber)]
 * - Mathematically guarantees unique nonces for every chunk.
 * - Prevents nonce reuse attack (catastrophic GCM polynomial forgery).
 * - Additional Authenticated Data (AAD) binds chunk metadata (fileId, index) to the ciphertext.
 */

const subtle = globalThis.crypto?.subtle;

/**
 * Construct a unique 96-bit (12-byte) IV for a given chunk sequence number.
 *
 * @param {Uint8Array} staticIv - 12-byte HKDF-derived static IV salt
 * @param {number | bigint} sequenceNumber - Strictly non-negative integer (0, 1, 2, ...)
 * @returns {Uint8Array} 12-byte unique nonce
 */
export function constructNonce(staticIv, sequenceNumber) {
  if (!(staticIv instanceof Uint8Array) || staticIv.length !== 12) {
    throw new Error('Invalid static IV: must be a 12-byte Uint8Array');
  }

  if (typeof sequenceNumber === 'number') {
    if (!Number.isSafeInteger(sequenceNumber) || sequenceNumber < 0) {
      throw new Error(`Invalid sequence number: ${sequenceNumber}. Must be a non-negative safe integer.`);
    }
  }

  const seq = typeof sequenceNumber === 'bigint' ? sequenceNumber : BigInt(sequenceNumber);
  if (seq < 0n || seq > 0xffffffffffffffffn) {
    throw new Error(`Invalid sequence number: ${sequenceNumber}. Must be non-negative 64-bit integer.`);
  }

  const nonce = new Uint8Array(12);

  // Copy first 4 bytes directly from staticIv (XOR with 0x00)
  nonce[0] = staticIv[0];
  nonce[1] = staticIv[1];
  nonce[2] = staticIv[2];
  nonce[3] = staticIv[3];

  // XOR remaining 8 bytes with 64-bit big-endian sequence counter
  let temp = seq;
  for (let i = 11; i >= 4; i--) {
    const byteVal = Number(temp & 0xffn);
    nonce[i] = staticIv[i] ^ byteVal;
    temp >>= 8n;
  }

  return nonce;
}

/**
 * Encrypt a single file chunk using AES-256-GCM with unique nonce.
 *
 * @param {Object} params
 * @param {CryptoKey} params.key - Derived AES-256-GCM session key
 * @param {Uint8Array} params.staticIv - 12-byte static IV salt
 * @param {number} params.chunkIndex - Monotonic chunk sequence index
 * @param {Uint8Array | ArrayBuffer} params.data - Plaintext chunk bytes
 * @param {Uint8Array | ArrayBuffer} [params.aad] - Additional Authenticated Data
 * @returns {Promise<{ ciphertext: Uint8Array, iv: Uint8Array, chunkIndex: number }>}
 */
export async function encryptChunk({
  key,
  staticIv,
  chunkIndex,
  data,
  plaintext,
  aad = new Uint8Array(0)
}) {
  const content = data !== undefined ? data : plaintext;
  if (!key || !staticIv) {
    throw new Error('key and staticIv are required for encryption');
  }
  if (content === undefined || content === null) {
    throw new Error('data or plaintext is required for encryption');
  }

  const iv = constructNonce(staticIv, chunkIndex);

  const encryptedBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad
    },
    key,
    content
  );

  return {
    ciphertext: new Uint8Array(encryptedBuffer),
    iv,
    chunkIndex
  };
}

/**
 * Decrypt and authenticate a single file chunk.
 * Fails automatically if ciphertext, tag, or AAD has been tampered with.
 *
 * @param {Object} params
 * @param {CryptoKey} params.key - Derived AES-256-GCM session key
 * @param {Uint8Array} params.staticIv - 12-byte static IV salt
 * @param {number} params.chunkIndex - Expected chunk sequence index
 * @param {Uint8Array | ArrayBuffer} params.ciphertext - Ciphertext including 16-byte GCM auth tag
 * @param {Uint8Array | ArrayBuffer} [params.aad] - Additional Authenticated Data
 * @returns {Promise<Uint8Array>} Plaintext chunk bytes
 */
export async function decryptChunk({
  key,
  staticIv,
  chunkIndex,
  ciphertext,
  aad = new Uint8Array(0)
}) {
  if (!key || !staticIv || !ciphertext) {
    throw new Error('key, staticIv, and ciphertext are required for decryption');
  }

  const iv = constructNonce(staticIv, chunkIndex);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad
    },
    key,
    ciphertext
  );

  return new Uint8Array(decryptedBuffer);
}
