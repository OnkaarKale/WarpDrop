/**
 * Ephemeral Session Key Exchange using Web Crypto ECDH (NIST P-256).
 *
 * Security guarantees:
 * - Ephemeral session key pairs generated in memory only.
 * - Private keys are non-extractable (extractable = false).
 * - Public keys exchanged over uncompressed raw P-256 format.
 * - No secrets written to disk or localStorage.
 * - Browser & Node.js isomorphic Base64 encoding (zero Buffer dependency).
 */

const subtle = globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error('Web Crypto API (crypto.subtle) is required but not available');
}

/**
 * Standard isomorphic Base64 encoder (works in Browser and Node.js)
 */
export function bytesToBase64(uint8Array) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(uint8Array).toString('base64');
  }
  let binary = '';
  const len = uint8Array.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary);
}

/**
 * Standard isomorphic Base64 decoder (works in Browser and Node.js)
 */
export function base64ToBytes(base64Str) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64Str, 'base64'));
  }
  const binary = atob(base64Str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate an ephemeral ECDH keypair for the transfer session.
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateSessionKeyPair() {
  return subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    false, // Private key MUST NOT be extractable
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Export ECDH public key to base64 string.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKey(publicKey) {
  if (!publicKey || publicKey.type !== 'public') {
    throw new Error('Invalid public key provided for export');
  }
  const rawBytes = await subtle.exportKey('raw', publicKey);
  return bytesToBase64(new Uint8Array(rawBytes));
}

/**
 * Import peer's base64 or binary ECDH public key.
 * @param {string | Uint8Array} keyData
 * @returns {Promise<CryptoKey>}
 */
export async function importPeerPublicKey(keyData) {
  let buffer;
  if (typeof keyData === 'string') {
    buffer = base64ToBytes(keyData);
  } else if (keyData instanceof Uint8Array || keyData instanceof ArrayBuffer) {
    buffer = keyData;
  } else {
    throw new Error('Key data must be a base64 string or Uint8Array/ArrayBuffer');
  }

  return subtle.importKey(
    'raw',
    buffer,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    []
  );
}

/**
 * Derive 256 bits of raw shared secret using ECDH.
 * @param {CryptoKey} privateKey - Local ephemeral private key
 * @param {CryptoKey} peerPublicKey - Peer's imported public key
 * @returns {Promise<ArrayBuffer>} 32-byte shared secret
 */
export async function deriveSharedSecretBits(privateKey, peerPublicKey) {
  if (!privateKey || !peerPublicKey) {
    throw new Error('Both privateKey and peerPublicKey are required');
  }
  return subtle.deriveBits(
    {
      name: 'ECDH',
      public: peerPublicKey
    },
    privateKey,
    256
  );
}
