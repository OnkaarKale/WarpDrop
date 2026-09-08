/**
 * HKDF-SHA-256 Key Derivation & SAS (Short Authentication String) Generation.
 *
 * Implements RFC 5869 Extract-and-Expand with directional domain separation:
 * 1. "file-transfer-v1-init-to-resp-aes-key" -> 256-bit AES-GCM encryption key (Initiator -> Responder)
 * 2. "file-transfer-v1-init-to-resp-iv-salt" -> 12-byte (96-bit) static IV salt (Initiator -> Responder)
 * 3. "file-transfer-v1-resp-to-init-aes-key" -> 256-bit AES-GCM encryption key (Responder -> Initiator)
 * 4. "file-transfer-v1-resp-to-init-iv-salt" -> 12-byte (96-bit) static IV salt (Responder -> Initiator)
 * 5. "file-transfer-v1-sas-auth"             -> 32-byte SAS & pairing auth token
 *
 * This directional design guarantees that even in full-duplex transfers or bidirectional control ACKs,
 * initiator and responder never share the same (key, nonce) space, preventing GCM nonce collisions and reflection attacks.
 */

const subtle = globalThis.crypto?.subtle;

// Exactly 32 visual emoji glyphs (2^5) -> perfectly divides 256 with ZERO modulo bias
const EMOJI_LIST = [
  '🚀', '🦊', '⚡', '🔒', '🌈', '💎', '🌊', '🌲',
  '☀️', '🌙', '⭐', '🎈', '🎨', '🎸', '🛸', '🦁',
  '🍇', '🍀', '🍎', '🏆', '🎯', '⚓', '🔮', '🕊️',
  '🔥', '🐬', '🪐', '🦄', '🐝', '🌺', '🏔️', '🧭'
];

// Exactly 32 phonetic mnemonic words (2^5) -> perfectly divides 256 with ZERO modulo bias
const WORD_LIST = [
  'alpha', 'bravo', 'coral', 'delta', 'eagle', 'frost', 'glide', 'haven',
  'iris', 'jade', 'kite', 'lunar', 'mystic', 'noble', 'orbit', 'pulse',
  'quartz', 'river', 'solar', 'titan', 'ultra', 'vivid', 'wave', 'zenith',
  'amber', 'blaze', 'cedar', 'dusk', 'ember', 'flint', 'grove', 'harbor'
];

/**
 * Derive directional session keys from ECDH shared secret bits using HKDF-SHA-256.
 *
 * @param {Object} params
 * @param {ArrayBuffer} params.sharedSecretBits - 32-byte raw shared secret
 * @param {string} params.sessionId - Unique temporary session ID
 * @param {string} [params.initiatorPubKey=''] - Base64 public key of the connection initiator
 * @param {string} [params.responderPubKey=''] - Base64 public key of the connection responder
 * @param {boolean} [params.isInitiator=true] - Whether local peer is the initiator
 * @returns {Promise<{
 *   outboundKey: CryptoKey,
 *   outboundStaticIv: Uint8Array,
 *   inboundKey: CryptoKey,
 *   inboundStaticIv: Uint8Array,
 *   sasToken: Uint8Array
 * }>}
 */
export async function deriveSessionKeys({
  sharedSecretBits,
  sessionId,
  initiatorPubKey = '',
  responderPubKey = '',
  isInitiator = true
}) {
  if (!sharedSecretBits || !sessionId) {
    throw new Error('sharedSecretBits and sessionId are required for key derivation');
  }

  // Salt binds session ID and directional public keys
  const saltData = new TextEncoder().encode(
    `file-transfer-session:${sessionId}:${initiatorPubKey}:${responderPubKey}`
  );
  const saltHash = await subtle.digest('SHA-256', saltData);
  const salt = new Uint8Array(saltHash);

  // Import shared secret as HKDF master key
  const baseKey = await subtle.importKey(
    'raw',
    sharedSecretBits,
    'HKDF',
    false,
    ['deriveKey', 'deriveBits']
  );

  // 1. Derive Initiator -> Responder AES-256-GCM key
  const initToRespAesKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('file-transfer-v1-init-to-resp-aes-key')
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 2. Derive Initiator -> Responder static IV salt
  const initToRespIvBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('file-transfer-v1-init-to-resp-iv-salt')
    },
    baseKey,
    96
  );
  const initToRespIv = new Uint8Array(initToRespIvBits);

  // 3. Derive Responder -> Initiator AES-256-GCM key
  const respToInitAesKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('file-transfer-v1-resp-to-init-aes-key')
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 4. Derive Responder -> Initiator static IV salt
  const respToInitIvBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('file-transfer-v1-resp-to-init-iv-salt')
    },
    baseKey,
    96
  );
  const respToInitIv = new Uint8Array(respToInitIvBits);

  // 5. Derive 32-byte SAS / pairing authentication token
  const sasTokenBits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('file-transfer-v1-sas-auth')
    },
    baseKey,
    256
  );
  const sasToken = new Uint8Array(sasTokenBits);

  // Assign outbound and inbound keys according to role
  const outboundKey = isInitiator ? initToRespAesKey : respToInitAesKey;
  const outboundStaticIv = isInitiator ? initToRespIv : respToInitIv;
  const inboundKey = isInitiator ? respToInitAesKey : initToRespAesKey;
  const inboundStaticIv = isInitiator ? respToInitIv : initToRespIv;

  return {
    outboundKey,
    outboundStaticIv,
    inboundKey,
    inboundStaticIv,
    sasToken
  };
}

/**
 * Generate Short Authentication String (SAS) for out-of-band peer verification.
 * Produces:
 * - 6-digit decimal code (e.g., "741 209")
 * - 4 visual emoji glyphs with zero modulo bias (32 emojis)
 * - 4 memorable phonetic words with zero modulo bias (32 words)
 *
 * @param {Uint8Array} sasToken - 32-byte SAS key material derived from HKDF
 * @returns {{ numericCode: string, glyphs: string, words: string }}
 */
export function generateSAS(sasToken) {
  if (!sasToken || sasToken.length < 16) {
    throw new Error('Valid SAS token of at least 16 bytes is required');
  }

  const view = new DataView(sasToken.buffer, sasToken.byteOffset, sasToken.byteLength);

  // 1. Numeric 6-digit code (modulo 1,000,000)
  const numVal = view.getUint32(0, false);
  const numericCode = (numVal % 1000000).toString().padStart(6, '0');

  // 2. Visual emoji sequence (4 emojis derived from bytes 4, 5, 6, 7 using bitmask 0x1f for 0..31)
  const glyphs = [
    EMOJI_LIST[sasToken[4] & 0x1f],
    EMOJI_LIST[sasToken[5] & 0x1f],
    EMOJI_LIST[sasToken[6] & 0x1f],
    EMOJI_LIST[sasToken[7] & 0x1f]
  ].join(' ');

  // 3. Mnemonic words sequence (4 words derived from bytes 8, 9, 10, 11 using bitmask 0x1f for 0..31)
  const words = [
    WORD_LIST[sasToken[8] & 0x1f],
    WORD_LIST[sasToken[9] & 0x1f],
    WORD_LIST[sasToken[10] & 0x1f],
    WORD_LIST[sasToken[11] & 0x1f]
  ].join(' ');

  return {
    numericCode,
    glyphs,
    words
  };
}
