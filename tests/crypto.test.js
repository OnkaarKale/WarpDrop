import test from 'node:test';
import assert from 'node:assert/strict';

import {
  generateSessionKeyPair,
  exportPublicKey,
  importPeerPublicKey,
  deriveSharedSecretBits,
  bytesToBase64,
  base64ToBytes
} from '../src/crypto/keyExchange.js';

import {
  deriveSessionKeys,
  generateSAS
} from '../src/crypto/kdf.js';

import {
  constructNonce,
  encryptChunk,
  decryptChunk
} from '../src/crypto/cipher.js';

import {
  createStreamingHash
} from '../src/crypto/hash.js';

test('Cryptographic Engine Test Suite', async (t) => {
  await t.test('ECDH P-256 Ephemeral Key Exchange', async (t2) => {
    await t2.test('generates ephemeral keypairs with non-extractable private keys', async () => {
      // Arrange & Act
      const aliceKeys = await generateSessionKeyPair();

      // Assert
      assert.ok(aliceKeys.publicKey, 'Public key must be generated');
      assert.ok(aliceKeys.privateKey, 'Private key must be generated');
      assert.equal(aliceKeys.publicKey.algorithm.name, 'ECDH');
      assert.equal(aliceKeys.publicKey.algorithm.namedCurve, 'P-256');
      assert.equal(aliceKeys.privateKey.extractable, false, 'Private key must be non-extractable');
    });

    await t2.test('exports and imports public keys correctly between peers using browser-safe base64', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();

      // Act
      const alicePubRaw = await exportPublicKey(aliceKeys.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeys.publicKey);

      const importedAlicePub = await importPeerPublicKey(alicePubRaw);
      const importedBobPub = await importPeerPublicKey(bobPubRaw);

      // Assert
      assert.equal(typeof alicePubRaw, 'string', 'Exported key should be base64 string');
      assert.ok(importedAlicePub, 'Imported key must be defined');
      assert.equal(importedAlicePub.algorithm.name, 'ECDH');
    });

    await t2.test('verifies isomorphic Base64 encoder/decoder roundtrip', () => {
      // Arrange
      const sample = new Uint8Array([0, 1, 255, 128, 42, 64, 18, 99]);

      // Act
      const base64 = bytesToBase64(sample);
      const decoded = base64ToBytes(base64);

      // Assert
      assert.deepEqual(decoded, sample, 'Decoded bytes must match original');
    });

    await t2.test('Alice and Bob compute identical shared secrets using ECDH', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();

      const alicePubRaw = await exportPublicKey(aliceKeys.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeys.publicKey);

      const importedBobPub = await importPeerPublicKey(bobPubRaw);
      const importedAlicePub = await importPeerPublicKey(alicePubRaw);

      // Act
      const aliceShared = await deriveSharedSecretBits(aliceKeys.privateKey, importedBobPub);
      const bobShared = await deriveSharedSecretBits(bobKeys.privateKey, importedAlicePub);

      // Assert
      const aliceArr = new Uint8Array(aliceShared);
      const bobArr = new Uint8Array(bobShared);
      assert.equal(aliceArr.length, 32, 'Shared secret should be 256 bits (32 bytes)');
      assert.deepEqual(aliceArr, bobArr, 'Shared secrets must match byte-for-byte');
    });
  });

  await t.test('HKDF-SHA-256 Key Derivation & Domain Separation', async (t2) => {
    await t2.test('derives separate directional AES keys and IV salts (Initiator vs Responder)', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const alicePubRaw = await exportPublicKey(aliceKeys.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeys.publicKey);
      const importedBobPub = await importPeerPublicKey(bobPubRaw);

      const sharedSecret = await deriveSharedSecretBits(aliceKeys.privateKey, importedBobPub);
      const sessionId = 'session-test-uuid-1234';

      // Act: Alice is initiator, Bob is responder
      const aliceSession = await deriveSessionKeys({
        sharedSecretBits: sharedSecret,
        sessionId,
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: true
      });

      const bobSession = await deriveSessionKeys({
        sharedSecretBits: sharedSecret,
        sessionId,
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: false
      });

      // Assert
      // Alice outbound static IV must match Bob inbound static IV
      assert.deepEqual(
        aliceSession.outboundStaticIv,
        bobSession.inboundStaticIv,
        "Alice's outbound IV salt must match Bob's inbound IV salt"
      );
      // Bob outbound static IV must match Alice inbound static IV
      assert.deepEqual(
        bobSession.outboundStaticIv,
        aliceSession.inboundStaticIv,
        "Bob's outbound IV salt must match Alice's inbound IV salt"
      );
      // CRITICAL: Outbound and Inbound IV salts MUST be distinct to prevent bidirectional nonce reuse
      assert.notDeepEqual(
        aliceSession.outboundStaticIv,
        aliceSession.inboundStaticIv,
        'Outbound and Inbound static IV salts must be strictly different'
      );
      assert.ok(aliceSession.sasToken, 'SAS token must be derived');
      assert.equal(aliceSession.sasToken.length, 32, 'SAS token must be 32 bytes');
    });

    await t2.test('different sessions produce completely different keys', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const alicePubRaw = await exportPublicKey(aliceKeys.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeys.publicKey);
      const importedBobPub = await importPeerPublicKey(bobPubRaw);

      const sharedSecret = await deriveSharedSecretBits(aliceKeys.privateKey, importedBobPub);

      // Act
      const session1 = await deriveSessionKeys({
        sharedSecretBits: sharedSecret,
        sessionId: 'session-alpha',
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: true
      });

      const session2 = await deriveSessionKeys({
        sharedSecretBits: sharedSecret,
        sessionId: 'session-beta',
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: true
      });

      // Assert
      assert.notDeepEqual(session1.outboundStaticIv, session2.outboundStaticIv, 'Static IV must differ for different sessions');
      assert.notDeepEqual(session1.sasToken, session2.sasToken, 'SAS token must differ for different sessions');
    });

    await t2.test('SAS generation creates matching 6-digit code and visual glyphs without modulo bias', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const alicePubRaw = await exportPublicKey(aliceKeys.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeys.publicKey);

      const aliceShared = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(bobPubRaw));
      const bobShared = await deriveSharedSecretBits(bobKeys.privateKey, await importPeerPublicKey(alicePubRaw));

      const sessionId = 'session-verified-456';

      // Act
      const aliceKeysDerived = await deriveSessionKeys({
        sharedSecretBits: aliceShared,
        sessionId,
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: true
      });

      const bobKeysDerived = await deriveSessionKeys({
        sharedSecretBits: bobShared,
        sessionId,
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: false
      });

      const aliceSAS = generateSAS(aliceKeysDerived.sasToken);
      const bobSAS = generateSAS(bobKeysDerived.sasToken);

      // Assert
      assert.equal(aliceSAS.numericCode.length, 6, 'Numeric SAS must be 6 digits');
      assert.equal(aliceSAS.numericCode, bobSAS.numericCode, 'Alice and Bob SAS numbers must match');
      assert.equal(aliceSAS.glyphs, bobSAS.glyphs, 'Alice and Bob visual glyphs must match');
      assert.ok(aliceSAS.words.length > 0, 'SAS mnemonic words must exist');
      assert.equal(aliceSAS.words, bobSAS.words, 'SAS words must match');
    });
  });

  await t.test('AES-256-GCM Nonce Strategy & Authenticated Encryption', async (t2) => {
    await t2.test('constructNonce produces strictly unique 96-bit nonces for each sequence number', () => {
      // Arrange
      const staticIv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
      const nonces = new Set();

      // Act
      for (let i = 0; i < 1000; i++) {
        const nonce = constructNonce(staticIv, i);
        assert.equal(nonce.length, 12, 'Nonce must be 12 bytes');
        const hex = Buffer.from(nonce).toString('hex');
        assert.equal(nonces.has(hex), false, `Nonce must not collide for index ${i}`);
        nonces.add(hex);
      }

      // Assert
      assert.equal(nonces.size, 1000, 'All 1000 nonces must be strictly unique');
    });

    await t2.test('rejects negative or invalid sequence numbers for nonce construction', () => {
      // Arrange
      const staticIv = new Uint8Array(12);

      // Act & Assert
      assert.throws(() => constructNonce(staticIv, -1), /Invalid sequence number/);
      assert.throws(() => constructNonce(staticIv, Number.MAX_SAFE_INTEGER + 1), /Invalid sequence number/);
      assert.throws(() => constructNonce(new Uint8Array(10), 0), /Invalid static IV/);
    });

    await t2.test('full-duplex bidirectional transmission uses independent key/nonce spaces', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const alicePub = await exportPublicKey(aliceKeys.publicKey);
      const bobPub = await exportPublicKey(bobKeys.publicKey);

      const sharedA = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(bobPub));
      const sharedB = await deriveSharedSecretBits(bobKeys.privateKey, await importPeerPublicKey(alicePub));

      const alice = await deriveSessionKeys({
        sharedSecretBits: sharedA,
        sessionId: 'duplex-test',
        initiatorPubKey: alicePub,
        responderPubKey: bobPub,
        isInitiator: true
      });

      const bob = await deriveSessionKeys({
        sharedSecretBits: sharedB,
        sessionId: 'duplex-test',
        initiatorPubKey: alicePub,
        responderPubKey: bobPub,
        isInitiator: false
      });

      // Alice sends Chunk #0 to Bob
      const msgAliceToBob = new TextEncoder().encode('Alice payload chunk 0');
      const encA = await encryptChunk({
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv,
        chunkIndex: 0,
        data: msgAliceToBob,
        aad: new TextEncoder().encode('aad-0')
      });

      // Bob sends Chunk #0 to Alice simultaneously
      const msgBobToAlice = new TextEncoder().encode('Bob payload chunk 0');
      const encB = await encryptChunk({
        key: bob.outboundKey,
        staticIv: bob.outboundStaticIv,
        chunkIndex: 0,
        data: msgBobToAlice,
        aad: new TextEncoder().encode('aad-0')
      });

      // Nonces for chunk #0 in opposite directions must be distinct
      assert.notDeepEqual(encA.iv, encB.iv, 'Opposite direction nonces must never collide');

      // Bob decrypts Alice chunk
      const decBob = await decryptChunk({
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv,
        chunkIndex: 0,
        ciphertext: encA.ciphertext,
        aad: new TextEncoder().encode('aad-0')
      });
      assert.equal(new TextDecoder().decode(decBob), 'Alice payload chunk 0');

      // Alice decrypts Bob chunk
      const decAlice = await decryptChunk({
        key: alice.inboundKey,
        staticIv: alice.inboundStaticIv,
        chunkIndex: 0,
        ciphertext: encB.ciphertext,
        aad: new TextEncoder().encode('aad-0')
      });
      assert.equal(new TextDecoder().decode(decAlice), 'Bob payload chunk 0');
    });

    await t2.test('fails decryption if ciphertext is tampered with', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const shared = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(await exportPublicKey(bobKeys.publicKey)));
      const { outboundKey, outboundStaticIv } = await deriveSessionKeys({
        sharedSecretBits: shared,
        sessionId: 'tamper-test',
        initiatorPubKey: 'pubA',
        responderPubKey: 'pubB',
        isInitiator: true
      });

      const chunkData = new TextEncoder().encode('Authentic payload');
      const aad = new TextEncoder().encode('aad-chunk-0');

      const encrypted = await encryptChunk({
        key: outboundKey,
        staticIv: outboundStaticIv,
        chunkIndex: 0,
        data: chunkData,
        aad
      });

      // Act: Flip a bit in the ciphertext
      const tamperedCiphertext = new Uint8Array(encrypted.ciphertext);
      tamperedCiphertext[5] ^= 0xff;

      // Assert
      await assert.rejects(
        async () => {
          await decryptChunk({
            key: outboundKey,
            staticIv: outboundStaticIv,
            chunkIndex: 0,
            ciphertext: tamperedCiphertext,
            aad
          });
        },
        /OperationError|operation failed|authentication failed/i,
        'Decryption must fail when ciphertext is modified'
      );
    });

    await t2.test('fails decryption if AAD is altered', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const shared = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(await exportPublicKey(bobKeys.publicKey)));
      const { outboundKey, outboundStaticIv } = await deriveSessionKeys({
        sharedSecretBits: shared,
        sessionId: 'aad-test',
        initiatorPubKey: 'pubA',
        responderPubKey: 'pubB',
        isInitiator: true
      });

      const chunkData = new TextEncoder().encode('Authentic payload');
      const originalAad = new TextEncoder().encode('chunk-index: 0');
      const forgedAad = new TextEncoder().encode('chunk-index: 1');

      const encrypted = await encryptChunk({
        key: outboundKey,
        staticIv: outboundStaticIv,
        chunkIndex: 0,
        data: chunkData,
        aad: originalAad
      });

      // Assert
      await assert.rejects(
        async () => {
          await decryptChunk({
            key: outboundKey,
            staticIv: outboundStaticIv,
            chunkIndex: 0,
            ciphertext: encrypted.ciphertext,
            aad: forgedAad
          });
        },
        /OperationError|operation failed|authentication failed/i,
        'Decryption must fail when AAD is altered'
      );
    });

    await t2.test('fails decryption when using wrong session key', async () => {
      // Arrange
      const aliceKeys = await generateSessionKeyPair();
      const bobKeys = await generateSessionKeyPair();
      const charlieKeys = await generateSessionKeyPair();

      const sharedAB = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(await exportPublicKey(bobKeys.publicKey)));
      const sharedAC = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(await exportPublicKey(charlieKeys.publicKey)));

      const sessionAB = await deriveSessionKeys({ sharedSecretBits: sharedAB, sessionId: 's1', initiatorPubKey: 'A', responderPubKey: 'B', isInitiator: true });
      const sessionAC = await deriveSessionKeys({ sharedSecretBits: sharedAC, sessionId: 's1', initiatorPubKey: 'A', responderPubKey: 'C', isInitiator: true });

      const encrypted = await encryptChunk({
        key: sessionAB.outboundKey,
        staticIv: sessionAB.outboundStaticIv,
        chunkIndex: 0,
        data: new TextEncoder().encode('Target confidential file chunk'),
        aad: new Uint8Array(0)
      });

      // Assert
      await assert.rejects(
        async () => {
          await decryptChunk({
            key: sessionAC.outboundKey,
            staticIv: sessionAB.outboundStaticIv,
            chunkIndex: 0,
            ciphertext: encrypted.ciphertext,
            aad: new Uint8Array(0)
          });
        },
        /OperationError|operation failed|authentication failed/i,
        'Wrong session key must not decrypt ciphertext'
      );
    });
  });

  await t.test('Incremental Streaming SHA-256 Integrity Verification', async (t2) => {
    await t2.test('computes correct digest across multiple streaming updates', () => {
      // Arrange
      const hasher = createStreamingHash();
      const chunk1 = new TextEncoder().encode('Hello, ');
      const chunk2 = new TextEncoder().encode('P2P ');
      const chunk3 = new TextEncoder().encode('World!');

      // Act
      hasher.update(chunk1);
      hasher.update(chunk2);
      hasher.update(chunk3);
      const digestHex = hasher.digest('hex');

      // Compare with single-shot of 'Hello, P2P World!'
      const fullHasher = createStreamingHash();
      fullHasher.update(new TextEncoder().encode('Hello, P2P World!'));
      const expectedHex = fullHasher.digest('hex');

      // Assert
      assert.equal(digestHex, expectedHex, 'Incremental hash must match full payload hash');
      assert.equal(digestHex.length, 64, 'SHA-256 hex string must be 64 characters');
    });

    await t2.test('detects single bit tamper in stream', () => {
      // Arrange
      const h1 = createStreamingHash();
      const h2 = createStreamingHash();

      const data1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const data2 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 9]); // 1 bit altered

      // Act
      h1.update(data1);
      h2.update(data2);

      // Assert
      assert.notEqual(h1.digest('hex'), h2.digest('hex'), 'Hash must change when data is altered');
    });
  });
});
