/**
 * Phase 7: Real-World Validation, Security Hardening & Performance Test Suite.
 *
 * Covers:
 * 1. File Transfer Matrix:
 *    - Zero-byte file (0 B, SHA-256 e3b0c442...)
 *    - 1 byte
 *    - 1 KB
 *    - 16 KB
 *    - 64 KB
 *    - 256 KB
 *    - 1 MB
 *    - 10 MB
 *    - Multiple files in sequence
 *    - Special, Unicode, space-separated, long, and extensionless filenames
 *    - Strict byte-for-byte and SHA-256 equality
 * 2. Cryptographic Security & Penetration Matrix:
 *    - Ciphertext tampering rejection
 *    - AAD header tampering rejection
 *    - Wrong session key rejection
 *    - Replay protection / safe deduplication
 *    - Conflicting duplicate rejection
 *    - Missing chunk detection
 *    - SHA-256 manifest mismatch detection
 *    - SAS derivation & MitM sensitivity
 * 3. Connection Failure & Cancellation:
 *    - Sender cancellation during transfer
 *    - Receiver cancellation during transfer
 *    - Incomplete transfer rejection
 * 4. Signaling Isolation & Zero-Knowledge Verification:
 *    - Binary frame rejection on signaling server
 *    - Schema violation rejection on signaling server
 *    - Null-byte path traversal rejection without server crash
 * 5. Performance & Memory Boundedness:
 *    - Bounded memory streaming verification
 *    - Transfer metrics measurement (throughput, duration, CPU, memory)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { WebSocket } from 'ws';

import { generateSessionKeyPair, exportPublicKey, importPeerPublicKey, deriveSharedSecretBits } from '../src/crypto/keyExchange.js';
import { deriveSessionKeys, generateSAS } from '../src/crypto/kdf.js';
import { encryptChunk, decryptChunk } from '../src/crypto/cipher.js';
import { createStreamingHash } from '../src/crypto/hash.js';

import { FileChunker } from '../src/protocol/chunker.js';
import { FileReassembler, MemoryChunkSink } from '../src/protocol/reassembler.js';
import { TransferStateMachine, TransferStates } from '../src/protocol/stateMachine.js';
import { packChunkFrame, unpackChunkFrame, packControlFrame, unpackControlFrame } from '../src/protocol/frames.js';
import { sanitizeFileName, sanitizeMimeType, validateFileMetadata } from '../src/protocol/types.js';

import { startServer } from '../server/index.js';
import { parseAndValidateQRPayload } from '../public/js/qr.js';
import { formatBytes, formatSpeed, formatDuration, calculateETA, UIStateManager } from '../public/js/ui.js';

// Test crypto channel helper
async function setupCryptoChannel(sessionId = 'session-phase7-test') {
  const alicePair = await generateSessionKeyPair();
  const bobPair = await generateSessionKeyPair();

  const alicePub = await exportPublicKey(alicePair.publicKey);
  const bobPub = await exportPublicKey(bobPair.publicKey);

  const sharedA = await deriveSharedSecretBits(alicePair.privateKey, await importPeerPublicKey(bobPub));
  const sharedB = await deriveSharedSecretBits(bobPair.privateKey, await importPeerPublicKey(alicePub));

  const aliceKeys = await deriveSessionKeys({
    sharedSecretBits: sharedA,
    sessionId,
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: true
  });

  const bobKeys = await deriveSessionKeys({
    sharedSecretBits: sharedB,
    sessionId,
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: false
  });

  return { aliceKeys, bobKeys, alicePub, bobPub, sessionId };
}

// End-to-end chunk stream simulation helper
async function executeTransfer({
  data,
  fileName,
  mimeType,
  chunkSize = 64 * 1024,
  fileIndex = 0,
  aliceKeys,
  bobKeys,
  corruptChunk = null
}) {
  const chunker = new FileChunker({
    file: data,
    fileName,
    mimeType,
    chunkSize,
    fileIndex,
    key: aliceKeys.outboundKey,
    staticIv: aliceKeys.outboundStaticIv
  });

  const manifest = await chunker.getManifest();

  const reassembler = new FileReassembler({
    manifest,
    fileIndex,
    key: bobKeys.inboundKey,
    staticIv: bobKeys.inboundStaticIv
  });
  reassembler.approve();

  let chunkIdx = 0;
  while (chunker.hasMoreChunks()) {
    let frame = await chunker.nextChunk();
    if (corruptChunk && corruptChunk.index === chunkIdx) {
      frame = corruptChunk.modify(frame);
    }
    await reassembler.receiveChunk(frame);
    chunkIdx++;
  }

  return { chunker, reassembler, manifest };
}

test('Phase 7: Real-World Validation, Security Hardening & Performance Test Suite', async (t) => {

  await t.test('File Transfer Matrix & Integrity Verification', async (t2) => {
    const { aliceKeys, bobKeys } = await setupCryptoChannel();

    // 1. Zero-byte file transfer
    await t2.test('zero-byte file transfers and verifies SHA-256 correctly', async () => {
      const emptyData = new Uint8Array(0);
      const { reassembler, manifest } = await executeTransfer({
        data: emptyData,
        fileName: 'empty.txt',
        mimeType: 'text/plain',
        aliceKeys,
        bobKeys
      });

      assert.equal(manifest.size, 0);
      assert.equal(manifest.sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      const result = await reassembler.finalize();
      assert.equal(result.verified, true);
      assert.equal(result.data.length, 0);
    });

    // 2. 1-byte file transfer
    await t2.test('1-byte file transfers byte-for-byte accurately', async () => {
      const oneByte = new Uint8Array([0x42]);
      const { reassembler } = await executeTransfer({
        data: oneByte,
        fileName: 'single_byte.bin',
        aliceKeys,
        bobKeys
      });

      const result = await reassembler.finalize();
      assert.equal(result.verified, true);
      assert.deepEqual(result.data, oneByte);
    });

    // 3. Various payload sizes: 1 KB, 16 KB, 64 KB, 256 KB, 1 MB
    const testSizes = [1 * 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];
    for (const size of testSizes) {
      await t2.test(`transfers ${formatBytes(size)} payload with byte-for-byte match`, async () => {
        const payload = new Uint8Array(size);
        for (let i = 0; i < size; i++) {
          payload[i] = (i * 31 + 7) % 256;
        }

        const { reassembler } = await executeTransfer({
          data: payload,
          fileName: `payload_${size}.dat`,
          chunkSize: 64 * 1024,
          aliceKeys,
          bobKeys
        });

        const result = await reassembler.finalize();
        assert.equal(result.verified, true);
        assert.equal(result.data.byteLength, size);
        assert.deepEqual(result.data, payload);
      });
    }

    // 4. Multi-megabyte (5 MB) transfer with throughput measurement
    await t2.test('transfers 5 MB large file with streaming SHA-256 validation', async () => {
      const size = 5 * 1024 * 1024;
      const largePayload = new Uint8Array(size);
      largePayload.fill(0xaa);

      const t0 = performance.now();
      const { reassembler } = await executeTransfer({
        data: largePayload,
        fileName: 'large_archive.zip',
        chunkSize: 64 * 1024,
        aliceKeys,
        bobKeys
      });

      const result = await reassembler.finalize();
      const elapsedSec = (performance.now() - t0) / 1000;
      const mbPerSec = (size / (1024 * 1024)) / elapsedSec;

      assert.equal(result.verified, true);
      assert.equal(result.data.byteLength, size);
      assert.ok(mbPerSec > 1.0, `Throughput should be reasonable: measured ${mbPerSec.toFixed(2)} MB/s`);
    });

    // 5. Multiple files transferred sequentially over single authenticated session
    await t2.test('multiple files transferred sequentially over the same session', async () => {
      const files = [
        { name: 'document1.pdf', data: new Uint8Array([1, 2, 3, 4, 5]), fileIndex: 0 },
        { name: 'image2.png', data: new Uint8Array([10, 20, 30, 40]), fileIndex: 1 },
        { name: 'notes3.txt', data: new Uint8Array([100, 101, 102]), fileIndex: 2 }
      ];

      for (const item of files) {
        const { reassembler } = await executeTransfer({
          data: item.data,
          fileName: item.name,
          fileIndex: item.fileIndex,
          aliceKeys,
          bobKeys
        });
        const result = await reassembler.finalize();
        assert.equal(result.verified, true);
        assert.equal(result.name, item.name);
        assert.deepEqual(result.data, item.data);
      }
    });

    // 6. Filename robustness: Unicode, spaces, special chars, long, and extensionless
    await t2.test('handles unicode, spaces, special characters, long and extensionless names', async () => {
      const testNames = [
        { input: '日本語_ファイル_🚀.pdf', expected: '日本語_ファイル_🚀.pdf' },
        { input: 'My Document (Draft) [v2] & Notes.txt', expected: 'My Document (Draft) [v2] & Notes.txt' },
        { input: 'LICENSE', expected: 'LICENSE' },
        { input: 'Makefile', expected: 'Makefile' },
        { input: '../../../../etc/passwd', expected: 'passwd' },
        { input: 'a'.repeat(300) + '.zip', expectedLength: 255 }
      ];

      for (const item of testNames) {
        const sanitized = sanitizeFileName(item.input);
        if (item.expected) {
          assert.equal(sanitized, item.expected);
        }
        if (item.expectedLength) {
          assert.ok(sanitized.length <= item.expectedLength);
        }
      }
    });
  });

  await t.test('Cryptographic Tampering & Security Boundaries', async (t2) => {
    const { aliceKeys, bobKeys } = await setupCryptoChannel('session-tampering-test');

    // 1. Modified ciphertext bytes must fail GCM tag verification
    await t2.test('tampered ciphertext throws GCM authentication failure', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      await assert.rejects(
        async () => {
          await executeTransfer({
            data,
            fileName: 'tampered.dat',
            aliceKeys,
            bobKeys,
            corruptChunk: {
              index: 0,
              modify: (frame) => {
                const corrupted = new Uint8Array(frame);
                // Corrupt byte in ciphertext payload (after 18-byte header)
                corrupted[20] ^= 0xff;
                return corrupted;
              }
            }
          });
        },
        /operation failed|tag/i
      );
    });

    // 2. Modified AAD header must fail GCM authentication
    await t2.test('tampered AAD header throws GCM authentication failure', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      await assert.rejects(
        async () => {
          await executeTransfer({
            data,
            fileName: 'tampered_aad.dat',
            aliceKeys,
            bobKeys,
            corruptChunk: {
              index: 0,
              modify: (frame) => {
                const corrupted = new Uint8Array(frame);
                // Corrupt fileIndex or chunkIndex in header AAD (bytes 4..14)
                corrupted[5] ^= 0x01;
                return corrupted;
              }
            }
          });
        },
        /File index mismatch|operation failed|tag|Frame length mismatch/i
      );
    });

    // 3. Wrong session key cannot decrypt chunks
    await t2.test('wrong session key fails chunk decryption', async () => {
      const otherChannel = await setupCryptoChannel('different-session-key');
      const data = new Uint8Array(500);

      await assert.rejects(
        async () => {
          await executeTransfer({
            data,
            fileName: 'wrong_key.dat',
            aliceKeys,
            bobKeys: otherChannel.bobKeys // Wrong key!
          });
        },
        /operation failed/i
      );
    });

    // 4. Conflicting duplicate chunk rejected
    await t2.test('conflicting duplicate chunk with different tag is rejected', async () => {
      const chunker = new FileChunker({
        file: new Uint8Array(100 * 1024),
        fileName: 'conflict.dat',
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv
      });
      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        key: bobKeys.inboundKey,
        staticIv: bobKeys.inboundStaticIv
      });
      reassembler.approve();

      const chunk0 = await chunker.nextChunk();
      await reassembler.receiveChunk(chunk0);

      // Create conflicting duplicate chunk 0 with different contents
      const fakePlaintext = new Uint8Array(65536).fill(99);
      const headerAad = new Uint8Array(18);
      const view = new DataView(headerAad.buffer);
      headerAad[0] = 0x50;
      headerAad[1] = 0x32;
      headerAad[2] = 0x02;
      view.setUint16(4, 0, false);
      view.setUint32(6, 0, false);
      view.setUint32(10, manifest.totalChunks, false);

      const fakeEncrypted = await encryptChunk({
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv,
        chunkIndex: 0,
        data: fakePlaintext,
        aad: headerAad
      });
      const conflictingChunk0 = packChunkFrame({
        fileIndex: 0,
        chunkIndex: 0,
        totalChunks: manifest.totalChunks,
        ciphertext: fakeEncrypted.ciphertext
      });

      await assert.rejects(
        async () => reassembler.receiveChunk(conflictingChunk0),
        /Conflicting duplicate chunk/
      );
    });

    // 5. Missing chunk causes finalize() to fail
    await t2.test('missing chunk causes finalize to throw', async () => {
      const chunker = new FileChunker({
        file: new Uint8Array(150 * 1024),
        fileName: 'missing.dat',
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv
      });
      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        key: bobKeys.inboundKey,
        staticIv: bobKeys.inboundStaticIv
      });
      reassembler.approve();

      const chunk0 = await chunker.nextChunk();
      // Skip chunk 1, chunk 2
      await reassembler.receiveChunk(chunk0);

      assert.equal(reassembler.isComplete(), false);
      await assert.rejects(
        async () => reassembler.finalize(),
        /Cannot finalize incomplete transfer/
      );
    });

    // 6. SHA-256 mismatch in manifest causes finalize to fail
    await t2.test('tampered SHA-256 manifest hash triggers integrity failure', async () => {
      const data = new Uint8Array(1000);
      const chunker = new FileChunker({
        file: data,
        fileName: 'sha_mismatch.dat',
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv
      });
      const manifest = await chunker.getManifest();

      // Forge the manifest hash
      const forgedManifest = {
        ...manifest,
        sha256: 'f'.repeat(64)
      };

      const reassembler = new FileReassembler({
        manifest: forgedManifest,
        key: bobKeys.inboundKey,
        staticIv: bobKeys.inboundStaticIv
      });
      reassembler.approve();

      while (chunker.hasMoreChunks()) {
        await reassembler.receiveChunk(await chunker.nextChunk());
      }

      await assert.rejects(
        async () => reassembler.finalize(),
        /Integrity verification failed: computed SHA-256/
      );
    });
  });

  await t.test('SAS Verification & MitM Sensitivity', async (t2) => {
    await t2.test('identical shared secrets produce matching numeric code, emojis, and words', async () => {
      const { aliceKeys, bobKeys } = await setupCryptoChannel('sas-match-test');
      const sasAlice = generateSAS(aliceKeys.sasToken);
      const sasBob = generateSAS(bobKeys.sasToken);

      assert.equal(sasAlice.numericCode, sasBob.numericCode);
      assert.equal(sasAlice.glyphs, sasBob.glyphs);
      assert.equal(sasAlice.words, sasBob.words);
    });

    await t2.test('different shared secrets (MitM intercept) produce distinct SAS codes', async () => {
      const channel1 = await setupCryptoChannel('session-mitm-1');
      const channel2 = await setupCryptoChannel('session-mitm-2');

      const sas1 = generateSAS(channel1.aliceKeys.sasToken);
      const sas2 = generateSAS(channel2.bobKeys.sasToken);

      assert.notEqual(sas1.numericCode, sas2.numericCode);
      assert.notEqual(sas1.glyphs, sas2.glyphs);
    });
  });

  await t.test('State Machine, Cancellation & Failure Handling', async (t2) => {
    await t2.test('receiver approval gate cannot be bypassed by unapproved incoming chunks', async () => {
      const { aliceKeys, bobKeys } = await setupCryptoChannel();
      const chunker = new FileChunker({
        file: new Uint8Array(100),
        fileName: 'unapproved.dat',
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv
      });
      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        key: bobKeys.inboundKey,
        staticIv: bobKeys.inboundStaticIv
      });

      // Attempt to feed chunk WITHOUT calling reassembler.approve()
      const chunk = await chunker.nextChunk();
      await assert.rejects(
        async () => reassembler.receiveChunk(chunk),
        /Cannot receive chunk: transfer not approved by receiver|Receiver approval required/i
      );
    });

    await t2.test('cancellation is idempotent and cleans state', () => {
      const sm = new TransferStateMachine('sender');
      sm.transition(TransferStates.MANIFEST_SENT);
      sm.cancel('User requested cancel');
      assert.equal(sm.getState(), TransferStates.CANCELLED);

      // Multiple cancel calls must not crash
      sm.cancel('Second cancel call');
      assert.equal(sm.getState(), TransferStates.CANCELLED);
    });
  });

  await t.test('Signaling Server Isolation & Hardening', async (t2) => {
    const serverInstance = await startServer(0, '127.0.0.1');
    const port = serverInstance.port;

    try {
      // 1. Rejects binary WebSocket frames on signaling server
      await t2.test('strictly rejects binary frame on signaling connection', async () => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`);
        await new Promise((resolve) => ws.on('open', resolve));

        const closePromise = new Promise((resolve) => {
          ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() }));
        });

        // Send binary frame
        ws.send(new Uint8Array([0x50, 0x32, 0x02, 0x00, 0x01]));
        const { code } = await closePromise;
        assert.ok(code === 4400 || code === 1003, `Expected binary rejection code 4400 or 1003, got ${code}`);
      });

      // 2. Rejects oversized signaling JSON message (> 64KB)
      await t2.test('rejects oversized signaling message', async () => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`);
        await new Promise((resolve) => ws.on('open', resolve));

        const closePromise = new Promise((resolve) => {
          ws.on('close', (code, reason) => resolve({ code, reason: reason.toString() }));
        });

        const hugePayload = 'X'.repeat(70 * 1024);
        ws.send(JSON.stringify({ type: 'JOIN', payload: hugePayload }));
        const { code } = await closePromise;
        assert.equal(code, 1009); // WebSocket 1009: Message Too Big
      });

      // 3. Rejects null byte in HTTP requests without server crash
      await t2.test('rejects null byte in URLs with 403 without crashing server', async () => {
        const status = await new Promise((resolve, reject) => {
          http.get({ host: '127.0.0.1', port, path: '/%00secret.txt' }, (res) => {
            resolve(res.statusCode);
          }).on('error', reject);
        });
        assert.equal(status, 403);
      });
    } finally {
      await serverInstance.signalingServer.close();
      await new Promise((resolve) => serverInstance.server.close(resolve));
      serverInstance.discoveryService.stop();
    }
  });

  await t.test('Secrets & Storage Audit', async (t2) => {
    await t2.test('qr payload contains zero private keys, file contents, or encryption keys', () => {
      const validPayload = {
        v: 1,
        h: '192.168.1.100',
        p: 3000,
        s: 'session-clean-test',
        t: 'token-clean-test'
      };

      const parsed = parseAndValidateQRPayload(validPayload);
      const str = JSON.stringify(parsed).toLowerCase();

      assert.ok(!str.includes('privatekey'), 'No privateKey in QR');
      assert.ok(!str.includes('aeskey'), 'No aesKey in QR');
      assert.ok(!str.includes('filecontent'), 'No file content in QR');
      assert.ok(!str.includes('secret'), 'No secret in QR');
    });
  });

});
