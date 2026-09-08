import test from 'node:test';
import assert from 'node:assert/strict';

import {
  FRAME_TYPE_CONTROL,
  FRAME_TYPE_CHUNK,
  MIN_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  MAX_CONTROL_PAYLOAD,
  MAX_FILE_SIZE,
  MAX_TOTAL_CHUNKS,
  sanitizeFileName,
  sanitizeMimeType,
  validateFileMetadata
} from '../src/protocol/types.js';

import {
  packChunkFrame,
  unpackChunkFrame,
  packControlFrame,
  unpackControlFrame
} from '../src/protocol/frames.js';

import {
  TransferStateMachine,
  TransferStates
} from '../src/protocol/stateMachine.js';

import {
  FileChunker
} from '../src/protocol/chunker.js';

import {
  FileReassembler,
  MemoryChunkSink
} from '../src/protocol/reassembler.js';

import {
  FlowController
} from '../src/transport/flowControl.js';

import {
  generateSessionKeyPair,
  exportPublicKey,
  importPeerPublicKey,
  deriveSharedSecretBits
} from '../src/crypto/keyExchange.js';

import {
  deriveSessionKeys
} from '../src/crypto/kdf.js';

// Helper to set up an authenticated crypto channel between Alice and Bob
async function createCryptoChannel() {
  const aliceKeys = await generateSessionKeyPair();
  const bobKeys = await generateSessionKeyPair();
  const alicePub = await exportPublicKey(aliceKeys.publicKey);
  const bobPub = await exportPublicKey(bobKeys.publicKey);

  const sharedA = await deriveSharedSecretBits(aliceKeys.privateKey, await importPeerPublicKey(bobPub));
  const sharedB = await deriveSharedSecretBits(bobKeys.privateKey, await importPeerPublicKey(alicePub));

  const alice = await deriveSessionKeys({
    sharedSecretBits: sharedA,
    sessionId: 'test-session-proto',
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: true
  });

  const bob = await deriveSessionKeys({
    sharedSecretBits: sharedB,
    sessionId: 'test-session-proto',
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: false
  });

  return { alice, bob };
}

test('Transfer Protocol & Framing Test Suite', async (t) => {
  await t.test('Metadata Validation & Sanitization', async (t2) => {
    await t2.test('sanitizes malicious filenames against path traversal', () => {
      assert.equal(sanitizeFileName('../../etc/passwd'), 'passwd');
      assert.equal(sanitizeFileName('..\\..\\Windows\\System32\\cmd.exe'), 'cmd.exe');
      assert.equal(sanitizeFileName('/var/log/secret.txt'), 'secret.txt');
      assert.equal(sanitizeFileName('foo/bar/baz.pdf'), 'baz.pdf');
      assert.equal(sanitizeFileName(''), 'unnamed_file');
      assert.equal(sanitizeFileName('   '), 'unnamed_file');
      assert.equal(sanitizeFileName('....'), 'unnamed_file');
    });

    await t2.test('truncates overly long filenames safely', () => {
      const longName = 'a'.repeat(300) + '.txt';
      const sanitized = sanitizeFileName(longName);
      assert.ok(sanitized.length <= 255, 'Filename must be capped at 255 chars');
    });

    await t2.test('sanitizes MIME types and rejects dangerous formats', () => {
      assert.equal(sanitizeMimeType('application/pdf'), 'application/pdf');
      assert.equal(sanitizeMimeType('image/png'), 'image/png');
      assert.equal(sanitizeMimeType('text/html; charset=utf-8'), 'text/html');
      assert.equal(sanitizeMimeType('<script>alert(1)</script>'), 'application/octet-stream');
      assert.equal(sanitizeMimeType(''), 'application/octet-stream');
    });

    await t2.test('rejects impossible file metadata and integer overflows', () => {
      const validSha = 'a'.repeat(64);
      // Negative size
      assert.throws(() => validateFileMetadata({ name: 'f.txt', size: -1, chunkSize: 65536, totalChunks: 1, sha256: validSha }), /Invalid file size/);
      // Size exceeds maximum (100 GB)
      assert.throws(() => validateFileMetadata({ name: 'f.txt', size: MAX_FILE_SIZE + 1, chunkSize: 65536, totalChunks: 1, sha256: validSha }), /exceeds maximum/);
      // Inconsistent chunk count
      assert.throws(() => validateFileMetadata({ name: 'f.txt', size: 100000, chunkSize: 65536, totalChunks: 5, sha256: validSha }), /Total chunks mismatch/);
      // Non-integer or out-of-bounds chunk size
      assert.throws(() => validateFileMetadata({ name: 'f.txt', size: 1000, chunkSize: 0, totalChunks: 1, sha256: validSha }), /Invalid chunk size/);
      // Missing mandatory SHA-256
      assert.throws(() => validateFileMetadata({ name: 'f.txt', size: 1000, chunkSize: 65536, totalChunks: 1 }), /Missing or invalid mandatory SHA-256/);
    });

    await t2.test('accepts valid metadata with sanitized output', () => {
      const validated = validateFileMetadata({
        name: '../../../reports/annual.pdf',
        size: 131072,
        chunkSize: 65536,
        totalChunks: 2,
        mimeType: 'application/pdf',
        sha256: 'a'.repeat(64)
      });
      assert.equal(validated.name, 'annual.pdf');
      assert.equal(validated.totalChunks, 2);
      assert.equal(validated.mimeType, 'application/pdf');
      assert.equal(validated.sha256, 'a'.repeat(64));
    });
  });

  await t.test('Binary Frame Packing & Validation', async (t2) => {
    await t2.test('packs and unpacks a valid chunk frame', () => {
      const payload = new Uint8Array([10, 20, 30, 40, 50]);
      const frame = packChunkFrame({
        fileIndex: 1,
        chunkIndex: 42,
        totalChunks: 100,
        ciphertext: payload
      });

      const unpacked = unpackChunkFrame(frame);

      assert.equal(unpacked.fileIndex, 1);
      assert.equal(unpacked.chunkIndex, 42);
      assert.equal(unpacked.totalChunks, 100);
      assert.deepEqual(unpacked.ciphertext, payload);
      assert.equal(unpacked.headerAad.length, 18, 'Header AAD should be 18 bytes');
    });

    await t2.test('rejects truncated or malformed binary frames', () => {
      // Too short
      assert.throws(() => unpackChunkFrame(new Uint8Array(10)), /Frame too short/);

      // Invalid magic bytes
      const badMagic = new Uint8Array(20);
      badMagic[0] = 0x00;
      badMagic[1] = 0x00;
      assert.throws(() => unpackChunkFrame(badMagic), /Invalid frame magic/);

      // Wrong frame type
      const wrongType = packControlFrame({ controlSeq: 1, ciphertext: new Uint8Array(10) });
      assert.throws(() => unpackChunkFrame(wrongType), /Expected CHUNK frame/);
    });

    await t2.test('rejects oversized frame payload length', () => {
      const frame = new Uint8Array(18);
      frame[0] = 0x50; // 'P'
      frame[1] = 0x32; // '2'
      frame[2] = FRAME_TYPE_CHUNK;
      const view = new DataView(frame.buffer);
      view.setUint32(14, MAX_CHUNK_SIZE + 100000, false); // Claim huge payload
      assert.throws(() => unpackChunkFrame(frame), /Payload length exceeds limit/);
    });
  });

  await t.test('Transfer State Machine & Explicit Receiver Approval Gate', async (t2) => {
    await t2.test('enforces receiver approval before moving to transferring state', () => {
      const sm = new TransferStateMachine('receiver');
      assert.equal(sm.getState(), TransferStates.IDLE);

      sm.transition(TransferStates.MANIFEST_RECEIVED);
      sm.transition(TransferStates.AWAITING_APPROVAL);

      // Attempting to jump to transferring without approval must fail
      assert.throws(() => sm.transition(TransferStates.TRANSFERRING), /Illegal transition/);

      // Explicit user approval
      sm.approve();
      assert.equal(sm.getState(), TransferStates.ACCEPTED);

      // Now transferring can start
      sm.transition(TransferStates.TRANSFERRING);
      assert.equal(sm.getState(), TransferStates.TRANSFERRING);

      sm.transition(TransferStates.VERIFYING);
      assert.equal(sm.getState(), TransferStates.VERIFYING);

      sm.transition(TransferStates.COMPLETED);
      assert.equal(sm.getState(), TransferStates.COMPLETED);
    });

    await t2.test('rejects illegal state transitions', () => {
      const sm = new TransferStateMachine('receiver');
      assert.equal(sm.getState(), TransferStates.IDLE);

      // Cannot jump from IDLE to COMPLETED
      assert.throws(() => sm.transition(TransferStates.COMPLETED), /Illegal transition/);

      // Cannot transition out of COMPLETED
      sm.transition(TransferStates.MANIFEST_RECEIVED);
      sm.approve();
      sm.transition(TransferStates.TRANSFERRING);
      sm.transition(TransferStates.VERIFYING);
      sm.transition(TransferStates.COMPLETED);
      assert.throws(() => sm.transition(TransferStates.TRANSFERRING), /Illegal transition/);
    });

    await t2.test('allows cancellation from any active state', () => {
      const sm = new TransferStateMachine('sender');
      sm.transition(TransferStates.MANIFEST_SENT);
      sm.transition(TransferStates.TRANSFERRING);
      sm.cancel('User clicked cancel');
      assert.equal(sm.getState(), TransferStates.CANCELLED);
    });
  });

  await t.test('End-to-End Encrypted Chunking, Streaming & Reassembly', async (t2) => {
    await t2.test('transfers, decrypts, and verifies file integrity with SHA-256', async () => {
      const { alice, bob } = await createCryptoChannel();

      // Create a 250 KB test payload
      const payloadSize = 250 * 1024;
      const originalBytes = new Uint8Array(payloadSize);
      for (let i = 0; i < payloadSize; i++) {
        originalBytes[i] = i % 256;
      }

      const chunkSize = 64 * 1024; // 64 KB chunks
      const chunker = new FileChunker({
        file: originalBytes,
        fileName: 'test_document.dat',
        chunkSize,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      assert.equal(manifest.totalChunks, 4); // ceil(250 / 64) = 4
      assert.equal(manifest.sha256.length, 64);

      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve(); // Explicit approval

      // Stream all chunks from chunker to reassembler
      while (chunker.hasMoreChunks()) {
        const chunkFrame = await chunker.nextChunk();
        assert.ok(chunkFrame instanceof Uint8Array);
        await reassembler.receiveChunk(chunkFrame);
      }

      assert.equal(reassembler.isComplete(), true);
      const result = await reassembler.finalize();

      assert.equal(result.verified, true, 'SHA-256 must match manifest');
      assert.equal(result.data.length, payloadSize);
      assert.deepEqual(result.data, originalBytes, 'Reassembled data must match original bytes exactly');
    });

    await t2.test('handles out-of-order chunk delivery correctly', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new Uint8Array(150 * 1024); // 3 chunks of 64KB
      testData.fill(42);

      const chunker = new FileChunker({
        file: testData,
        fileName: 'order_test.bin',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const chunks = [];
      while (chunker.hasMoreChunks()) {
        chunks.push(await chunker.nextChunk());
      }
      assert.equal(chunks.length, 3);

      // Deliver in reverse order: 2, 1, 0
      await reassembler.receiveChunk(chunks[2]);
      assert.equal(reassembler.isComplete(), false);
      await reassembler.receiveChunk(chunks[0]);
      assert.equal(reassembler.isComplete(), false);
      await reassembler.receiveChunk(chunks[1]);

      assert.equal(reassembler.isComplete(), true);
      const finalized = await reassembler.finalize();
      assert.equal(finalized.verified, true);
      assert.deepEqual(finalized.data, testData);
    });

    await t2.test('safely ignores duplicate chunks and tracks missing chunks', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new Uint8Array(120 * 1024); // 2 chunks

      const chunker = new FileChunker({
        file: testData,
        fileName: 'dup_test.bin',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const chunk0 = await chunker.nextChunk();
      const chunk1 = await chunker.nextChunk();

      await reassembler.receiveChunk(chunk0);
      const missingBeforeDup = reassembler.getMissingChunkIndices();
      assert.deepEqual(missingBeforeDup, [1]);

      // Replay chunk0 (legitimate duplicate retransmission)
      await reassembler.receiveChunk(chunk0);
      assert.deepEqual(reassembler.getMissingChunkIndices(), [1], 'Duplicate must not alter missing state');

      await reassembler.receiveChunk(chunk1);
      assert.equal(reassembler.isComplete(), true);
      const finalized = await reassembler.finalize();
      assert.equal(finalized.verified, true);
    });

    await t2.test('aborts and throws on tampered chunk payload', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new Uint8Array(64 * 1024);
      testData.fill(7);

      const chunker = new FileChunker({
        file: testData,
        fileName: 'tamper.bin',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const chunk = await chunker.nextChunk();
      // Corrupt byte in payload
      chunk[chunk.length - 5] ^= 0xff;

      await assert.rejects(
        async () => {
          await reassembler.receiveChunk(chunk);
        },
        /OperationError|Decryption failed|Authentication failed/i,
        'Corrupted chunk must trigger authentication failure'
      );
    });

    await t2.test('detects final SHA-256 mismatch if manifest is forged', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new TextEncoder().encode('Legitimate content');

      const chunker = new FileChunker({
        file: testData,
        fileName: 'integrity.txt',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      // Forge manifest hash with valid length hex
      manifest.sha256 = '0'.repeat(64);

      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const chunk = await chunker.nextChunk();
      await reassembler.receiveChunk(chunk);

      await assert.rejects(
        async () => {
          await reassembler.finalize();
        },
        /Integrity verification failed/i,
        'SHA-256 mismatch must reject file completion'
      );
    });
  });

  await t.test('WebRTC DataChannel Flow Control & Backpressure', async (t2) => {
    await t2.test('detects high water mark and waits for bufferedamountlow event', async () => {
      const listeners = {};
      const mockChannel = {
        bufferedAmount: 1500000,
        bufferedAmountLowThreshold: 0,
        readyState: 'open',
        addEventListener: (event, handler) => {
          listeners[event] = handler;
        },
        removeEventListener: (event) => {
          delete listeners[event];
        }
      };

      const fc = new FlowController({ highWaterMark: 1000000, lowWaterMark: 250000 });
      fc.configureChannel(mockChannel);
      assert.equal(mockChannel.bufferedAmountLowThreshold, 250000);
      assert.equal(fc.shouldWait(mockChannel), true);

      const waitPromise = fc.waitForDrain(mockChannel);

      setTimeout(() => {
        mockChannel.bufferedAmount = 200000;
        listeners['bufferedamountlow']?.();
      }, 20);

      await waitPromise;
      assert.equal(fc.shouldWait(mockChannel), false);
    });
  });

  await t.test('Remediation: Security, Resource Limits & Receiver Approval', async (t2) => {
    await t2.test('enforces receiver approval at the receiveChunk path', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new TextEncoder().encode('Unapproved chunk test');

      const chunker = new FileChunker({
        file: testData,
        fileName: 'unapproved.txt',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });

      const chunk = await chunker.nextChunk();

      // Receiving before approve() must be rejected
      await assert.rejects(
        async () => {
          await reassembler.receiveChunk(chunk);
        },
        /not approved by receiver|Approval required/i,
        'receiveChunk must reject chunks before explicit approval'
      );

      // After approval, receiving must succeed
      reassembler.approve();
      const res = await reassembler.receiveChunk(chunk);
      assert.equal(res.chunkIndex, 0);
    });

    await t2.test('rejects chunks with wrong fileIndex', async () => {
      const { alice, bob } = await createCryptoChannel();
      const testData = new TextEncoder().encode('File index mismatch test');

      // Chunker with fileIndex = 1
      const chunker = new FileChunker({
        file: testData,
        fileName: 'file1.txt',
        fileIndex: 1,
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker.getManifest();

      // Reassembler expecting fileIndex = 0
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const chunk = await chunker.nextChunk();

      // Chunk with fileIndex 1 must be rejected by reassembler expecting fileIndex 0
      await assert.rejects(
        async () => {
          await reassembler.receiveChunk(chunk);
        },
        /File index mismatch/i,
        'Reassembler must reject chunks with unexpected fileIndex'
      );
    });

    await t2.test('rejects conflicting duplicate chunk for already accepted chunkIndex', async () => {
      const { alice, bob } = await createCryptoChannel();

      // Two different payloads for chunk 0
      const chunker1 = new FileChunker({
        file: new TextEncoder().encode('Legitimate payload for chunk 0'),
        fileName: 'conflict.txt',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const chunker2 = new FileChunker({
        file: new TextEncoder().encode('Malicious conflicting payload for chunk 0'),
        fileName: 'conflict.txt',
        chunkSize: 64 * 1024,
        key: alice.outboundKey,
        staticIv: alice.outboundStaticIv
      });

      const manifest = await chunker1.getManifest();
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bob.inboundKey,
        staticIv: bob.inboundStaticIv
      });
      reassembler.approve();

      const legitimateChunk0 = await chunker1.nextChunk();
      const conflictingChunk0 = await chunker2.nextChunk();

      // Accept legitimate chunk
      await reassembler.receiveChunk(legitimateChunk0);

      // Conflicting duplicate chunk must be rejected
      await assert.rejects(
        async () => {
          await reassembler.receiveChunk(conflictingChunk0);
        },
        /Conflicting duplicate chunk/i,
        'Conflicting duplicate chunk must be rejected'
      );
    });

    await t2.test('rejects excessive totalChunks exceeding maximum limit', () => {
      assert.throws(
        () => {
          validateFileMetadata({
            name: 'huge.bin',
            size: 100 * 1024 * 1024 * 1024,
            chunkSize: 64 * 1024,
            totalChunks: 2000000, // Exceeds MAX_TOTAL_CHUNKS (1,000,000)
            sha256: 'a'.repeat(64)
          });
        },
        /exceeds maximum allowable chunk count/i
      );
    });

    await t2.test('rejects chunk sizes below minimum allowed limit (16KB)', () => {
      assert.throws(
        () => {
          validateFileMetadata({
            name: 'small_chunk.bin',
            size: 10000,
            chunkSize: 8192, // Below 16KB
            totalChunks: 2,
            sha256: 'a'.repeat(64)
          });
        },
        /Invalid chunk size/i
      );
    });
  });
});
