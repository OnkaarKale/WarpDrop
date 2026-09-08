/**
 * WebRTC DataChannel P2P Transport Test Suite.
 *
 * Tests the WebRTC transport abstraction, candidate queueing,
 * state machine, backpressure flow control, and integration with Phase 3/4.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import EventEmitter from 'node:events';

import {
  WebRTCConnection,
  WebRTCStates,
  MAX_TRANSPORT_FRAME_SIZE
} from '../src/transport/webrtcConnection.js';

import {
  WebRTCPeerTransport
} from '../src/transport/webrtcPeer.js';

import {
  FlowController,
  DEFAULT_HIGH_WATER_MARK,
  DEFAULT_LOW_WATER_MARK
} from '../src/transport/flowControl.js';

import {
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_CONTROL,
  ControlActions,
  MAX_CHUNK_SIZE
} from '../src/protocol/types.js';

import {
  generateSessionKeyPair,
  exportPublicKey,
  deriveSharedSecretBits,
  importPeerPublicKey
} from '../src/crypto/keyExchange.js';

import {
  deriveSessionKeys
} from '../src/crypto/kdf.js';

import {
  FileReassembler,
  MemoryChunkSink
} from '../src/protocol/reassembler.js';

import {
  FileChunker
} from '../src/protocol/chunker.js';

import {
  createStreamingHash
} from '../src/crypto/hash.js';

// --- Emulated WebRTC Primitives for Headless Node Environment ---

class MockRTCDataChannel extends EventEmitter {
  constructor(label = 'file-transfer', options = {}) {
    super();
    this.label = label;
    this.ordered = options.ordered ?? true;
    this.maxRetransmits = options.maxRetransmits;
    this.maxPacketLifeTime = options.maxPacketLifeTime;
    this.readyState = 'connecting';
    this.binaryType = 'blob';
    this.bufferedAmount = 0;
    this.bufferedAmountLowThreshold = 0;
    this.remotePeerChannel = null;
  }

  send(data) {
    if (this.readyState !== 'open') {
      throw new Error(`InvalidStateError: RTCDataChannel readyState is '${this.readyState}'`);
    }

    let payload;
    if (typeof data === 'string') {
      payload = data;
    } else if (data instanceof Uint8Array) {
      payload = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    } else if (data instanceof ArrayBuffer) {
      payload = data.slice(0);
    } else {
      payload = data;
    }

    if (this.remotePeerChannel && this.remotePeerChannel.readyState === 'open') {
      queueMicrotask(() => {
        if (this.remotePeerChannel && this.remotePeerChannel.readyState === 'open') {
          this.remotePeerChannel.emit('message', { data: payload });
        }
      });
    }
  }

  simulateOpen() {
    this.readyState = 'open';
    this.emit('open');
  }

  simulateClose() {
    this.readyState = 'closed';
    this.emit('close');
  }

  simulateError(error = new Error('DataChannel error')) {
    this.emit('error', error);
  }

  close() {
    if (this.readyState !== 'closed') {
      this.readyState = 'closed';
      this.emit('close');
    }
  }

  addEventListener(event, fn) {
    this.on(event, fn);
  }

  removeEventListener(event, fn) {
    this.removeListener(event, fn);
  }
}

class MockRTCPeerConnection extends EventEmitter {
  constructor(config = {}) {
    super();
    this.config = config;
    this.connectionState = 'new';
    this.iceConnectionState = 'new';
    this.iceGatheringState = 'new';
    this.signalingState = 'stable';
    this.localDescription = null;
    this.remoteDescription = null;
    this.dataChannels = [];
    this.remotePeerConnection = null;
  }

  createDataChannel(label, options) {
    const channel = new MockRTCDataChannel(label, options);
    this.dataChannels.push(channel);
    return channel;
  }

  async createOffer() {
    return {
      type: 'offer',
      sdp: 'v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 DTLS/SCTP 5000\r\n'
    };
  }

  async createAnswer() {
    return {
      type: 'answer',
      sdp: 'v=0\r\no=- 654321 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 DTLS/SCTP 5000\r\n'
    };
  }

  async setLocalDescription(desc) {
    this.localDescription = desc;
    this.signalingState = desc.type === 'offer' ? 'have-local-offer' : 'stable';
    this.emit('signalingstatechange');
  }

  async setRemoteDescription(desc) {
    this.remoteDescription = desc;
    this.signalingState = desc.type === 'offer' ? 'have-remote-offer' : 'stable';
    this.emit('signalingstatechange');
  }

  async addIceCandidate(candidate) {
    if (!this.remoteDescription) {
      throw new Error('InvalidStateError: Remote description must be set before adding ICE candidate');
    }
    if (this.connectionState === 'closed') {
      throw new Error('InvalidStateError: Cannot add ICE candidate on closed connection');
    }
    return Promise.resolve();
  }

  close() {
    this.connectionState = 'closed';
    this.iceConnectionState = 'closed';
    this.signalingState = 'closed';
    for (const ch of this.dataChannels) {
      ch.close();
    }
    this.emit('connectionstatechange');
    this.emit('iceconnectionstatechange');
    this.emit('signalingstatechange');
  }
}

test('WebRTC DataChannel P2P Transport Test Suite', async (t) => {

  await t.test('Connection & Negotiation Lifecycle', async (t2) => {
    await t2.test('initializes in NEW state with correct defaults', () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });
      assert.equal(conn.getState(), WebRTCStates.NEW);
      assert.equal(conn.isOpen(), false);
      conn.close();
    });

    await t2.test('creates reliable ordered DataChannel as initiator', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });

      const channel = conn.initDataChannel();
      assert.ok(channel);
      assert.equal(channel.ordered, true, 'DataChannel must be ordered');
      assert.equal(channel.maxRetransmits, undefined, 'Must not be partially reliable');
      assert.equal(channel.binaryType, 'arraybuffer', 'Must be binary mode');
      conn.close();
    });

    await t2.test('creates SDP offer as initiator', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });

      const offer = await conn.createOffer();
      assert.equal(offer.type, 'offer');
      assert.ok(typeof offer.sdp === 'string');
      conn.close();
    });

    await t2.test('creates SDP answer after remote description as responder', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      const offer = { type: 'offer', sdp: 'v=0\r\no=...' };
      await conn.setRemoteDescription(offer);
      const answer = await conn.createAnswer();
      assert.equal(answer.type, 'answer');
      assert.ok(typeof answer.sdp === 'string');
      conn.close();
    });

    await t2.test('queues ICE candidates arriving before remote description and flushes them afterward', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      const candidate1 = { candidate: 'candidate:1 1 UDP 2130706431 192.168.1.100 50000 typ host', sdpMid: '0', sdpMLineIndex: 0 };
      const candidate2 = { candidate: 'candidate:2 1 UDP 2130706431 192.168.1.101 50001 typ host', sdpMid: '0', sdpMLineIndex: 0 };

      // Add candidates BEFORE remote description
      await conn.addIceCandidate(candidate1);
      await conn.addIceCandidate(candidate2);

      assert.equal(conn.getQueuedCandidateCount(), 2, 'Candidates must be queued before remoteDescription');

      // Now set remote description
      const offer = { type: 'offer', sdp: 'v=0\r\no=...' };
      await conn.setRemoteDescription(offer);

      assert.equal(conn.getQueuedCandidateCount(), 0, 'Candidate queue must be flushed after remoteDescription is set');
      conn.close();
    });

    await t2.test('rejects malformed ICE candidate structures', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });

      await assert.rejects(
        async () => conn.addIceCandidate('not-an-object'),
        /Invalid ICE candidate/i
      );

      await assert.rejects(
        async () => conn.addIceCandidate({ foo: 'bar' }),
        /Invalid ICE candidate/i
      );
      conn.close();
    });

    await t2.test('safely ignores duplicate ICE candidates', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });

      const candidate = { candidate: 'candidate:dup 1 UDP 2130706431 192.168.1.100 50000 typ host', sdpMid: '0', sdpMLineIndex: 0 };
      await conn.addIceCandidate(candidate);
      await conn.addIceCandidate(candidate); // Duplicate

      assert.equal(conn.getQueuedCandidateCount(), 1, 'Duplicate candidate must not be queued twice');
      conn.close();
    });

    await t2.test('handles incoming DataChannel on responder', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      const rawChannel = new MockRTCDataChannel('file-transfer');
      let openFired = false;
      conn.on('open', () => { openFired = true; });

      // Simulate browser firing ondatachannel
      conn.pc.emit('datachannel', { channel: rawChannel });
      assert.equal(rawChannel.binaryType, 'arraybuffer', 'Responder must set binaryType to arraybuffer');

      rawChannel.simulateOpen();
      assert.equal(openFired, true);
      assert.equal(conn.getState(), WebRTCStates.CONNECTED);
      conn.close();
    });
  });

  await t.test('Security & Message Boundaries', async (t2) => {
    await t2.test('rejects sending data before DataChannel is open', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });
      conn.initDataChannel();

      const frame = new Uint8Array([0x50, 0x32, 0x01, 0x00]);
      await assert.rejects(
        async () => conn.send(frame),
        /DataChannel is not open/i
      );
      conn.close();
    });

    await t2.test('rejects unexpected text messages on DataChannel', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });
      const channel = conn.initDataChannel();
      channel.simulateOpen();

      let errorFired = null;
      conn.on('error', (err) => { errorFired = err; });

      // Emit unexpected text message
      channel.emit('message', { data: 'Unexpected string message' });

      assert.ok(errorFired, 'Must trigger error event on text message');
      assert.match(errorFired.message, /Unexpected non-binary DataChannel message/i);
      conn.close();
    });

    await t2.test('rejects oversized frames exceeding MAX_TRANSPORT_FRAME_SIZE', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });
      const channel = conn.initDataChannel();
      channel.simulateOpen();

      const oversized = new Uint8Array(MAX_TRANSPORT_FRAME_SIZE + 1024);
      await assert.rejects(
        async () => conn.send(oversized),
        /Frame exceeds maximum allowed WebRTC transport size/i
      );
      conn.close();
    });

    await t2.test('rejects arbitrary non-binary objects in send()', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });
      const channel = conn.initDataChannel();
      channel.simulateOpen();

      await assert.rejects(
        async () => conn.send({ file: 'data.txt', content: 'hello' }),
        /Payload must be a Uint8Array or ArrayBuffer/i
      );
      conn.close();
    });
  });

  await t.test('Flow Control & Backpressure', async (t2) => {
    await t2.test('pauses sending when bufferedAmount exceeds high water mark and resumes on drain', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true,
        highWaterMark: 1024,
        lowWaterMark: 256
      });
      const channel = conn.initDataChannel();
      channel.simulateOpen();

      // Simulate high buffer
      channel.bufferedAmount = 1024;

      let sendFinished = false;
      const sendPromise = conn.send(new Uint8Array(100)).then(() => {
        sendFinished = true;
      });

      // Assert that send is paused waiting for drain
      await new Promise((r) => setTimeout(r, 10));
      assert.equal(sendFinished, false, 'Send must pause when bufferedAmount >= highWaterMark');

      // Now simulate drain event
      channel.bufferedAmount = 200;
      channel.emit('bufferedamountlow');

      await sendPromise;
      assert.equal(sendFinished, true, 'Send must resume after drain');
      conn.close();
    });

    await t2.test('aborts pending flow-control wait cleanly on connection close', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true,
        highWaterMark: 500,
        lowWaterMark: 100
      });
      const channel = conn.initDataChannel();
      channel.simulateOpen();
      channel.bufferedAmount = 600;

      const sendPromise = conn.send(new Uint8Array(50));

      // Close while waiting
      conn.close();

      await assert.rejects(
        async () => sendPromise,
        /closed|aborted/i
      );
    });
  });

  await t.test('Failure & Teardown Handling', async (t2) => {
    await t2.test('transitions to FAILED on RTCPeerConnection failure', () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });

      let stateChanged = null;
      conn.on('stateChange', (st) => { stateChanged = st; });

      conn.pc.connectionState = 'failed';
      conn.pc.emit('connectionstatechange');

      assert.equal(conn.getState(), WebRTCStates.FAILED);
      assert.equal(stateChanged, WebRTCStates.FAILED);
      conn.close();
    });

    await t2.test('handles ICE connection failure', () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });

      conn.pc.iceConnectionState = 'failed';
      conn.pc.emit('iceconnectionstatechange');

      assert.equal(conn.getState(), WebRTCStates.FAILED);
      conn.close();
    });

    await t2.test('closes all resources and can be called idempotently', () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });
      conn.initDataChannel();

      conn.close();
      assert.equal(conn.getState(), WebRTCStates.CLOSED);
      // Safe to call again
      conn.close();
      assert.equal(conn.getState(), WebRTCStates.CLOSED);
    });
  });

  await t.test('End-to-End P2P Transport & Protocol Integration', async (t2) => {
    await t2.test('initiator and responder exchange Phase 3 encrypted chunk over WebRTC DataChannel', async () => {
      // 1. Setup Phase 2 crypto context
      const aliceKeyPair = await generateSessionKeyPair();
      const bobKeyPair = await generateSessionKeyPair();
      const alicePubRaw = await exportPublicKey(aliceKeyPair.publicKey);
      const bobPubRaw = await exportPublicKey(bobKeyPair.publicKey);

      const aliceSharedSecret = await deriveSharedSecretBits(aliceKeyPair.privateKey, await importPeerPublicKey(bobPubRaw));
      const bobSharedSecret = await deriveSharedSecretBits(bobKeyPair.privateKey, await importPeerPublicKey(alicePubRaw));

      const aliceKeys = await deriveSessionKeys({
        sharedSecretBits: aliceSharedSecret,
        sessionId: 'session-test-123',
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: true
      });

      const bobKeys = await deriveSessionKeys({
        sharedSecretBits: bobSharedSecret,
        sessionId: 'session-test-123',
        initiatorPubKey: alicePubRaw,
        responderPubKey: bobPubRaw,
        isInitiator: false
      });

      // 2. Setup mock WebRTC connections
      const aliceConn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: true
      });

      const bobConn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      // Link mock channels
      const aliceChannel = aliceConn.initDataChannel();
      const bobRawChannel = new MockRTCDataChannel('file-transfer');

      aliceChannel.remotePeerChannel = bobRawChannel;
      bobRawChannel.remotePeerChannel = aliceChannel;

      // Responder receives data channel
      bobConn.pc.emit('datachannel', { channel: bobRawChannel });

      // Both open
      aliceChannel.simulateOpen();
      bobRawChannel.simulateOpen();

      assert.equal(aliceConn.isOpen(), true);
      assert.equal(bobConn.isOpen(), true);

      // 3. Setup Sender FileChunker
      const plaintextChunk = new TextEncoder().encode('Hello, this is confidential data over WebRTC DataChannel!');
      const chunker = new FileChunker({
        file: plaintextChunk,
        fileName: 'confidential.txt',
        chunkSize: MAX_CHUNK_SIZE,
        fileIndex: 0,
        key: aliceKeys.outboundKey,
        staticIv: aliceKeys.outboundStaticIv
      });
      const manifest = await chunker.getManifest();

      // 4. Setup Receiver FileReassembler
      const sink = new MemoryChunkSink(1, plaintextChunk.byteLength);
      const reassembler = new FileReassembler({
        manifest,
        fileIndex: 0,
        key: bobKeys.inboundKey,
        staticIv: bobKeys.inboundStaticIv,
        sink
      });

      // Wire bobConn incoming frames to reassembler
      const receivedFrames = [];
      bobConn.on('frame', (data) => {
        receivedFrames.push(data);
      });

      // 5. Send Chunk Frame over WebRTC DataChannel
      const chunkFrame = await chunker.nextChunk();
      await aliceConn.send(chunkFrame);

      // Wait for frame delivery over mock channel
      await new Promise((resolve) => {
        const interval = setInterval(() => {
          if (receivedFrames.length > 0) {
            clearInterval(interval);
            resolve();
          }
        }, 10);
      });

      assert.equal(receivedFrames.length, 1);

      // 6. Enforce Receiver Approval Gate (Phase 3 requirement)
      // Unapproved chunk should be rejected
      await assert.rejects(
        async () => reassembler.receiveChunk(receivedFrames[0]),
        /Transfer not approved/i
      );

      // Explicit user approval
      reassembler.approve();

      // Now approved chunk is accepted and decrypted
      const result = await reassembler.receiveChunk(receivedFrames[0]);
      assert.equal(result.chunkIndex, 0);
      assert.equal(result.isComplete, true);

      const written = await sink.readChunk(0);
      assert.deepEqual(written, plaintextChunk);

      // Verify whole-file SHA-256 integrity
      const finalResult = await reassembler.finalize();
      assert.equal(finalResult.verified, true);
      assert.deepEqual(finalResult.data, plaintextChunk);

      aliceConn.close();
      bobConn.close();
    });

    await t2.test('rejects corrupted or malformed protocol frames received on DataChannel', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      const rawChannel = new MockRTCDataChannel('file-transfer');
      conn.pc.emit('datachannel', { channel: rawChannel });
      rawChannel.simulateOpen();

      const receivedErrors = [];
      conn.on('error', (err) => receivedErrors.push(err));

      // Emit 18 bytes with corrupted magic bytes
      const corruptedBytes = new Uint8Array([
        0x99, 0x88, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
      ]);
      let frameReceived = null;
      conn.on('frame', (f) => { frameReceived = f; });
      rawChannel.emit('message', { data: corruptedBytes.buffer });

      assert.ok(frameReceived);
      // Verify that parsing fails when Phase 3 unpackChunkFrame processes it
      const { unpackChunkFrame } = await import('../src/protocol/frames.js');
      assert.throws(() => unpackChunkFrame(frameReceived), /Invalid frame magic/i);

      conn.close();
    });
  });

  await t.test('WebRTCPeerTransport Signaling Integration & Zero-Knowledge Boundary', async (t2) => {
    await t2.test('orchestrates SDP/ICE signaling without leaking secrets or file contents', async () => {
      // Mock signaling message recorder
      const recordedSignalingMessages = [];

      class MockSignalingSocket extends EventEmitter {
        constructor() {
          super();
          this.readyState = 1; // OPEN
          this.peerSocket = null;
        }

        send(msgStr) {
          const parsed = JSON.parse(msgStr);
          recordedSignalingMessages.push(parsed);

          // Route to other peer
          if (this.peerSocket) {
            queueMicrotask(() => {
              this.peerSocket.emit('message', msgStr);
            });
          }
        }

        close() {
          this.readyState = 3;
          this.emit('close', { code: 1000, reason: 'Closed' });
        }
      }

      const socketAlice = new MockSignalingSocket();
      const socketBob = new MockSignalingSocket();
      socketAlice.peerSocket = socketBob;
      socketBob.peerSocket = socketAlice;

      const aliceTransport = new WebRTCPeerTransport({
        role: 'initiator',
        sessionId: 'session-xyz-123456',
        peerId: 'peer-alice-123456',
        token: 'token-abc-123456',
        ws: socketAlice,
        RTCPeerConnection: MockRTCPeerConnection
      });

      const bobTransport = new WebRTCPeerTransport({
        role: 'responder',
        sessionId: 'session-xyz-123456',
        peerId: 'peer-bob-654321',
        token: 'token-abc-123456',
        ws: socketBob,
        RTCPeerConnection: MockRTCPeerConnection
      });

      await aliceTransport.connect();
      await bobTransport.connect();

      // Alice sends JOIN, Bob sends JOIN
      assert.ok(recordedSignalingMessages.some((m) => m.type === 'JOIN' && m.peerId === 'peer-alice-123456'));
      assert.ok(recordedSignalingMessages.some((m) => m.type === 'JOIN' && m.peerId === 'peer-bob-654321'));

      // Simulate signaling server notifying Alice that Bob joined
      socketAlice.emit('message', JSON.stringify({
        type: 'PEER_JOINED',
        sessionId: 'session-xyz-123456',
        peerId: 'peer-bob-654321'
      }));

      // Wait for Alice to create and send SDP offer
      await new Promise((resolve) => setTimeout(resolve, 20));

      const offerMsg = recordedSignalingMessages.find((m) => m.type === 'SDP_OFFER');
      assert.ok(offerMsg, 'Alice must send SDP offer through signaling');
      assert.equal(offerMsg.targetPeerId, 'peer-bob-654321');

      // Verify ZERO secrets in all signaling messages
      for (const msg of recordedSignalingMessages) {
        const str = JSON.stringify(msg).toLowerCase();
        assert.ok(!str.includes('privatekey'), 'Signaling must never contain privateKey');
        assert.ok(!str.includes('aes-gcm'), 'Signaling must never contain AES key material');
        assert.ok(!str.includes('chunkdata'), 'Signaling must never contain chunk payload');
        assert.ok(!str.includes('filecontent'), 'Signaling must never contain file content');
      }

      aliceTransport.close();
      bobTransport.close();
    });

    await t2.test('handles peer disconnect and signaling close cleanly', async () => {
      class MockSimpleSocket extends EventEmitter {
        constructor() {
          super();
          this.readyState = 1;
        }
        send() {}
        close() { this.readyState = 3; this.emit('close'); }
      }

      const socket = new MockSimpleSocket();
      const transport = new WebRTCPeerTransport({
        role: 'initiator',
        sessionId: 'session-test-close',
        peerId: 'peer-close-1',
        token: 'token-close-1',
        ws: socket,
        RTCPeerConnection: MockRTCPeerConnection
      });

      await transport.connect();

      let peerLeftFired = false;
      transport.on('peerLeft', () => { peerLeftFired = true; });

      // Simulate PEER_LEFT
      socket.emit('message', JSON.stringify({
        type: 'PEER_LEFT',
        peerId: 'peer-remote'
      }));

      assert.equal(peerLeftFired, true);
      assert.equal(transport.closed, true);
    });

    await t2.test('rejects signaling messages with mismatched peerId once target peer is bound', async () => {
      class MockSimpleSocket extends EventEmitter {
        constructor() {
          super();
          this.readyState = 1;
        }
        send() {}
        close() { this.readyState = 3; this.emit('close'); }
      }

      const socket = new MockSimpleSocket();
      const transport = new WebRTCPeerTransport({
        role: 'initiator',
        sessionId: 'session-bound-test',
        peerId: 'peer-alice',
        targetPeerId: 'peer-bob',
        token: 'token-test',
        ws: socket,
        RTCPeerConnection: MockRTCPeerConnection
      });

      await transport.connect();

      let errorEmitted = null;
      transport.on('error', (err) => { errorEmitted = err; });

      // Attacker attempts to inject SDP_OFFER using a different peerId
      socket.emit('message', JSON.stringify({
        type: 'SDP_OFFER',
        peerId: 'peer-attacker',
        payload: { sdp: 'v=0...', type: 'offer' }
      }));

      assert.ok(errorEmitted);
      assert.match(errorEmitted.message, /Unauthorized signaling message: missing or mismatched sender peerId 'peer-attacker' does not match bound peer 'peer-bob'/i);

      // Attacker attempts to bypass check by omitting peerId entirely
      errorEmitted = null;
      socket.emit('message', JSON.stringify({
        type: 'ICE_CANDIDATE',
        payload: { candidate: 'candidate:rogue', sdpMid: '0', sdpMLineIndex: 0 }
      }));

      assert.ok(errorEmitted);
      assert.match(errorEmitted.message, /Unauthorized signaling message: missing or mismatched sender peerId 'undefined' does not match bound peer 'peer-bob'/i);
    });
  });

  await t.test('Remediation: Security Limits & Candidate Bounding', async (t2) => {
    await t2.test('drops incoming DataChannel frames exceeding MAX_TRANSPORT_FRAME_SIZE with error', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection,
        isInitiator: false
      });

      const rawChannel = new MockRTCDataChannel('file-transfer');
      conn.pc.emit('datachannel', { channel: rawChannel });
      rawChannel.simulateOpen();

      let errorFired = null;
      conn.on('error', (err) => { errorFired = err; });

      let frameFired = false;
      conn.on('frame', () => { frameFired = true; });

      // Create an oversized ArrayBuffer
      const oversizedBuffer = new ArrayBuffer(MAX_TRANSPORT_FRAME_SIZE + 1024);
      rawChannel.emit('message', { data: oversizedBuffer });

      assert.equal(frameFired, false, 'Oversized frame must NOT be emitted as a frame');
      assert.ok(errorFired, 'Error must be emitted for oversized frame');
      assert.match(errorFired.message, /Incoming DataChannel frame exceeds maximum allowed size/i);

      conn.close();
    });

    await t2.test('enforces MAX_ICE_CANDIDATES limit to prevent memory exhaustion', async () => {
      const conn = new WebRTCConnection({
        RTCPeerConnection: MockRTCPeerConnection
      });

      const { MAX_ICE_CANDIDATES } = await import('../src/transport/webrtcConnection.js');
      assert.equal(typeof MAX_ICE_CANDIDATES, 'number');

      // Add up to MAX_ICE_CANDIDATES candidates
      for (let i = 0; i < MAX_ICE_CANDIDATES; i++) {
        await conn.addIceCandidate({
          candidate: `candidate:${i} 1 UDP 2130706431 192.168.1.${i % 250} 50000 typ host`,
          sdpMid: '0',
          sdpMLineIndex: 0
        });
      }

      // The (MAX_ICE_CANDIDATES + 1)th candidate must be rejected
      await assert.rejects(
        async () => conn.addIceCandidate({
          candidate: 'candidate:overflow 1 UDP 2130706431 192.168.1.254 50000 typ host',
          sdpMid: '0',
          sdpMLineIndex: 0
        }),
        /ICE candidate limit exceeded/i
      );

      conn.close();
    });
  });

  await t.test('Two-Way Download Handshake & Keepalive', async (t2) => {
    await t2.test('ControlActions includes DOWNLOAD_ACK action', () => {
      assert.equal(ControlActions.DOWNLOAD_ACK, 'DOWNLOAD_ACK');
    });

    await t2.test('WebRTCPeerTransport handles PONG message without error', async () => {
      class MockSimpleSocket extends EventEmitter {
        constructor() {
          super();
          this.readyState = 1;
        }
        send() {}
        close() { this.readyState = 3; this.emit('close'); }
      }

      const socket = new MockSimpleSocket();
      const transport = new WebRTCPeerTransport({
        isInitiator: true,
        sessionId: 'session-keepalive-test',
        token: 'token-keepalive',
        peerId: 'peer-alice',
        ws: socket,
        RTCPeerConnection: MockRTCPeerConnection
      });

      let errorFired = false;
      transport.on('error', () => { errorFired = true; });

      await transport.connect();

      // Emit PONG message from signaling server
      socket.emit('message', JSON.stringify({
        type: 'PONG',
        sessionId: 'session-keepalive-test'
      }));

      assert.equal(errorFired, false, 'PONG must not trigger error in WebRTCPeerTransport');
      assert.equal(transport.closed, false, 'Transport must remain open after PONG');

      transport.close();
    });
  });
});
