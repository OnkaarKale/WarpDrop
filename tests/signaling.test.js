import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import WebSocket from 'ws';

import {
  createSignalingServer,
  SignalingServer
} from '../server/signaling.js';

import {
  SignalingMessageTypes
} from '../server/security.js';

// Helper to create a client WebSocket connection
function connectClient(port, origin = 'http://localhost:3000') {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { origin }
    });

    const messages = [];
    const closeEvents = [];
    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        messages.push({ isBinary: true, data });
      } else {
        try {
          messages.push(JSON.parse(data.toString()));
        } catch {
          messages.push({ raw: data.toString() });
        }
      }
    });

    ws.on('close', (code, reason) => {
      closeEvents.push({ code, reason: reason.toString() });
    });

    ws.on('open', () => resolve({ ws, messages, closeEvents }));
    ws.on('error', (err) => reject(err));
  });
}

// Helper to wait for a message matching a predicate
function waitForMessage(messages, predicate, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const interval = setInterval(() => {
      const found = messages.find(predicate);
      if (found) {
        clearInterval(interval);
        resolve(found);
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(interval);
        reject(new Error(`Timed out waiting for message after ${timeoutMs}ms. Messages received: ${JSON.stringify(messages)}`));
      }
    }, 10);
  });
}

test('Signaling Server Test Suite', async (t) => {
  let httpServer;
  let signalingServer;
  let port;

  t.before(async () => {
    httpServer = http.createServer();
    signalingServer = createSignalingServer({ server: httpServer });
    await new Promise((resolve) => {
      httpServer.listen(0, '127.0.0.1', () => {
        port = httpServer.address().port;
        resolve();
      });
    });
  });

  t.after(async () => {
    await signalingServer.close();
    await new Promise((resolve) => httpServer.close(resolve));
  });

  await t.test('Session Lifecycle & Capacity', async (t2) => {
    await t2.test('allows 2 peers to join a room, rejects 3rd peer', async () => {
      const { sessionId, token } = signalingServer.createSession();
      assert.ok(sessionId);
      assert.ok(token);

      // Peer 1 joins
      const client1 = await connectClient(port);
      client1.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-alice-123456',
        token
      }));

      const msg1 = await waitForMessage(client1.messages, (m) => m.type === SignalingMessageTypes.PEER_JOINED);
      assert.equal(msg1.peerId, 'peer-alice-123456');

      // Peer 2 joins
      const client2 = await connectClient(port);
      client2.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-bob-12345678',
        token
      }));

      // Peer 1 should receive notification that Peer 2 joined
      const joinedNotification = await waitForMessage(
        client1.messages,
        (m) => m.type === SignalingMessageTypes.PEER_JOINED && m.peerId === 'peer-bob-12345678'
      );
      assert.ok(joinedNotification);

      // Peer 3 attempts to join same session -> REJECTED
      const client3 = await connectClient(port);
      client3.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-charlie-9999',
        token
      }));

      const errorMsg = await waitForMessage(client3.messages, (m) => m.type === SignalingMessageTypes.ERROR);
      assert.match(errorMsg.error, /Session is full/i);

      // Cleanup
      client1.ws.close();
      client2.ws.close();
      client3.ws.close();
    });

    await t2.test('cleans up session when peers disconnect', async () => {
      const { sessionId, token } = signalingServer.createSession();
      const client1 = await connectClient(port);
      const client2 = await connectClient(port);

      client1.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-alice-dc',
        token
      }));

      client2.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-bob-dc',
        token
      }));

      await waitForMessage(client1.messages, (m) => m.type === SignalingMessageTypes.PEER_JOINED && m.peerId === 'peer-bob-dc');

      // Client 2 disconnects
      client2.ws.close();

      // Client 1 should receive PEER_LEFT
      const leftMsg = await waitForMessage(client1.messages, (m) => m.type === SignalingMessageTypes.PEER_LEFT);
      assert.equal(leftMsg.peerId, 'peer-bob-dc');

      // Client 1 disconnects -> session room should be purged
      client1.ws.close();

      await new Promise((r) => setTimeout(r, 50));
      assert.equal(signalingServer.hasSession(sessionId), false, 'Empty session room must be purged from memory');
    });

    await t2.test('rejects joining with invalid token or nonexistent session', async () => {
      const client = await connectClient(port);
      client.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId: 'session-nonexistent-123',
        peerId: 'peer-hacker',
        token: 'invalid-token'
      }));

      const err = await waitForMessage(client.messages, (m) => m.type === SignalingMessageTypes.ERROR);
      assert.match(err.error, /Session not found|Invalid session/i);
      client.ws.close();
    });
  });

  await t.test('WebRTC Signaling Message Forwarding', async (t2) => {
    await t2.test('routes SDP offer, SDP answer, and ICE candidates between peers', async () => {
      const { sessionId, token } = signalingServer.createSession();
      const alice = await connectClient(port);
      const bob = await connectClient(port);

      alice.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-alice-rtc',
        token
      }));

      bob.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-bob-rtc',
        token
      }));

      await waitForMessage(alice.messages, (m) => m.type === SignalingMessageTypes.PEER_JOINED && m.peerId === 'peer-bob-rtc');

      // Alice sends SDP offer
      const offerPayload = { sdp: 'v=0\r\no=alice 1 1 IN IP4 127.0.0.1\r\n', type: 'offer' };
      alice.ws.send(JSON.stringify({
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId,
        peerId: 'peer-alice-rtc',
        token,
        payload: offerPayload
      }));

      const receivedOffer = await waitForMessage(bob.messages, (m) => m.type === SignalingMessageTypes.SDP_OFFER);
      assert.deepEqual(receivedOffer.payload, offerPayload);
      assert.equal(receivedOffer.peerId, 'peer-alice-rtc');

      // Bob sends SDP answer
      const answerPayload = { sdp: 'v=0\r\no=bob 2 2 IN IP4 127.0.0.1\r\n', type: 'answer' };
      bob.ws.send(JSON.stringify({
        type: SignalingMessageTypes.SDP_ANSWER,
        sessionId,
        peerId: 'peer-bob-rtc',
        token,
        payload: answerPayload
      }));

      const receivedAnswer = await waitForMessage(alice.messages, (m) => m.type === SignalingMessageTypes.SDP_ANSWER);
      assert.deepEqual(receivedAnswer.payload, answerPayload);

      // Alice sends ICE candidate
      const candidatePayload = { candidate: 'candidate:1 1 UDP 1 127.0.0.1 5000 typ host', sdpMid: '0', sdpMLineIndex: 0 };
      alice.ws.send(JSON.stringify({
        type: SignalingMessageTypes.ICE_CANDIDATE,
        sessionId,
        peerId: 'peer-alice-rtc',
        token,
        payload: candidatePayload
      }));

      const receivedCandidate = await waitForMessage(bob.messages, (m) => m.type === SignalingMessageTypes.ICE_CANDIDATE);
      assert.deepEqual(receivedCandidate.payload, candidatePayload);

      alice.ws.close();
      bob.ws.close();
    });
  });

  await t.test('Security: File Content & Binary Frame Rejection', async (t2) => {
    await t2.test('strictly rejects binary frames such as CHUNK frames on signaling server', async () => {
      const client = await connectClient(port);

      // Send binary frame (Phase 3 CHUNK frame with magic 0x50 0x32)
      const binaryChunkFrame = new Uint8Array([0x50, 0x32, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);
      client.ws.send(binaryChunkFrame);

      const errorMsg = await waitForMessage(client.messages, (m) => m.type === SignalingMessageTypes.ERROR);
      assert.match(errorMsg.error, /Binary data is strictly prohibited|Signaling channel cannot transfer files/i);

      client.ws.close();
    });

    await t2.test('rejects oversized JSON message exceeding maximum signaling limit', async () => {
      const client = await connectClient(port);
      const hugeString = 'x'.repeat(70 * 1024); // 70 KB exceeds 64 KB limit

      const closePromise = new Promise((resolve) => {
        client.ws.on('close', (code, reason) => {
          resolve({ code, reason: reason.toString() });
        });
      });

      client.ws.send(JSON.stringify({
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId: 'session-test',
        peerId: 'peer-1',
        token: 'token-12345678',
        payload: { sdp: hugeString, type: 'offer' }
      }));

      const closeInfo = await closePromise;
      assert.equal(closeInfo.code, 1009, 'WebSocket should close with code 1009 (Message Too Big)');
    });
  });

  await t.test('Connection-State & Identity Binding', async (t2) => {
    await t2.test('rejects SDP offer if socket has not joined or peer identity mismatches', async () => {
      const { sessionId, token } = signalingServer.createSession();
      const client = await connectClient(port);

      // Attempt to send SDP offer without having joined first
      client.ws.send(JSON.stringify({
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId,
        peerId: 'peer-impostor',
        token,
        payload: { sdp: 'v=0\r\n', type: 'offer' }
      }));

      const errorMsg = await waitForMessage(client.messages, (m) => m.type === SignalingMessageTypes.ERROR);
      assert.match(errorMsg.error, /Unauthorized: peer identity mismatch or not joined/i);

      client.ws.close();
    });
  });

  await t.test('Signaling Keepalive & Heartbeat', async (t2) => {
    await t2.test('responds with PONG to client PING keepalive message', async () => {
      const { sessionId, token } = signalingServer.createSession();
      const client = await connectClient(port);

      // Join session
      client.ws.send(JSON.stringify({
        type: SignalingMessageTypes.JOIN,
        sessionId,
        peerId: 'peer-ping-tester',
        token
      }));

      // Send PING
      client.ws.send(JSON.stringify({
        type: SignalingMessageTypes.PING,
        sessionId,
        peerId: 'peer-ping-tester',
        token
      }));

      const pongMsg = await waitForMessage(client.messages, (m) => m.type === SignalingMessageTypes.PONG);
      assert.equal(pongMsg.type, SignalingMessageTypes.PONG);
      assert.equal(pongMsg.sessionId, sessionId);

      client.ws.close();
    });
  });
});
