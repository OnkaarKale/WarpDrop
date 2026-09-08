import test from 'node:test';
import assert from 'node:assert/strict';

import {
  validateSessionId,
  validatePeerId,
  validateSignalingMessage,
  validateOrigin,
  RateLimiter,
  MAX_SIGNALING_MESSAGE_SIZE,
  SignalingMessageTypes
} from '../server/security.js';

test('Security Module Test Suite', async (t) => {
  await t.test('Session and Peer ID Validation', async (t2) => {
    await t2.test('validates valid session IDs and peer IDs', () => {
      // UUID v4 format or 16-32 char secure hex/alphanumeric
      assert.equal(validateSessionId('c7a4b6d8-9e1f-4a3b-8c5d-2e4f6a8b0c1d'), true);
      assert.equal(validateSessionId('session-abcdef1234567890'), true);
      assert.equal(validatePeerId('peer-1234567890abcdef'), true);
      assert.equal(validatePeerId('alice-device-1'), true);
    });

    await t2.test('rejects invalid, malicious, or empty IDs', () => {
      assert.equal(validateSessionId(''), false);
      assert.equal(validateSessionId('short'), false);
      assert.equal(validateSessionId('../../etc/passwd'), false);
      assert.equal(validateSessionId('<script>alert(1)</script>'), false);
      assert.equal(validateSessionId('a'.repeat(200)), false);

      assert.equal(validatePeerId(''), false);
      assert.equal(validatePeerId('p'), false);
      assert.equal(validatePeerId('peer;DROP TABLE;'), false);
    });
  });

  await t.test('Signaling Message Schema Validation', async (t2) => {
    await t2.test('accepts valid JOIN message', () => {
      const msg = {
        type: SignalingMessageTypes.JOIN,
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456',
        token: 'token-secret-12345678'
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, true);
    });

    await t2.test('accepts valid SDP_OFFER message with standard SDP payload', () => {
      const msg = {
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456',
        token: 'token-secret-12345678',
        payload: {
          sdp: 'v=0\r\no=- 123456 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n',
          type: 'offer'
        }
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, true);
    });

    await t2.test('accepts valid ICE_CANDIDATE message', () => {
      const msg = {
        type: SignalingMessageTypes.ICE_CANDIDATE,
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456',
        token: 'token-secret-12345678',
        payload: {
          candidate: 'candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host',
          sdpMid: '0',
          sdpMLineIndex: 0
        }
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, true);
    });

    await t2.test('rejects unknown message types', () => {
      const msg = {
        type: 'SEND_FILE_CHUNK',
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456'
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, false);
      assert.match(result.error, /Unknown message type/);
    });

    await t2.test('rejects messages missing required fields', () => {
      assert.equal(validateSignalingMessage(null).valid, false);
      assert.equal(validateSignalingMessage({}).valid, false);
      assert.equal(validateSignalingMessage({ type: 'JOIN' }).valid, false);
    });

    await t2.test('rejects file-like payloads or binary data representations', () => {
      const msg = {
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456',
        token: 'token-secret-12345678',
        payload: {
          fileBytes: 'SGVsbG8gV29ybGQ=', // base64 file data attempt
          fileName: 'confidential.pdf'
        }
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, false);
      assert.match(result.error, /file content transmission is strictly prohibited|Invalid SDP payload/);
    });

    await t2.test('rejects private key-like payloads', () => {
      const msg = {
        type: SignalingMessageTypes.SDP_OFFER,
        sessionId: 'session-1234567890abcdef',
        peerId: 'peer-alice-123456',
        token: 'token-secret-12345678',
        payload: {
          sdp: 'valid-looking-sdp',
          type: 'offer',
          privateKey: 'BEGIN PRIVATE KEY...'
        }
      };
      const result = validateSignalingMessage(msg);
      assert.equal(result.valid, false);
      assert.match(result.error, /prohibited key material/i);
    });
  });

  await t.test('Origin Validation', async (t2) => {
    await t2.test('allows localhost and local loopback origins', () => {
      assert.equal(validateOrigin('http://localhost:3000'), true);
      assert.equal(validateOrigin('http://127.0.0.1:3000'), true);
      assert.equal(validateOrigin('https://localhost:8443'), true);
    });

    await t2.test('allows private LAN IP origins', () => {
      assert.equal(validateOrigin('http://192.168.1.15:3000'), true);
      assert.equal(validateOrigin('http://10.0.0.5:3000'), true);
      assert.equal(validateOrigin('http://172.20.10.2:3000'), true);
    });

    await t2.test('allows undefined or null origin for native/mobile clients without browser origin', () => {
      assert.equal(validateOrigin(undefined), true);
      assert.equal(validateOrigin(''), true);
    });

    await t2.test('rejects untrusted external public origins', () => {
      assert.equal(validateOrigin('http://malicious-attacker.com'), false);
      assert.equal(validateOrigin('https://phishing-site.xyz:3000'), false);
      assert.equal(validateOrigin('http://8.8.8.8:3000'), false);
    });

    await t2.test('allows same-origin matching server host for public cloud deployments', () => {
      assert.equal(validateOrigin('https://warpdrop.onrender.com', 'warpdrop.onrender.com'), true);
      assert.equal(validateOrigin('https://warpdrop.onrender.com:443', 'warpdrop.onrender.com:443'), true);
      assert.equal(validateOrigin('https://malicious.com', 'warpdrop.onrender.com'), false);
    });
  });

  await t.test('Rate Limiter', async (t2) => {
    await t2.test('allows burst up to limit and rejects excess', () => {
      const limiter = new RateLimiter({ maxTokens: 5, refillRatePerSec: 1 });
      const clientKey = 'client-1';

      // 5 tokens should pass
      for (let i = 0; i < 5; i++) {
        assert.equal(limiter.tryConsume(clientKey), true, `Token ${i} should be allowed`);
      }

      // 6th token must be throttled
      assert.equal(limiter.tryConsume(clientKey), false, 'Excess token should be throttled');
    });

    await t2.test('cleans up idle client records', () => {
      const limiter = new RateLimiter({ maxTokens: 5, refillRatePerSec: 1, idleTimeoutMs: 10 });
      limiter.tryConsume('idle-client');
      assert.equal(limiter.getClientCount(), 1);

      return new Promise((resolve) => {
        setTimeout(() => {
          limiter.cleanup();
          assert.equal(limiter.getClientCount(), 0);
          resolve();
        }, 20);
      });
    });
  });
});
