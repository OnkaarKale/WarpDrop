import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getLocalIpAddresses,
  createQRPayload,
  validateQRPayload,
  generatePairingQR,
  QR_VERSION
} from '../server/discovery.js';

test('Discovery & QR Pairing Test Suite', async (t) => {
  await t.test('Local IP Address Discovery', async (t2) => {
    await t2.test('discovers local IPv4 addresses and filters out internal loopback by default', () => {
      const addresses = getLocalIpAddresses({ includeLoopback: false });
      assert.ok(Array.isArray(addresses), 'Must return an array of interfaces');

      for (const iface of addresses) {
        assert.equal(iface.family, 'IPv4', 'Should return IPv4 addresses');
        assert.notEqual(iface.address, '127.0.0.1', 'Should not contain loopback when includeLoopback=false');
        assert.ok(!iface.internal, 'Should not contain internal interfaces');
      }
    });

    await t2.test('includes loopback when explicitly requested', () => {
      const addresses = getLocalIpAddresses({ includeLoopback: true });
      assert.ok(addresses.some((iface) => iface.address === '127.0.0.1'), 'Should contain 127.0.0.1');
    });

    await t2.test('handles custom interface mock correctly without crashing', () => {
      const mockInterfaces = {
        lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }],
        eth0: [
          { address: '192.168.1.105', family: 'IPv4', internal: false },
          { address: 'fe80::1', family: 'IPv6', internal: false }
        ],
        docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false }]
      };

      const discovered = getLocalIpAddresses({ interfaces: mockInterfaces, includeLoopback: false });
      assert.equal(discovered.length, 2);
      assert.equal(discovered[0].address, '192.168.1.105');
      assert.equal(discovered[1].address, '172.17.0.1');
    });

    await t2.test('handles machine with no external LAN interfaces gracefully', () => {
      const mockEmpty = {
        lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }]
      };
      const discovered = getLocalIpAddresses({ interfaces: mockEmpty, includeLoopback: false });
      assert.equal(discovered.length, 0, 'Should return empty array when no external interfaces');
    });
  });

  await t.test('QR Pairing Payload Validation & Generation', async (t2) => {
    await t2.test('creates valid minimal QR payload', () => {
      const payload = createQRPayload({
        host: '192.168.1.50',
        port: 3000,
        sessionId: 'session-1234567890abcdef',
        token: 'token-secret-12345678'
      });

      assert.equal(payload.v, QR_VERSION);
      assert.equal(payload.h, '192.168.1.50');
      assert.equal(payload.p, 3000);
      assert.equal(payload.s, 'session-1234567890abcdef');
      assert.equal(payload.t, 'token-secret-12345678');

      // Verify validation passes
      const validated = validateQRPayload(payload);
      assert.equal(validated.valid, true);
    });

    await t2.test('rejects QR payload with missing or invalid fields', () => {
      assert.equal(validateQRPayload(null).valid, false);
      assert.equal(validateQRPayload({}).valid, false);

      // Invalid port
      assert.equal(validateQRPayload({ v: 1, h: 'localhost', p: -1, s: 'session-1234567890', t: 'token' }).valid, false);
      assert.equal(validateQRPayload({ v: 1, h: 'localhost', p: 70000, s: 'session-1234567890', t: 'token' }).valid, false);

      // Dangerous or malicious host
      assert.equal(validateQRPayload({ v: 1, h: 'evil.com;rm -rf', p: 3000, s: 'session-1234567890', t: 'token' }).valid, false);
    });

    await t2.test('strictly verifies QR payload does NOT contain secrets or file data', () => {
      const payload = createQRPayload({
        host: '192.168.1.50',
        port: 3000,
        sessionId: 'session-1234567890abcdef',
        token: 'token-secret-12345678'
      });

      const json = JSON.stringify(payload);

      // Must not contain crypto key markers or file contents
      assert.equal(json.includes('privateKey'), false);
      assert.equal(json.includes('aesKey'), false);
      assert.equal(json.includes('fileData'), false);
      assert.equal(json.includes('chunk'), false);
      assert.ok(json.length < 512, 'QR payload should be compact');
    });

    await t2.test('generates QR code data URL and string using qrcode library', async () => {
      const payload = createQRPayload({
        host: '192.168.1.50',
        port: 3000,
        sessionId: 'session-1234567890abcdef',
        token: 'token-secret-12345678'
      });

      const qrDataUrl = await generatePairingQR(payload, { format: 'dataUrl' });
      assert.ok(qrDataUrl.startsWith('data:image/png;base64,'), 'Should generate PNG data URL');

      const qrAscii = await generatePairingQR(payload, { format: 'terminal' });
      assert.ok(qrAscii.length > 0, 'Should generate terminal text QR code');
    });
  });
});
