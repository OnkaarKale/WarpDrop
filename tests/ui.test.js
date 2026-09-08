/**
 * Test Suite for Phase 6: Responsive Web UI & Browser Integration.
 *
 * Tests:
 * 1. Server API endpoints (/api/session, /api/qr, static /src/ and /vendor/noble-hashes/ serving).
 * 2. Static path confinement & security headers.
 * 3. QR code payload validation and parsing.
 * 4. Transfer speed, size formatting, and ETA calculation logic.
 * 5. UI state transitions and explicit receiver approval gating.
 * 6. XSS sanitization for filenames, device names, and error messages.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { startServer } from '../server/index.js';
import { parseAndValidateQRPayload, parsePairingInput } from '../public/js/qr.js';
import {
  formatBytes,
  formatSpeed,
  formatDuration,
  calculateETA,
  sanitizeText,
  UIStateManager
} from '../public/js/ui.js';

test('Web UI & Browser Integration Test Suite', async (t) => {

  await t.test('Server API & Static Asset Serving', async () => {
    const serverInstance = await startServer(0, '127.0.0.1');
    const port = serverInstance.server.address().port;

    try {
      // 1. GET /api/session
      const resData = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/api/session`, (res) => {
          assert.equal(res.statusCode, 200);
          assert.equal(res.headers['content-type'], 'application/json');
          let body = '';
          res.on('data', (chunk) => { body += chunk; });
          res.on('end', () => resolve(JSON.parse(body)));
        }).on('error', reject);
      });

      assert.ok(resData.sessionId, 'Must have sessionId');
      assert.ok(resData.token, 'Must have token');
      assert.ok(resData.host, 'Must have host');
      assert.ok(typeof resData.port === 'number', 'Port must be number');
      assert.ok(resData.qrPayload, 'Must have qrPayload object');
      assert.equal(resData.qrPayload.v, 1, 'QR version must be 1');
      assert.ok(resData.qrDataUrl.startsWith('data:image/png;base64,'), 'Must return base64 PNG QR Data URL');

      // 2. Serves public/index.html at /
      const { statusCode, contentType, body } = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/`, (res) => {
          let b = '';
          res.on('data', (chunk) => { b += chunk; });
          res.on('end', () => resolve({
            statusCode: res.statusCode,
            contentType: res.headers['content-type'],
            body: b
          }));
        }).on('error', reject);
      });

      assert.equal(statusCode, 200);
      assert.ok(contentType.includes('text/html'));
      assert.ok(body.includes('<!DOCTYPE html>'));
      assert.ok(body.includes('Secure P2P Transfer') || body.includes('File Transfer'));

      // 3. Serves styles.css and app.js
      const cssStatus = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/css/styles.css`, (res) => {
          assert.equal(res.statusCode, 200);
          assert.ok(res.headers['content-type'].includes('text/css'));
          resolve(true);
        }).on('error', reject);
      });
      assert.ok(cssStatus);

      const jsStatus = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/js/app.js`, (res) => {
          assert.equal(res.statusCode, 200);
          assert.ok(res.headers['content-type'].includes('text/javascript'));
          resolve(true);
        }).on('error', reject);
      });
      assert.ok(jsStatus);

      // 4. Serves ES modules from /src/
      const srcBody = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/src/protocol/types.js`, (res) => {
          assert.equal(res.statusCode, 200);
          assert.ok(res.headers['content-type'].includes('text/javascript'));
          let b = '';
          res.on('data', (chunk) => { b += chunk; });
          res.on('end', () => resolve(b));
        }).on('error', reject);
      });
      assert.ok(srcBody.includes('export const'));

      // 5. Serves noble-hashes vendor files from /vendor/noble-hashes/
      const vendorBody = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/vendor/noble-hashes/sha2.js`, (res) => {
          assert.equal(res.statusCode, 200);
          assert.ok(res.headers['content-type'].includes('text/javascript'));
          let b = '';
          res.on('data', (chunk) => { b += chunk; });
          res.on('end', () => resolve(b));
        }).on('error', reject);
      });
      assert.ok(vendorBody.includes('export'));

      // 6. Blocks directory traversal in /src/ and /vendor/
      const status1 = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/src/../package.json' }, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });
      assert.equal(status1, 403);

      const status2 = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/vendor/noble-hashes/../../server/signaling.js' }, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });
      assert.equal(status2, 403);

      // 7. Blocks null byte injection attempts without server crash (DoS mitigation)
      const nullByteStatus1 = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/%00' }, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });
      assert.equal(nullByteStatus1, 403);

      const nullByteStatus2 = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/src/%00/types.js' }, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });
      assert.equal(nullByteStatus2, 403);
    } finally {
      await serverInstance.signalingServer.close();
      await new Promise((resolve) => serverInstance.server.close(resolve));
      serverInstance.discoveryService.stop();
    }
  });

  await t.test('QR Payload Validation & Parsing', async (t2) => {
    await t2.test('validates and parses legitimate QR payload object or string', () => {
      const validPayload = {
        v: 1,
        h: '192.168.1.50',
        p: 3000,
        s: 'session-xyz-123456',
        t: 'token-abc-123456'
      };

      const parsed = parseAndValidateQRPayload(validPayload);
      assert.equal(parsed.host, '192.168.1.50');
      assert.equal(parsed.port, 3000);
      assert.equal(parsed.sessionId, 'session-xyz-123456');
      assert.equal(parsed.token, 'token-abc-123456');

      // Also parses from JSON string
      const parsedFromJson = parseAndValidateQRPayload(JSON.stringify(validPayload));
      assert.equal(parsedFromJson.sessionId, 'session-xyz-123456');
    });

    await t2.test('rejects invalid or malicious QR payloads', () => {
      assert.throws(() => parseAndValidateQRPayload(null), /Invalid QR payload/);
      assert.throws(() => parseAndValidateQRPayload('not-json'), /Invalid QR payload/);
      assert.throws(() => parseAndValidateQRPayload({ v: 2, h: 'localhost' }), /Unsupported QR version/);
      assert.throws(() => parseAndValidateQRPayload({ v: 1, h: '<script>alert(1)</script>', p: 3000, s: 'a', t: 'b' }), /Invalid host/);
      assert.throws(() => parseAndValidateQRPayload({ v: 1, h: '127.0.0.1', p: 99999, s: 'a', t: 'b' }), /Invalid port/);
      assert.throws(() => parseAndValidateQRPayload({ v: 1, h: '127.0.0.1', p: 3000, s: 'invalid!@#', t: 'b' }), /Invalid sessionId/);
    });

    await t2.test('parsePairingInput correctly extracts credentials from URLs, copied text, and JSON', () => {
      // Direct URL
      const fromUrl = parsePairingInput('http://localhost:3001/?s=session-test1234&t=tok-abcd5678&h=192.168.1.5&p=3001');
      assert.equal(fromUrl.sessionId, 'session-test1234');
      assert.equal(fromUrl.token, 'tok-abcd5678');
      assert.equal(fromUrl.host, '192.168.1.5');
      assert.equal(fromUrl.port, 3001);

      // Relative URL with query params
      const fromRelUrl = parsePairingInput('/?s=session-rel123&t=tok-rel456');
      assert.equal(fromRelUrl.sessionId, 'session-rel123');
      assert.equal(fromRelUrl.token, 'tok-rel456');

      // Copied text format
      const copiedText = `Direct Link: http://localhost:3001/?s=session-copy99&t=tok-copy88&h=10.0.0.2&p=3001\n\nSession ID: session-copy99\nToken: tok-copy88\nHost: 10.0.0.2:3001`;
      const fromCopied = parsePairingInput(copiedText);
      assert.equal(fromCopied.sessionId, 'session-copy99');
      assert.equal(fromCopied.token, 'tok-copy88');

      // JSON string
      const fromJson = parsePairingInput(JSON.stringify({ s: 'session-j1', t: 'tok-j2', h: 'myhost', p: 8080 }));
      assert.equal(fromJson.sessionId, 'session-j1');
      assert.equal(fromJson.token, 'tok-j2');
      assert.equal(fromJson.host, 'myhost');
      assert.equal(fromJson.port, 8080);

      // Rejects unparseable text
      assert.throws(() => parsePairingInput('hello world random text'), /Could not find a valid session/);
    });
  });

  await t.test('Transfer Metrics & Formatting Helpers', async (t2) => {
    await t2.test('formats byte sizes accurately', () => {
      assert.equal(formatBytes(0), '0 B');
      assert.equal(formatBytes(512), '512 B');
      assert.equal(formatBytes(1024), '1.00 KB');
      assert.equal(formatBytes(1024 * 1024 * 2.5), '2.50 MB');
      assert.equal(formatBytes(1024 * 1024 * 1024 * 1.75), '1.75 GB');
    });

    await t2.test('formats transfer speeds accurately', () => {
      assert.equal(formatSpeed(0), '0 B/s');
      assert.equal(formatSpeed(500 * 1024), '500.00 KB/s');
      assert.equal(formatSpeed(15 * 1024 * 1024), '15.00 MB/s');
    });

    await t2.test('formats duration into readable string', () => {
      assert.equal(formatDuration(0), '0s');
      assert.equal(formatDuration(45), '45s');
      assert.equal(formatDuration(75), '1m 15s');
      assert.equal(formatDuration(3665), '1h 1m 5s');
    });

    await t2.test('calculates ETA safely without division by zero', () => {
      assert.equal(calculateETA({ totalBytes: 1000, transferredBytes: 0, bytesPerSecond: 0 }), null);
      assert.equal(calculateETA({ totalBytes: 1000, transferredBytes: 1000, bytesPerSecond: 500 }), 0);
      assert.equal(calculateETA({ totalBytes: 10000, transferredBytes: 5000, bytesPerSecond: 1000 }), 5);
    });
  });

  await t.test('Security & DOM XSS Prevention', async (t2) => {
    await t2.test('sanitizes text preventing HTML/script injection', () => {
      const malicious = '<script>alert("xss")</script><img src=x onerror=alert(1)>';
      const clean = sanitizeText(malicious);
      assert.ok(!clean.includes('<script>'));
      assert.ok(!clean.includes('<img'));
      assert.ok(clean.includes('&lt;script&gt;'));
      assert.ok(clean.includes('&lt;img'));
    });
  });

  await t.test('UI State Machine Manager', async (t2) => {
    await t2.test('tracks application UI states cleanly', () => {
      const ui = new UIStateManager();
      assert.equal(ui.getState(), 'IDLE');

      ui.transition('SELECTING_FILES');
      assert.equal(ui.getState(), 'SELECTING_FILES');

      ui.transition('PAIRING');
      assert.equal(ui.getState(), 'PAIRING');

      ui.transition('CONNECTED');
      assert.equal(ui.getState(), 'CONNECTED');

      // Cannot jump directly to TRANSFERRING without WAITING_APPROVAL
      assert.throws(() => ui.transition('TRANSFERRING'), /Receiver approval required|Invalid state transition/);

      ui.transition('WAITING_APPROVAL');
      assert.equal(ui.getState(), 'WAITING_APPROVAL');

      ui.approve();
      ui.transition('TRANSFERRING');
      assert.equal(ui.getState(), 'TRANSFERRING');

      ui.transition('VERIFYING');
      ui.transition('COMPLETED');
      assert.equal(ui.getState(), 'COMPLETED');
    });

    await t2.test('allows cancel or error from any active state', () => {
      const ui = new UIStateManager();
      ui.transition('PAIRING');
      ui.cancel('User canceled');
      assert.equal(ui.getState(), 'CANCELLED');

      const ui2 = new UIStateManager();
      ui2.transition('PAIRING');
      ui2.error('Connection timeout');
      assert.equal(ui2.getState(), 'ERROR');
      assert.equal(ui2.getErrorMessage(), 'Connection timeout');
    });
  });

});
