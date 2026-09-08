import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { startServer } from '../server/index.js';

test('Server Integration Test Suite', async (t) => {
  await t.test('starts and stops server cleanly on ephemeral port', async () => {
    const instance = await startServer(0, '127.0.0.1');
    const port = instance.server.address().port;
    assert.ok(port > 0, 'Port must be assigned');

    // Test HTTP GET /
    const status = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${port}/`, (res) => {
        resolve(res.statusCode);
      }).on('error', reject);
    });

    assert.ok(status === 404 || status === 200);

    // Shutdown
    await instance.signalingServer.close();
    await new Promise((resolve) => instance.server.close(resolve));
    instance.discoveryService.stop();
  });

  await t.test('rejects path traversal attempts on static file server', async () => {
    const instance = await startServer(0, '127.0.0.1');
    const port = instance.server.address().port;

    try {
      // Test directory traversal
      const statusTraversal = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/static/../package.json' }, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });

      assert.equal(statusTraversal, 403, 'Path traversal must return 403 Forbidden');

      // Test query parameters stripping
      const statusQuery = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/?v=123&test=abc`, (res) => {
          resolve(res.statusCode);
        }).on('error', reject);
      });

      assert.ok(statusQuery === 404 || statusQuery === 200, 'Query string should be stripped cleanly');
    } finally {
      await instance.signalingServer.close();
      await new Promise((resolve) => instance.server.close(resolve));
      instance.discoveryService.stop();
    }
  });
});
