/**
 * Server Entrypoint for Local Signaling & Device Discovery.
 *
 * Runs local HTTP + WebSocket signaling server.
 * Displays local network connection URLs and terminal pairing QR code.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createSignalingServer } from './signaling.js';
import { getLocalIpAddresses, DiscoveryService, createQRPayload, generatePairingQR } from './discovery.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, '../public');
const srcDir = path.resolve(__dirname, '../src');
const vendorNobleDir = path.resolve(__dirname, '../node_modules/@noble/hashes');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

const mimeTypes = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

/**
 * Hardened HTTP request handler for static files and ephemeral session generation.
 */
function handleHttpRequest(req, res, context = {}) {
  // 1. Check for directory traversal and null-byte injection attempts in raw and decoded URL
  if (req.url.includes('..') || req.url.includes('\0') || req.url.includes('%00')) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden: directory traversal prohibited');
    return;
  }

  let rawPathname = '/';
  try {
    const parsed = new URL(req.url, 'http://localhost');
    rawPathname = decodeURIComponent(parsed.pathname);
    if (rawPathname.includes('..') || rawPathname.includes('\0')) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: directory traversal prohibited');
      return;
    }
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad Request');
    return;
  }

  // Common security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' ws: wss:; worker-src 'self' blob:; object-src 'none';"
  );
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');

  const isHttps = (context.server && context.server instanceof https.Server) || req.headers['x-forwarded-proto'] === 'https';
  if (isHttps) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  // 2. Handle REST API: GET /api/session
  if (rawPathname === '/api/session') {
    if (req.method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'text/plain' });
      res.end('Method Not Allowed');
      return;
    }

    if (!context.signalingServer || !context.discoveryService) {
      res.writeHead(503, { 'Content-Type': 'text/plain' });
      res.end('Signaling server initializing');
      return;
    }

    const { sessionId, token } = context.signalingServer.createSession();
    let host = context.primaryIp || '127.0.0.1';
    let port = context.server?.address()?.port || context.port || PORT;
    try {
      const forwardedHost = req.headers['x-forwarded-host'] || req.headers.host;
      const forwardedProto = req.headers['x-forwarded-proto'] || (context.server instanceof https.Server ? 'https' : 'http');
      if (forwardedHost) {
        const parsedUrl = new URL(req.url, `${forwardedProto}://${forwardedHost}`);
        if (parsedUrl.hostname && parsedUrl.hostname !== '0.0.0.0') {
          host = parsedUrl.hostname;
        }
        if (parsedUrl.port) {
          port = parseInt(parsedUrl.port, 10);
        } else {
          port = forwardedProto === 'https' ? 443 : 80;
        }
      }
    } catch {
      // Fall back to primaryIp
    }

    const qrPayload = createQRPayload({ host, port, sessionId, token });
    generatePairingQR(qrPayload, { format: 'dataUrl' })
      .then((qrDataUrl) => {
        console.log(`[HTTP] Created session via /api/session: ${sessionId} (Host: ${host}:${port})`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            sessionId,
            token,
            host,
            port,
            qrPayload,
            qrDataUrl
          })
        );
      })
      .catch((err) => {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`QR Generation Error: ${err.message}`);
      });
    return;
  }

  // 3. Resolve target file based on path prefix with strict path confinement
  let resolvedPath = null;

  if (rawPathname.startsWith('/src/')) {
    const subpath = rawPathname.slice('/src/'.length);
    resolvedPath = path.resolve(srcDir, subpath);
    if (!resolvedPath.startsWith(srcDir + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: directory traversal prohibited');
      return;
    }
  } else if (rawPathname.startsWith('/vendor/noble-hashes/')) {
    const subpath = rawPathname.slice('/vendor/noble-hashes/'.length);
    resolvedPath = path.resolve(vendorNobleDir, subpath);
    if (!resolvedPath.startsWith(vendorNobleDir + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: directory traversal prohibited');
      return;
    }
  } else if (rawPathname.startsWith('/server/')) {
    const subpath = rawPathname.slice('/server/'.length);
    resolvedPath = path.resolve(__dirname, subpath);
    if (!resolvedPath.startsWith(__dirname + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: directory traversal prohibited');
      return;
    }
  } else {
    const targetFile = rawPathname === '/' ? 'index.html' : rawPathname.replace(/^\/+/, '');
    resolvedPath = path.resolve(publicDir, targetFile);
    if (
      !resolvedPath.startsWith(publicDir + path.sep) &&
      resolvedPath !== path.join(publicDir, 'index.html')
    ) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden: directory traversal prohibited');
      return;
    }
  }

  try {
    fs.readFile(resolvedPath, (err, content) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
        } else {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end(`Server Error: ${err.code}`);
        }
      } else {
        const ext = path.extname(resolvedPath).toLowerCase();
        const contentType = mimeTypes[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content, 'utf-8');
      }
    });
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('Bad Request');
  }
}

/**
 * Start the application server.
 */
export async function startServer(port = PORT, host = HOST) {
  let signalingServerInstance;
  let discoveryServiceInstance;
  let primaryIp = '127.0.0.1';

  const server = http.createServer((req, res) => {
    handleHttpRequest(req, res, {
      signalingServer: signalingServerInstance,
      discoveryService: discoveryServiceInstance,
      server,
      port: server.address() ? server.address().port : port,
      primaryIp
    });
  });

  // Helper to bind port with graceful fallback if default port is occupied
  const listenWithRetry = async (targetPort, maxAttempts = 10) => {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const currentPort = targetPort === 0 ? 0 : targetPort + attempt;
      try {
        await new Promise((resolve, reject) => {
          const onError = (err) => {
            server.removeListener('error', onError);
            reject(err);
          };
          server.once('error', onError);
          server.listen(currentPort, host, () => {
            server.removeListener('error', onError);
            resolve();
          });
        });
        return;
      } catch (err) {
        if (err.code === 'EADDRINUSE' && targetPort !== 0 && attempt < maxAttempts - 1 && !process.env.PORT) {
          continue;
        }
        throw err;
      }
    }
  };

  await listenWithRetry(port);

  const boundPort = server.address().port;
  signalingServerInstance = createSignalingServer({ server });
  discoveryServiceInstance = new DiscoveryService({ port: boundPort });

  // Optional HTTPS Server on port 3443 for mobile camera QR scanning
  const certPath = path.resolve(__dirname, '../certs/server.crt');
  const keyPath = path.resolve(__dirname, '../certs/server.key');
  let httpsServer = null;
  let httpsPort = null;

  if (port !== 0 && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const sslOptions = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath)
      };

      httpsServer = https.createServer(sslOptions, (req, res) => {
        handleHttpRequest(req, res, {
          signalingServer: signalingServerInstance,
          discoveryService: discoveryServiceInstance,
          server: httpsServer,
          port: httpsServer.address() ? httpsServer.address().port : 3443,
          primaryIp
        });
      });

      httpsServer.on('upgrade', (req, socket, head) => {
        signalingServerInstance.wss.handleUpgrade(req, socket, head, (ws) => {
          signalingServerInstance.wss.emit('connection', ws, req);
        });
      });

      const targetHttpsPort = parseInt(process.env.HTTPS_PORT || '3443', 10);
      await new Promise((resolve) => {
        httpsServer.listen(targetHttpsPort, host, () => {
          httpsPort = httpsServer.address().port;
          resolve();
        });
        httpsServer.on('error', () => resolve());
      });
    } catch {
      // Graceful fallback
    }
  }

  const localIps = getLocalIpAddresses({ includeLoopback: false });
  primaryIp = localIps.length > 0 ? localIps[0].address : '127.0.0.1';

  console.log('====================================================');
  console.log('  SECURE P2P FILE TRANSFER - LOCAL SIGNALING SERVER  ');
  console.log('====================================================');
  console.log(`Local Access (PC):   http://localhost:${server.address().port}`);
  if (httpsPort) {
    console.log(`                     https://localhost:${httpsPort}`);
  }
  if (localIps.length > 0) {
    for (const iface of localIps) {
      if (httpsPort) {
        console.log(`Wi-Fi / LAN (Phone): https://${iface.address}:${httpsPort} (Recommended for Camera)`);
      }
      console.log(`                     http://${iface.address}:${server.address().port} (${iface.name})`);
    }
  }
  console.log('----------------------------------------------------');
  console.log('Signaling:      WebSocket active (ws:// & wss://)');
  console.log('Privacy:        Zero-storage, zero-file relay active');
  console.log('====================================================');

  return {
    server,
    httpsServer,
    signalingServer: signalingServerInstance,
    discoveryService: discoveryServiceInstance,
    port: server.address().port,
    httpsPort,
    host
  };
}

// Auto-run if started directly from CLI
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
