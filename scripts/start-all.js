/**
 * Unified Process Manager for Node.js Signaling Server + Nginx Reverse Proxy.
 *
 * Runs:
 * 1. Node.js backend (signaling, discovery, REST API, static files) on 127.0.0.1:3001
 * 2. Nginx reverse proxy on port 8080 (HTTP) and 8443 (HTTPS)
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const nginxConf = path.resolve(rootDir, 'nginx/nginx.conf');

function getLocalIpAddresses() {
  const allInterfaces = os.networkInterfaces();
  const results = [];

  for (const [name, list] of Object.entries(allInterfaces)) {
    if (!list) continue;
    for (const iface of list) {
      if (iface.family === 'IPv4' && !iface.internal && iface.address !== '127.0.0.1') {
        results.push({ name, address: iface.address });
      }
    }
  }
  return results;
}

console.log('====================================================');
console.log('   SECURE P2P FILE TRANSFER - FULL SYSTEM LAUNCH    ');
console.log('====================================================');

// 1. Start Node.js Server
console.log('[1/2] Starting Node.js Backend Server...');
const nodeProcess = spawn('node', ['server/index.js'], {
  cwd: rootDir,
  env: { ...process.env, PORT: '3001' },
  stdio: 'inherit'
});

nodeProcess.on('error', (err) => {
  console.error('Failed to start Node.js server:', err);
  process.exit(1);
});

// Wait 1.5 seconds for Node to bind port 3001
setTimeout(() => {
  // 2. Start Nginx with daemon off
  console.log('[2/2] Starting Nginx Reverse Proxy (HTTP: 8080 | HTTPS: 8443)...');
  const nginxProcess = spawn('nginx', ['-g', 'daemon off;', '-c', nginxConf], {
    cwd: rootDir,
    stdio: 'inherit'
  });

  nginxProcess.on('error', (err) => {
    console.error('Failed to start Nginx:', err);
    cleanup();
    process.exit(1);
  });

  const localIps = getLocalIpAddresses();
  const primaryIp = localIps.length > 0 ? localIps[0].address : '127.0.0.1';

  setTimeout(() => {
    console.log('\n====================================================');
    console.log('             ONLINE & READY FOR TRANSFERS           ');
    console.log('====================================================');
    console.log(`Local Access (PC):     http://localhost:8080`);
    console.log(`                       https://localhost:8443`);
    console.log('----------------------------------------------------');
    console.log(`Mobile / Same Wi-Fi:   https://${primaryIp}:8443 (Recommended for Camera)`);
    console.log(`                       http://${primaryIp}:8080`);
    if (localIps.length > 1) {
      for (let i = 1; i < localIps.length; i++) {
        console.log(`                       https://${localIps[i].address}:8443 (${localIps[i].name})`);
      }
    }
    console.log('----------------------------------------------------');
    console.log('Security & Features:');
    console.log('  • Nginx TLS termination on port 8443 (HTTPS/WSS)');
    console.log('  • Mobile Camera QR Scanner enabled over HTTPS');
    console.log('  • WebRTC DataChannel direct P2P transfer');
    console.log('  • AES-256-GCM application-level E2EE');
    console.log('====================================================\n');
  }, 1000);

  function cleanup() {
    console.log('\nStopping servers...');
    try { nodeProcess.kill('SIGTERM'); } catch {}
    try { nginxProcess.kill('SIGTERM'); } catch {}
  }

  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
}, 1500);
