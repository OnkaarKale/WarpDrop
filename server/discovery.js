/**
 * Local Device Discovery & QR Pairing Module.
 *
 * Provides safe local IP enumeration, minimal connection QR generation,
 * and discovery lifecycle controls.
 */

import os from 'node:os';
import QRCode from 'qrcode';

export const QR_VERSION = 1;

/**
 * Enumerate usable local network IP addresses.
 *
 * @param {Object} [options]
 * @param {boolean} [options.includeLoopback=false] - Whether to include 127.0.0.1
 * @param {Object} [options.interfaces] - Custom networkInterfaces object for testing
 * @returns {Array<{ address: string, family: string, name: string, internal: boolean }>}
 */
export function getLocalIpAddresses({ includeLoopback = false, interfaces = null } = {}) {
  const allInterfaces = interfaces || os.networkInterfaces();
  const results = [];

  for (const [name, list] of Object.entries(allInterfaces)) {
    if (!list) continue;
    for (const iface of list) {
      // Only consider IPv4
      if (iface.family !== 'IPv4') continue;

      if (!includeLoopback && (iface.internal || iface.address === '127.0.0.1')) {
        continue;
      }

      results.push({
        address: iface.address,
        family: iface.family,
        name,
        internal: iface.internal
      });
    }
  }

  return results;
}

/**
 * Construct minimal, secure pairing payload for QR code.
 * Excludes any file metadata, filenames, private keys, or encryption keys.
 *
 * @param {Object} params
 * @param {string} params.host - Local IP or hostname of signaling server
 * @param {number} params.port - Port number of signaling server
 * @param {string} params.sessionId - Ephemeral session identifier
 * @param {string} params.token - Ephemeral session authentication token
 * @returns {Object}
 */
export function createQRPayload({ host, port, sessionId, token }) {
  return {
    v: QR_VERSION,
    h: host,
    p: port,
    s: sessionId,
    t: token
  };
}

/**
 * Validate parsed QR pairing payload.
 *
 * @param {any} payload
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateQRPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, error: 'QR payload must be an object' };
  }

  const { v, h, p, s, t } = payload;

  if (v !== QR_VERSION) {
    return { valid: false, error: `Unsupported QR version: ${v}` };
  }

  // Validate host: must be safe hostname or IP without special chars or command characters
  if (typeof h !== 'string' || !/^[a-zA-Z0-9.-]+$/.test(h) || h.length > 253) {
    return { valid: false, error: 'Invalid host in QR payload' };
  }

  // Validate port: 1..65535
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    return { valid: false, error: 'Invalid port number in QR payload' };
  }

  // Validate session ID & token strings
  if (typeof s !== 'string' || s.length < 8 || s.length > 64) {
    return { valid: false, error: 'Invalid sessionId in QR payload' };
  }

  if (typeof t !== 'string' || t.length < 8 || t.length > 128) {
    return { valid: false, error: 'Invalid token in QR payload' };
  }

  return { valid: true };
}

/**
 * Generate QR code representation using the qrcode library.
 *
 * @param {Object} payload - Pairing payload
 * @param {Object} [options]
 * @param {'dataUrl' | 'terminal' | 'svg'} [options.format='dataUrl']
 * @returns {Promise<string>}
 */
export async function generatePairingQR(payload, { format = 'dataUrl' } = {}) {
  const json = JSON.stringify(payload);

  if (format === 'terminal') {
    return QRCode.toString(json, { type: 'terminal', small: true });
  }

  if (format === 'svg') {
    return QRCode.toString(json, { type: 'svg' });
  }

  // Default: PNG Data URL
  return QRCode.toDataURL(json, { errorCorrectionLevel: 'M' });
}

/**
 * Lightweight local discovery controller.
 */
export class DiscoveryService {
  constructor({ port = 3000 } = {}) {
    this.port = port;
    this.isRunning = false;
  }

  start() {
    this.isRunning = true;
    const ips = getLocalIpAddresses();
    return {
      running: true,
      port: this.port,
      addresses: ips.map((i) => i.address)
    };
  }

  stop() {
    this.isRunning = false;
  }
}
