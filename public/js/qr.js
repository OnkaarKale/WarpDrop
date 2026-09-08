/**
 * QR Code Scanner and Payload Validation Module.
 *
 * Implements:
 * 1. Safe parsing and schema validation of QR pairing payloads.
 * 2. Mobile and desktop camera QR scanner using BarcodeDetector API.
 * 3. File upload and manual payload fallbacks.
 * 4. Strict camera stream cleanup (stopping all tracks on close).
 */

export const QR_VERSION = 1;

const HOST_REGEX = /^[a-zA-Z0-9.-]+$/;
const ID_TOKEN_REGEX = /^[a-zA-Z0-9_-]{8,128}$/;

/**
 * Parse and validate a QR code payload object or JSON string.
 *
 * Expected payload format:
 * {
 *   v: 1,                       // Version
 *   h: '192.168.1.50',          // Host / IP
 *   p: 3000,                    // Port
 *   s: 'session-xyz-123456',    // Session ID
 *   t: 'token-abc-123456'       // Auth Token
 * }
 *
 * @param {Object | string} rawPayload
 * @returns {{ host: string, port: number, sessionId: string, token: string, version: number }}
 */
export function parseAndValidateQRPayload(rawPayload) {
  if (!rawPayload) {
    throw new Error('Invalid QR payload: payload is empty');
  }

  let payload = rawPayload;
  if (typeof rawPayload === 'string') {
    try {
      payload = JSON.parse(rawPayload);
    } catch {
      throw new Error('Invalid QR payload: failed to parse JSON string');
    }
  }

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('Invalid QR payload: expected an object');
  }

  // 1. Version check
  if (payload.v !== QR_VERSION) {
    throw new Error(`Unsupported QR version: expected ${QR_VERSION}, got ${payload.v}`);
  }

  // 2. Host check
  if (typeof payload.h !== 'string' || !HOST_REGEX.test(payload.h) || payload.h.length > 253) {
    throw new Error(`Invalid host in QR payload: ${payload.h}`);
  }

  // 3. Port check
  if (
    typeof payload.p !== 'number' ||
    !Number.isInteger(payload.p) ||
    payload.p < 1 ||
    payload.p > 65535
  ) {
    throw new Error(`Invalid port in QR payload: ${payload.p}`);
  }

  // 4. Session ID check
  if (typeof payload.s !== 'string' || !ID_TOKEN_REGEX.test(payload.s)) {
    throw new Error(`Invalid sessionId in QR payload: ${payload.s}`);
  }

  // 5. Token check
  if (typeof payload.t !== 'string' || !ID_TOKEN_REGEX.test(payload.t)) {
    throw new Error(`Invalid token in QR payload: ${payload.t}`);
  }

  return {
    version: payload.v,
    host: payload.h,
    port: payload.p,
    sessionId: payload.s,
    token: payload.t
  };
}

/**
 * Parse pairing input from various formats:
 * - Direct link URL: "http://localhost:3001/?s=session-...&t=tok-...&h=localhost&p=3001" or "/?s=..."
 * - Copied pairing details text: "Session ID: session-... \n Token: tok-..."
 * - Raw JSON string: '{"v":1,"h":"localhost","p":3001,"s":"session-...","t":"tok-..."}'
 *
 * @param {string} rawInput
 * @returns {{ host: string, port: number, sessionId: string, token: string }}
 */
export function parsePairingInput(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Please provide pairing text or a link');
  }

  const str = rawInput.trim();

  // 1. Try parsing JSON format
  if (str.startsWith('{') && str.endsWith('}')) {
    try {
      const parsed = JSON.parse(str);
      if (parsed.s && parsed.t) {
        return {
          sessionId: String(parsed.s).trim(),
          token: String(parsed.t).trim(),
          host: parsed.h ? String(parsed.h).trim() : 'localhost',
          port: Number(parsed.p) || 3000
        };
      }
      if (parsed.sessionId && parsed.token) {
        return {
          sessionId: String(parsed.sessionId).trim(),
          token: String(parsed.token).trim(),
          host: parsed.host ? String(parsed.host).trim() : 'localhost',
          port: Number(parsed.port) || 3000
        };
      }
    } catch {}
  }

  // 2. Try parsing URL (absolute or relative with query string)
  try {
    let urlObj = null;
    if (str.startsWith('http://') || str.startsWith('https://')) {
      urlObj = new URL(str);
    } else if (str.includes('?')) {
      const queryPart = str.slice(str.indexOf('?'));
      urlObj = new URL(queryPart, 'http://localhost');
    }

    if (urlObj && urlObj.searchParams) {
      const s = urlObj.searchParams.get('s') || urlObj.searchParams.get('sessionId');
      const t = urlObj.searchParams.get('t') || urlObj.searchParams.get('token');
      const h = urlObj.searchParams.get('h') || urlObj.searchParams.get('host') || (urlObj.hostname && urlObj.hostname !== 'localhost' ? urlObj.hostname : undefined);
      const p = urlObj.searchParams.get('p') || urlObj.searchParams.get('port') || (urlObj.port ? urlObj.port : undefined);

      if (s && t) {
        return {
          sessionId: s.trim(),
          token: t.trim(),
          host: h ? h.trim() : 'localhost',
          port: p ? parseInt(p, 10) : 3000
        };
      }
    }
  } catch {}

  // 3. Try regex extraction for formatted text (e.g. Session ID: ..., Token: ..., Host: ...)
  const sessionMatch = str.match(/session-[a-zA-Z0-9_-]+/i);
  const tokenMatch = str.match(/tok-[a-zA-Z0-9_-]+/i);

  if (sessionMatch && tokenMatch) {
    let host = 'localhost';
    let port = 3000;

    const hostMatch = str.match(/Host:\s*([a-zA-Z0-9.-]+)(?::(\d+))?/i);
    if (hostMatch) {
      if (hostMatch[1]) host = hostMatch[1].trim();
      if (hostMatch[2]) port = parseInt(hostMatch[2], 10);
    }

    return {
      sessionId: sessionMatch[0].trim(),
      token: tokenMatch[0].trim(),
      host,
      port
    };
  }

  throw new Error('Could not find a valid session ID and token in the input.');
}

/**
 * Camera QR Scanner Class for mobile and desktop browsers.
 */
export class QRScanner {
  constructor() {
    this.stream = null;
    this.videoElement = null;
    this.animationFrameId = null;
    this.barcodeDetector = null;
    this.isScanning = false;

    if (typeof globalThis.BarcodeDetector !== 'undefined') {
      try {
        this.barcodeDetector = new globalThis.BarcodeDetector({ formats: ['qr_code'] });
      } catch {
        this.barcodeDetector = null;
      }
    }
  }

  /**
   * Check if native camera BarcodeDetector is supported.
   * @returns {boolean}
   */
  static isSupported() {
    return (
      typeof navigator !== 'undefined' &&
      !!navigator.mediaDevices &&
      typeof navigator.mediaDevices.getUserMedia === 'function'
    );
  }

  /**
   * Start camera video stream and begin continuous QR scan detection.
   *
   * @param {HTMLVideoElement} videoElement
   * @param {(payload: Object) => void} onScanSuccess
   * @param {(error: Error) => void} onError
   */
  async start(videoElement, onScanSuccess, onError) {
    if (this.isScanning) {
      this.stop();
    }

    this.videoElement = videoElement;
    this.isScanning = true;

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Camera access is not supported by your browser');
      }

      // Request rear camera on mobile devices with fallback
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
        audio: false
      });

      if (!this.isScanning) {
        this._stopTracks();
        return;
      }

      this.videoElement.srcObject = this.stream;
      await this.videoElement.play();

      if (this.barcodeDetector) {
        this._scanLoop(onScanSuccess, onError);
      } else {
        // Fallback: Notify caller that BarcodeDetector is not natively available
        onError?.(new Error('Native BarcodeDetector not supported; use image upload or manual entry'));
      }
    } catch (err) {
      this.stop();
      onError?.(err);
    }
  }

  /**
   * Continuous detection loop using BarcodeDetector.
   */
  async _scanLoop(onScanSuccess, onError) {
    if (!this.isScanning || !this.videoElement) return;

    try {
      if (this.videoElement.readyState >= 2) {
        const barcodes = await this.barcodeDetector.detect(this.videoElement);
        if (barcodes && barcodes.length > 0) {
          for (const barcode of barcodes) {
            try {
              const validated = parseAndValidateQRPayload(barcode.rawValue);
              this.stop();
              onScanSuccess(validated);
              return;
            } catch {
              // Ignore barcodes that don't match our protocol schema
            }
          }
        }
      }
    } catch {
      // Frame detect error - ignore and retry next frame
    }

    if (this.isScanning) {
      this.animationFrameId = requestAnimationFrame(() => {
        this._scanLoop(onScanSuccess, onError);
      });
    }
  }

  /**
   * Scan QR code from an image File or Blob.
   *
   * @param {File | Blob | HTMLImageElement} imageSource
   * @returns {Promise<Object>} Validated payload
   */
  async scanImage(imageSource) {
    if (!this.barcodeDetector) {
      throw new Error('BarcodeDetector API is not available on this browser');
    }

    let target = imageSource;
    if (typeof ImageBitmap !== 'undefined' && (imageSource instanceof Blob || imageSource instanceof File)) {
      target = await createImageBitmap(imageSource);
    }

    const barcodes = await this.barcodeDetector.detect(target);
    if (!barcodes || barcodes.length === 0) {
      throw new Error('No QR code detected in the provided image');
    }

    for (const barcode of barcodes) {
      try {
        return parseAndValidateQRPayload(barcode.rawValue);
      } catch {
        // Continue searching
      }
    }

    throw new Error('QR code does not contain a valid file transfer pairing payload');
  }

  /**
   * Stop camera stream immediately and release all media hardware.
   */
  stop() {
    this.isScanning = false;

    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
      this.animationFrameId = null;
    }

    this._stopTracks();

    if (this.videoElement) {
      try {
        this.videoElement.pause();
        this.videoElement.srcObject = null;
      } catch {
        // Ignore video element cleanup error
      }
      this.videoElement = null;
    }
  }

  _stopTracks() {
    if (this.stream) {
      try {
        for (const track of this.stream.getTracks()) {
          track.stop();
        }
      } catch {
        // Ignore track stop error
      }
      this.stream = null;
    }
  }
}
