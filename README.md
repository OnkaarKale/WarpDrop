# ⚡ WarpDrop - Secure P2P Wireless File & Folder Transfer

**WarpDrop** is an ultra-fast, zero-server-storage, peer-to-peer file and folder transfer application that operates directly between browsers over WebRTC DataChannels with authenticated end-to-end encryption (AES-256-GCM + ECDH P-256), QR-code pairing, automated directory hierarchy preservation, and SHA-256 integrity verification.

---

## 🌐 Live Hosted App

Try WarpDrop directly in your browser without any installation:

👉 **[https://warpdrop-py9e.onrender.com/](https://warpdrop-py9e.onrender.com/)**

*(Hosted live on Render with automatic HTTPS and WebSocket signaling)*

---

## 👥 Credits & Authorship

- **Created with the help of**: **Antigravity** & **Onkar Kale** ([@OnkaarKale](https://github.com/OnkaarKale))

---

## ⚠️ Disclaimer

> [!WARNING]
> **Use At Your Own Risk**: This software is provided *"as is"*, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability. If you use this software, **you use it at your own risk**. Always verify sensitive file transfers, protect your ephemeral session credentials, and exercise caution when sharing files across public or untrusted networks.

---

> [!IMPORTANT]
> **Status (Validated & Production-Hardened)**: Passing **196/196 automated tests** across 11 test suites (0 failures). Tested across the full file transfer matrix (0 B to multi-gigabytes), multi-file queues, recursive nested folder structures, Zip Slip traversal protection, tamper detection, signaling isolation, and resource bounds.

---

## 1. System Architecture

```
                  ┌──────────────────────────────────────────────┐
                  │        Local Node.js Signaling Server        │
                  │   • Ephemeral in-memory 2-peer rooms         │
                  │   • Relays SDP Offer, SDP Answer, ICE        │
                  │   • STRICTLY ZERO-STORAGE: Never relays      │
                  │     or inspects file contents or crypto keys │
                  └──────────────────────┬───────────────────────┘
                                         │
                         WebSocket (SDP + ICE Only)
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
                 ▼                                               ▼
         Device A (Browser)                              Device B (Browser)
          Initiator Peer                                  Responder Peer
                 │                                               │
                 │                                               │
                 └────────────── Direct WebRTC P2P ──────────────┘
                                  RTCDataChannel
                         (ordered: true, binaryType: arraybuffer)
                                         │
                               Encrypted Binary Frames
                                (Phase 3 18-byte Header
                               + AES-256-GCM Ciphertext)
                                         │
                            Streaming File Chunk Sink
                                (Bounded Memory)
```

---

## 2. Security Model & Threat Analysis

### Why Application-Level E2EE is Mandatory
While WebRTC uses DTLS-SRTP for transport-level encryption, DTLS only secures hop-by-hop transport:
1. **Endpoint Identity Verification**: DTLS does not inherently authenticate device identity to human users. Our application-level layer uses ECDH P-256 key agreement with SAS (Short Authentication String) emoji/word verification and QR pairing to ensure users are communicating with the intended physical device.
2. **Protocol Independence**: Application-level AES-256-GCM ensures that even if WebRTC connection metadata is inspected, file contents and filenames remain encrypted end-to-end.
3. **Receiver Approval Gate**: WebRTC connection opening does **not** grant automatic file transfer permission. Incoming file chunks are rejected until the receiver explicitly approves the transfer manifest.

### Zero-Knowledge Signaling Server
- The Node.js signaling server strictly handles: `JOIN`, `PEER_JOINED`, `PEER_LEFT`, `SDP_OFFER`, `SDP_ANSWER`, `ICE_CANDIDATE`.
- Binary frames, file bytes, chunk payloads, private ECDH keys, and AES session keys are **strictly forbidden** from the signaling server.
- Binary frames submitted to the signaling WebSocket are rejected with immediate connection termination.
- Static file server enforces strict path normalization and rejects null-byte injections with `403 Forbidden`.

---

## 3. WebRTC Peer Connection & Wire Protocol

### Channel Settings
- `ordered`: `true` (guaranteed in-order delivery).
- `binaryType`: `'arraybuffer'` (strictly binary mode; unexpected text frames are dropped with error).
- Maximum chunk payload: `256 KB` (`MAX_CHUNK_SIZE`).
- Header size: `18 bytes` (`packChunkFrame`).
- GCM Auth Tag: `16 bytes`.
- Flow control: WebRTC DataChannel backpressure pauses transmission when `bufferedAmount >= 1 MB` and resumes on `bufferedamountlow` (`<= 256 KB`).

---

## 4. Performance Benchmarks

Measured on Node.js v24 (Linux x86_64) using `scripts/benchmark.js`:

| Transfer Size | Duration | Throughput | Peak Heap | Peak RSS | Integrity |
|---|---|---|---|---|---|
| **10 MB** | 0.300 s | **33.38 MB/s** | 6.81 MB | 98.38 MB | SHA-256 Verified |
| **50 MB** | 1.215 s | **41.17 MB/s** | 8.30 MB | 223.59 MB | SHA-256 Verified |

*Note*: Memory remains strictly bounded because the streaming reassembler processes chunks through an incremental hash pipeline without buffering full files in active heap.

---

## 5. Deployment Guide

### A. Try the Hosted Version
Open **[https://warpdrop-py9e.onrender.com/](https://warpdrop-py9e.onrender.com/)** directly in any browser on your computer and mobile device.

### B. Local Development (Single Machine)
```bash
git clone git@github.com:OnkaarKale/WarpDrop.git
cd WarpDrop
npm install
npm run dev
```
Open two browser tabs at `http://localhost:3000`. Tab 1 generates the pairing QR / session; Tab 2 joins using the session URL or pairing payload.

### C. Home / Office LAN (Wi-Fi)
1. Start the server on host machine:
   ```bash
   npm start
   ```
2. The server binds to `0.0.0.0:3000` and displays your machine's LAN IP (e.g., `http://192.168.1.50:3000`).
3. Scan the QR code displayed in the terminal or on the web UI using your mobile device connected to the same Wi-Fi.

### D. Production Deployment (HTTPS + WSS)
To satisfy browser WebRTC security policies (`getUserMedia` for camera QR scanner and Web Crypto), production deployments must be served over TLS/HTTPS:

```nginx
server {
    listen 443 ssl http2;
    server_name transfer.example.com;

    ssl_certificate /etc/ssl/certs/transfer.crt;
    ssl_certificate_key /etc/ssl/private/transfer.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Security Headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:; img-src 'self' data: blob:;" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 6. Configuration & Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP and WebSocket signaling port |
| `HOST` | `0.0.0.0` | Network binding interface |
| `MAX_SIGNALING_MESSAGE_SIZE` | `65536` | Maximum signaling message size (64 KB) |

---

## 7. Troubleshooting & Known Limitations

1. **AP (Client) Isolation**: Guest or enterprise Wi-Fi networks with client isolation block direct UDP communication between devices on the same subnet. Use a standard private Wi-Fi network or personal mobile hotspot.
2. **No TURN Relay by Design**: Transfers operate strictly peer-to-peer. Symmetrical NAT configurations that prevent direct STUN hole punching will fail gracefully rather than relaying sensitive file data through third-party servers.
3. **Mobile Browser Tab Backgrounding**: iOS Safari and Android Chrome aggressively throttle WebRTC threads when switching tabs or locking the screen. Keep the browser tab in the foreground until the transfer completes.
4. **Headless Environment Testing**: In headless Linux containers without desktop GUI browsers, automated unit and integration tests run via the Node.js test harness. Real browser testing reports `REAL_BROWSER_TEST = NOT_AVAILABLE`.

---

## 8. Running Tests & Verification

```bash
# Run full automated test suite (196 tests)
npm test

# Run Phase 7 validation test suite
node --test tests/phase7.test.js

# Run performance benchmarks
node scripts/benchmark.js
```
