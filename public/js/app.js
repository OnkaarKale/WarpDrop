/**
 * Main Application Orchestrator for Secure P2P File Transfer.
 *
 * Connects UI, Camera QR Scanner, WebRTC Transport, ECDH Key Agreement,
 * SAS Verification, Receiver Approval Gating, and Encrypted Chunk Streaming.
 */

import { parseAndValidateQRPayload, parsePairingInput, QRScanner } from './qr.js';
import {
  formatBytes,
  formatSpeed,
  formatDuration,
  calculateETA,
  sanitizeText,
  UIStates,
  UIStateManager,
  createProgressThrottler,
  setElementText
} from './ui.js';

import {
  generateSessionKeyPair,
  exportPublicKey,
  importPeerPublicKey,
  deriveSharedSecretBits
} from '/src/crypto/keyExchange.js';

import { deriveSessionKeys, generateSAS } from '/src/crypto/kdf.js';
import { encryptChunk, decryptChunk } from '/src/crypto/cipher.js';

import { FileChunker } from '/src/protocol/chunker.js';
import { FileReassembler } from '/src/protocol/reassembler.js';
import {
  FRAME_MAGIC_0,
  FRAME_MAGIC_1,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_CONTROL,
  ControlActions
} from '/src/protocol/types.js';
import {
  packChunkFrame,
  unpackChunkFrame,
  packControlFrame,
  unpackControlFrame
} from '/src/protocol/frames.js';

import { WebRTCPeerTransport } from '/src/transport/webrtcPeer.js';
import { createZipArchive, extractZipArchive } from '/src/protocol/zip.js';

// Application State
const ui = new UIStateManager();
const qrScanner = new QRScanner();

let currentRole = 'sender'; // 'sender' or 'receiver'
let selectedFile = null;
let selectedFilesList = []; // Array of { file, path, isFolder }
let selectedPackageName = '';
let currentSession = null;
let localPeerId = null;
let targetPeerId = null;

let localKeyPair = null;
let localPubKeyB64 = null;
let peerPubKeyB64 = null;

let cryptoKeys = null; // { outboundKey, outboundStaticIv, inboundKey, inboundStaticIv, sasToken }
let transport = null;
let chunker = null;
let reassembler = null;
let controlSeqCounter = 0;

let transferStartTime = 0;
let lastBytesTransferred = 0;
let lastSpeedCheckTime = 0;
let currentSpeedBps = 0;
let isCancelled = false;
let activeDownloadUrl = null;
let handshakeSent = false;

// DOM Element References
const tabSend = document.getElementById('tab-send');
const tabReceive = document.getElementById('tab-receive');
const panelSend = document.getElementById('panel-send');
const panelReceive = document.getElementById('panel-receive');
const viewTransferring = document.getElementById('view-transferring');
const viewComplete = document.getElementById('view-complete');
const connectionBadge = document.getElementById('connection-badge');
const alertBanner = document.getElementById('alert-banner');
const alertMessage = document.getElementById('alert-message');
const alertClose = document.getElementById('alert-close');

// Send Panel Elements
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const folderInput = document.getElementById('folder-input');
const browseBtn = document.getElementById('browse-btn');
const browseFolderBtn = document.getElementById('browse-folder-btn');
const selectedFileCard = document.getElementById('selected-file-card');
const selectedCardTitle = document.getElementById('selected-card-title');
const selectedFileIcon = document.getElementById('selected-file-icon');
const selectedFileName = document.getElementById('selected-file-name');
const selectedFileSize = document.getElementById('selected-file-size');
const selectedFileType = document.getElementById('selected-file-type');
const removeFileBtn = document.getElementById('remove-file-btn');
const openScannerBtn = document.getElementById('open-scanner-btn');
const manualPairForm = document.getElementById('manual-pair-form');
const inputHost = document.getElementById('input-host');
const inputPort = document.getElementById('input-port');
const inputSessionId = document.getElementById('input-session-id');
const inputToken = document.getElementById('input-token');

// Receive Panel Elements
const refreshSessionBtn = document.getElementById('refresh-session-btn');
const qrLoading = document.getElementById('qr-loading');
const receiveQrImg = document.getElementById('receive-qr-img');
const displayLink = document.getElementById('display-link');
const displaySessionId = document.getElementById('display-session-id');
const displayToken = document.getElementById('display-token');
const displayHost = document.getElementById('display-host');
const copyFieldLink = document.getElementById('copy-field-link');
const copyFieldSession = document.getElementById('copy-field-session');
const copyFieldToken = document.getElementById('copy-field-token');
const copyFieldHost = document.getElementById('copy-field-host');
const copyDetailsBtn = document.getElementById('copy-details-btn');

// SAS Modal Elements
const modalSas = document.getElementById('modal-sas');
const sasDigits = document.getElementById('sas-digits');
const sasEmojis = document.getElementById('sas-emojis');
const sasWords = document.getElementById('sas-words');
const sasConfirmBtn = document.getElementById('sas-confirm-btn');
const sasRejectBtn = document.getElementById('sas-reject-btn');

// Approval Modal Elements
const modalApproval = document.getElementById('modal-approval');
const approvalFilename = document.getElementById('approval-filename');
const approvalFilesize = document.getElementById('approval-filesize');
const approvalChunks = document.getElementById('approval-chunks');
const approveTransferBtn = document.getElementById('approve-transfer-btn');
const rejectTransferBtn = document.getElementById('reject-transfer-btn');

// Camera Scanner Modal Elements
const modalScanner = document.getElementById('modal-scanner');
const scannerVideo = document.getElementById('scanner-video');
const scannerStatus = document.getElementById('scanner-status');
const closeScannerBtn = document.getElementById('close-scanner-btn');
const scannerModalPasteInput = document.getElementById('scanner-modal-paste-input');
const scannerModalPasteBtn = document.getElementById('scanner-modal-paste-btn');
const scannerFileInput = document.getElementById('scanner-file-input');
const scannerUploadBtn = document.getElementById('scanner-upload-btn');

// Transfer Progress Elements
const transferTitle = document.getElementById('transfer-title');
const transferDirectionBadge = document.getElementById('transfer-direction-badge');
const transferFilename = document.getElementById('transfer-filename');
const transferFilesize = document.getElementById('transfer-filesize');
const progressBarContainer = document.getElementById('progress-bar-container');
const progressFill = document.getElementById('progress-fill');
const progressPercent = document.getElementById('progress-percent');
const progressSpeed = document.getElementById('progress-speed');
const progressEta = document.getElementById('progress-eta');
const transferStatusMessage = document.getElementById('transfer-status-message');
const cancelTransferBtn = document.getElementById('cancel-transfer-btn');

// Complete View Elements
const completeFilename = document.getElementById('complete-filename');
const completeFilesize = document.getElementById('complete-filesize');
const completeSha256 = document.getElementById('complete-sha256');
const downloadFileBtn = document.getElementById('download-file-btn');
const startNewBtn = document.getElementById('start-new-btn');
const unzippedCard = document.getElementById('unzipped-card');
const unzippedTitle = document.getElementById('unzipped-title');
const unzippedStats = document.getElementById('unzipped-stats');
const unzippedFilesList = document.getElementById('unzipped-files-list');
const folderSearchInput = document.getElementById('folder-search-input');
const folderSearchCount = document.getElementById('folder-search-count');
const saveFolderDiskBtn = document.getElementById('save-folder-disk-btn');
const downloadAllUnzippedBtn = document.getElementById('download-all-unzipped-btn');

let currentExtractedFiles = [];
let isFinalizingTransfer = false;

// Helper to generate a random client peer ID
function generatePeerId(prefix = 'peer') {
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}-${rand}`;
}

// Show alert message
function showAlert(message, type = 'error') {
  alertMessage.textContent = message;
  alertBanner.classList.remove('hidden');
  if (type === 'error') {
    alertBanner.style.borderColor = 'var(--accent-danger)';
  } else {
    alertBanner.style.borderColor = 'var(--accent-primary)';
  }
}

function hideAlert() {
  alertBanner.classList.add('hidden');
  alertMessage.textContent = '';
}

// Throttled progress updater to avoid DOM thrashing
const progressThrottler = createProgressThrottler({
  onUpdate: (data) => {
    const { percentage, transferredBytes, totalBytes, speed, eta } = data;
    if (progressBarContainer) {
      progressBarContainer.setAttribute('aria-valuenow', percentage);
    }
    progressFill.style.width = `${percentage}%`;
    progressPercent.textContent = `${percentage}%`;
    transferFilesize.textContent = `${formatBytes(transferredBytes)} / ${formatBytes(totalBytes)}`;
    progressSpeed.textContent = formatSpeed(speed);
    progressEta.textContent = eta !== null ? `ETA: ${formatDuration(eta)}` : 'ETA: --';
  },
  intervalMs: 80
});

// Update connection status badge in header
function updateBadge(text, className) {
  connectionBadge.textContent = text;
  connectionBadge.className = `badge ${className}`;
}

// Switch between Send and Receive tabs
function setTab(tab) {
  if (tab === 'send') {
    currentRole = 'sender';
    tabSend.classList.add('active');
    tabSend.setAttribute('aria-selected', 'true');
    tabReceive.classList.remove('active');
    tabReceive.setAttribute('aria-selected', 'false');
    panelSend.classList.remove('hidden');
    panelReceive.classList.add('hidden');
  } else {
    currentRole = 'receiver';
    tabReceive.classList.add('active');
    tabReceive.setAttribute('aria-selected', 'true');
    tabSend.classList.remove('active');
    tabSend.setAttribute('aria-selected', 'false');
    panelReceive.classList.remove('hidden');
    panelSend.classList.add('hidden');
    initReceiverSession();
  }
}

// Initialize Receiver Ephemeral Session from Server
async function initReceiverSession() {
  qrLoading.classList.remove('hidden');
  receiveQrImg.classList.add('hidden');
  if (displayLink) displayLink.textContent = 'Generating...';
  displaySessionId.textContent = 'Generating...';
  displayToken.textContent = 'Generating...';
  displayHost.textContent = 'Detecting...';

  try {
    const res = await fetch('/api/session');
    if (!res.ok) {
      throw new Error(`Failed to create session: ${res.statusText}`);
    }
    const sessionData = await res.json();
    currentSession = sessionData;

    localPeerId = generatePeerId('rx');
    receiveQrImg.src = sessionData.qrDataUrl;
    receiveQrImg.classList.remove('hidden');
    qrLoading.classList.add('hidden');

    const directUrl = `${window.location.origin}/?s=${encodeURIComponent(sessionData.sessionId)}&t=${encodeURIComponent(sessionData.token)}&h=${encodeURIComponent(sessionData.host)}&p=${sessionData.port}`;
    if (displayLink) {
      displayLink.textContent = directUrl;
    }
    displaySessionId.textContent = sessionData.sessionId;
    displayToken.textContent = sessionData.token;
    displayHost.textContent = `${sessionData.host}:${sessionData.port}`;

    updateBadge('Waiting for peer', 'badge-info');

    // Connect receiver to signaling
    await startPeerConnection({
      role: 'responder',
      sessionId: sessionData.sessionId,
      token: sessionData.token,
      host: sessionData.host,
      port: sessionData.port
    });
  } catch (err) {
    qrLoading.classList.add('hidden');
    showAlert(`Failed to initialize receive session: ${err.message}`);
    updateBadge('Error', 'badge-danger');
  }
}

// File and Folder Selection Handlers
function handleFilesSelected(files, isFolder = false) {
  if (!files || files.length === 0) return;

  if (files.length === 1 && !isFolder && !files[0].webkitRelativePath) {
    selectedFile = files[0];
    selectedFilesList = [{ file: files[0], path: files[0].name, isFolder: false }];
    selectedPackageName = files[0].name;

    selectedFileName.textContent = selectedFile.name;
    selectedFileSize.textContent = formatBytes(selectedFile.size);
    selectedFileType.textContent = selectedFile.type || 'application/octet-stream';
    if (selectedFileIcon) selectedFileIcon.textContent = '📄';
    if (selectedCardTitle) selectedCardTitle.textContent = 'Selected File';

    selectedFileCard.classList.remove('hidden');
    dropzone.classList.add('hidden');
    ui.transition(UIStates.SELECTING_FILES);
    hideAlert();
    return;
  }

  // Multiple files or folder selected via input
  const fileEntries = [];
  let rootFolder = '';
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const rel = f.webkitRelativePath || f.name;
    if (f.webkitRelativePath && !rootFolder) {
      rootFolder = f.webkitRelativePath.split('/')[0];
    }
    fileEntries.push({ file: f, path: rel, isFolder: !!f.webkitRelativePath });
  }

  const isDir = isFolder || !!rootFolder;
  const pkgName = isDir ? `${rootFolder || 'folder'}.zip` : `bundle_${files.length}_files.zip`;
  setMultiFilesSelected(fileEntries, pkgName, isDir ? 'folder' : 'multifile', rootFolder);
}

function setMultiFilesSelected(fileEntries, zipName, type = 'multifile', folderName = '') {
  selectedFilesList = fileEntries;
  selectedPackageName = zipName;
  selectedFile = null; // Will be created as ZIP upon send

  const totalBytes = fileEntries.reduce((sum, item) => sum + item.file.size, 0);

  if (type === 'folder') {
    selectedFileName.textContent = `${folderName || 'Folder'} (${fileEntries.length} files)`;
    selectedFileSize.textContent = formatBytes(totalBytes);
    selectedFileType.textContent = 'Folder Archive (will send as .zip)';
    if (selectedFileIcon) selectedFileIcon.textContent = '📁';
    if (selectedCardTitle) selectedCardTitle.textContent = 'Selected Folder';
  } else {
    const sample = fileEntries.slice(0, 2).map((f) => f.file.name).join(', ');
    const more = fileEntries.length > 2 ? ` and ${fileEntries.length - 2} more` : '';
    selectedFileName.textContent = `${fileEntries.length} files (${sample}${more})`;
    selectedFileSize.textContent = formatBytes(totalBytes);
    selectedFileType.textContent = 'Multi-file Archive (will send as .zip)';
    if (selectedFileIcon) selectedFileIcon.textContent = '📦';
    if (selectedCardTitle) selectedCardTitle.textContent = 'Selected Files';
  }

  selectedFileCard.classList.remove('hidden');
  dropzone.classList.add('hidden');
  ui.transition(UIStates.SELECTING_FILES);
  hideAlert();
}

async function handleDataTransferDrop(dataTransfer) {
  const items = dataTransfer.items;
  if (!items || items.length === 0) {
    if (dataTransfer.files) {
      handleFilesSelected(dataTransfer.files);
    }
    return;
  }

  const entries = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (item.webkitGetAsEntry) {
      const entry = item.webkitGetAsEntry();
      if (entry) entries.push(entry);
    }
  }

  if (entries.length === 0) {
    handleFilesSelected(dataTransfer.files);
    return;
  }

  const collected = [];
  for (const entry of entries) {
    const list = await readEntryRecursive(entry, '');
    collected.push(...list);
  }

  if (collected.length === 0) return;

  if (collected.length === 1 && entries.length === 1 && entries[0].isFile) {
    handleFilesSelected([collected[0].file]);
  } else {
    const isSingleFolder = entries.length === 1 && entries[0].isDirectory;
    const folderName = isSingleFolder ? entries[0].name : `bundle_${collected.length}_files`;
    setMultiFilesSelected(collected, `${folderName}.zip`, isSingleFolder ? 'folder' : 'multifile', folderName);
  }
}

async function readEntryRecursive(entry, parentPath = '') {
  if (entry.isFile) {
    return new Promise((resolve) => {
      entry.file(
        (file) => resolve([{ file, path: parentPath + file.name, isFolder: !!parentPath }]),
        () => resolve([])
      );
    });
  } else if (entry.isDirectory) {
    const dirReader = entry.createReader();
    const currentPath = parentPath + entry.name + '/';
    const allEntries = [];

    const readBatch = () => {
      return new Promise((resolve) => {
        dirReader.readEntries(async (batch) => {
          if (!batch || batch.length === 0) {
            resolve(allEntries);
          } else {
            allEntries.push(...batch);
            const more = await readBatch();
            resolve(more);
          }
        }, () => resolve(allEntries));
      });
    };

    const children = await readBatch();
    const results = await Promise.all(children.map((c) => readEntryRecursive(c, currentPath)));
    return results.flat();
  }
  return [];
}

let zipPromise = null;

async function ensureSelectedFileReady() {
  if (selectedFile) return selectedFile;
  if (!selectedFilesList || selectedFilesList.length === 0) return null;

  if (selectedFilesList.length === 1 && !selectedFilesList[0].isFolder) {
    selectedFile = selectedFilesList[0].file;
    return selectedFile;
  }

  if (zipPromise) {
    return zipPromise;
  }

  updateBadge('Packaging ZIP...', 'badge-info');
  zipPromise = (async () => {
    try {
      const zip = await createZipArchive(selectedFilesList, selectedPackageName || 'archive.zip');
      selectedFile = zip;
      return zip;
    } finally {
      zipPromise = null;
    }
  })();

  return zipPromise;
}

function clearSelectedFile() {
  selectedFile = null;
  selectedFilesList = [];
  selectedPackageName = '';
  zipPromise = null;
  fileInput.value = '';
  if (folderInput) folderInput.value = '';
  selectedFileCard.classList.add('hidden');
  dropzone.classList.remove('hidden');
  ui.transition(UIStates.IDLE);
}

// Establish WebRTC Connection via Local Signaling
async function startPeerConnection({ role, sessionId, token, host, port }) {
  if (transport) {
    transport.close();
    transport = null;
  }

  isCancelled = false;
  handshakeSent = false;
  currentRole = (role === 'initiator' || role === 'sender') ? 'sender' : 'receiver';
  localPeerId = generatePeerId(currentRole === 'sender' ? 'tx' : 'rx');
  targetPeerId = null;
  cryptoKeys = null;
  chunker = null;
  reassembler = null;
  controlSeqCounter = 0;

  // Ephemeral ECDH Key Pair Generation (Web Crypto API)
  localKeyPair = await generateSessionKeyPair();
  localPubKeyB64 = await exportPublicKey(localKeyPair.publicKey);

  // Dynamic ICE server configuration from backend
  let rtcConfig = undefined;
  try {
    const iceRes = await fetch('/api/ice-servers');
    if (iceRes.ok) {
      const iceData = await iceRes.json();
      if (Array.isArray(iceData?.iceServers) && iceData.iceServers.length > 0) {
        rtcConfig = { iceServers: iceData.iceServers };
      }
    }
  } catch (iceErr) {
    console.warn('[P2P] Dynamic ICE resolution fallback to default:', iceErr.message);
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const isStandardPort = (protocol === 'wss:' && (port === 443 || !port)) || (protocol === 'ws:' && (port === 80 || !port));
  const signalingUrl = isStandardPort ? `${protocol}//${host}` : `${protocol}//${host}:${port}`;

  transport = new WebRTCPeerTransport({
    role,
    sessionId,
    peerId: localPeerId,
    token,
    signalingUrl,
    rtcConfig
  });

  transport.on('open', async () => {
    const mode = transport.getTransportMode ? transport.getTransportMode() : 'p2p';
    const badgeText = mode === 'tunnel' ? 'Connected (Relay)' : 'Connected (P2P)';
    updateBadge(badgeText, 'badge-success');
    ui.transition(UIStates.CONNECTED);

    // Initial ECDH public key exchange over DataChannel or Tunnel
    if (!handshakeSent) {
      handshakeSent = true;
      const handshakePayload = new TextEncoder().encode(
        JSON.stringify({
          type: 'HANDSHAKE_INIT',
          publicKey: localPubKeyB64,
          peerId: localPeerId,
          role
        })
      );
      await transport.send(handshakePayload);
    }
  });

  transport.on('modeChange', (mode) => {
    if (ui.getState() === UIStates.CONNECTED || ui.getState() === UIStates.TRANSFERRING) {
      updateBadge(mode === 'tunnel' ? 'Connected (Relay)' : 'Connected (P2P)', 'badge-success');
    }
  });

  transport.on('frame', async (frameData) => {
    await handleIncomingFrame(frameData);
  });

  transport.on('error', (err) => {
    // Suppress non-fatal transport warnings if connection (P2P or Tunnel) is actively transferring or verifying
    if (transport && transport.isOpen()) {
      console.warn('[P2P] Suppressed non-fatal transport error while connection is open:', err.message);
      return;
    }
    const msg = (err?.message || '').toLowerCase();
    if (msg.includes('rtcpeerconnection failed') || msg.includes('ice connection failed')) {
      console.warn('[P2P] Suppressed non-fatal ICE error; fallback to tunnel in progress:', err.message);
      return;
    }
    showAlert(`Connection error: ${err.message}`);
    updateBadge('Failed', 'badge-danger');
    ui.error(err.message);
  });

  transport.on('close', () => {
    updateBadge('Disconnected', 'badge-idle');
  });

  transport.on('signalingClose', () => {
    // If WebRTC DataChannel is active and transferring/verifying, do not disrupt ongoing P2P transfer
    if (transport && transport.isOpen() && (ui.getState() === UIStates.TRANSFERRING || ui.getState() === UIStates.VERIFYING)) {
      console.log('[P2P] Signaling channel closed, but WebRTC DataChannel is active.');
      return;
    }
    if (
      role === 'responder' &&
      currentSession &&
      !isCancelled &&
      ui.getState() !== UIStates.TRANSFERRING &&
      ui.getState() !== UIStates.COMPLETED &&
      ui.getState() !== UIStates.ERROR
    ) {
      updateBadge('Reconnecting...', 'badge-info');
      setTimeout(() => {
        if (
          role === 'responder' &&
          currentSession &&
          !isCancelled &&
          ui.getState() !== UIStates.TRANSFERRING &&
          ui.getState() !== UIStates.ERROR
        ) {
          startPeerConnection({
            role: 'responder',
            sessionId: currentSession.sessionId,
            token: currentSession.token,
            host: currentSession.host,
            port: currentSession.port
          }).catch(() => {});
        }
      }, 1500);
    }
  });

  await transport.connect();
}

// Process incoming DataChannel Frames
async function handleIncomingFrame(frame) {
  try {
    // Check if frame is binary protocol frame (FRAME_MAGIC_0 = 0x50, FRAME_MAGIC_1 = 0x32)
    if (frame.byteLength >= 2 && frame[0] === FRAME_MAGIC_0 && frame[1] === FRAME_MAGIC_1) {
      const frameType = frame[2];

      if (frameType === FRAME_TYPE_CHUNK) {
        if (reassembler) {
          if (reassembler.isFinalized) {
            return;
          }
          await reassembler.receiveChunk(frame);
          const progress = reassembler.getProgress();
          const transferredBytes = (progress.receivedChunks / progress.totalChunks) * reassembler.manifest.size;
          updateProgressMetrics(transferredBytes, reassembler.manifest.size);

          if (reassembler.isComplete() && !isFinalizingTransfer) {
            await finalizeReceiverTransfer();
          }
        }
      } else if (frameType === FRAME_TYPE_CONTROL) {
        await handleControlFrame(frame);
      }
      return;
    }

    // Otherwise, attempt decoding JSON handshake message
    const text = new TextDecoder().decode(frame);
    const msg = JSON.parse(text);

    if (msg.type === 'HANDSHAKE_INIT' && msg.publicKey) {
      peerPubKeyB64 = msg.publicKey;
      targetPeerId = msg.peerId;

      // If peer initiated handshake and we haven't sent ours yet, reply immediately
      if (!handshakeSent) {
        handshakeSent = true;
        const handshakePayload = new TextEncoder().encode(
          JSON.stringify({
            type: 'HANDSHAKE_INIT',
            publicKey: localPubKeyB64,
            peerId: localPeerId,
            role: currentRole === 'sender' ? 'initiator' : 'responder'
          })
        );
        await transport.send(handshakePayload);
      }

      const peerKey = await importPeerPublicKey(peerPubKeyB64);
      const sharedSecretBits = await deriveSharedSecretBits(localKeyPair.privateKey, peerKey);

      const isInitiator = currentRole === 'sender';
      const initiatorPubKey = isInitiator ? localPubKeyB64 : peerPubKeyB64;
      const responderPubKey = isInitiator ? peerPubKeyB64 : localPubKeyB64;

      cryptoKeys = await deriveSessionKeys({
        sharedSecretBits,
        sessionId: transport.sessionId,
        initiatorPubKey,
        responderPubKey,
        isInitiator
      });

      // Direct Transfer: Start sending file immediately without blocking code confirmation
      const sas = generateSAS(cryptoKeys.sasToken);
      console.log('[P2P] Authenticated session established. SAS:', sas.numericCode, sas.glyphs);
      modalSas.classList.add('hidden');

      if (currentRole === 'sender') {
        const fileToSend = await ensureSelectedFileReady();
        if (!fileToSend) {
          showAlert('No file or folder selected to transfer. Please select files first.');
          return;
        }

        chunker = new FileChunker({
          file: fileToSend,
          fileName: fileToSend.name,
          mimeType: fileToSend.type,
          key: cryptoKeys.outboundKey,
          staticIv: cryptoKeys.outboundStaticIv
        });

        updateBadge('Hashing file...', 'badge-info');
        if (transferStatusMessage) {
          transferStatusMessage.classList.remove('hidden');
          transferStatusMessage.innerHTML = '🔍 <strong>Computing file integrity hash...</strong>';
        }
        const manifest = await chunker.getManifest({
          onProgress: (pct) => {
            updateBadge(`Hashing ${pct}%...`, 'badge-info');
            if (transferStatusMessage) {
              transferStatusMessage.innerHTML = `🔍 <strong>Computing file integrity hash (${pct}%)...</strong>`;
            }
          }
        });
        if (transferStatusMessage) {
          transferStatusMessage.classList.add('hidden');
        }
        console.log('[P2P] Sending MANIFEST directly to receiver:', manifest);
        await sendControlMessage(ControlActions.MANIFEST, { manifest });
        updateBadge('Sending file...', 'badge-info');
      } else {
        updateBadge('Connected, waiting for file...', 'badge-info');
      }
    }
  } catch (err) {
    console.error('Frame processing failed:', err);
    showAlert(`Transfer error: ${err.message}`);
    ui.error(err.message);
  }
}

// Display SAS Modal for peer comparison (optional / reference)
function displaySASModal(sas) {
  const num = sas.numericCode;
  sasDigits.textContent = `${num.slice(0, 3)} ${num.slice(3)}`;
  sasEmojis.textContent = sas.glyphs;
  sasWords.textContent = sas.words;
}

// Send encrypted control frame over DataChannel
async function sendControlMessage(action, payload = {}) {
  if (!cryptoKeys || !transport) return;

  const controlSeq = ++controlSeqCounter;
  const plaintext = new TextEncoder().encode(JSON.stringify({ action, ...payload }));
  const encrypted = await encryptChunk({
    key: cryptoKeys.outboundKey,
    staticIv: cryptoKeys.outboundStaticIv,
    chunkIndex: controlSeq,
    data: plaintext
  });

  const frame = packControlFrame({
    controlSeq,
    ciphertext: encrypted.ciphertext
  });
  await transport.send(frame);
}

// Process encrypted control frames
async function handleControlFrame(frame) {
  if (!cryptoKeys) return;

  const { controlSeq, ciphertext } = unpackControlFrame(frame);
  const decryptedBytes = await decryptChunk({
    key: cryptoKeys.inboundKey,
    staticIv: cryptoKeys.inboundStaticIv,
    chunkIndex: controlSeq,
    ciphertext
  });

  const msg = JSON.parse(new TextDecoder().decode(decryptedBytes));

  switch (msg.action) {
    case ControlActions.MANIFEST: {
      // Auto-accept transfer directly without approval prompt
      console.log('[P2P] Received MANIFEST directly. Auto-accepting and streaming...');
      ui.approve(); // Gate clearance

      reassembler = new FileReassembler({
        manifest: msg.manifest,
        fileIndex: 0,
        key: cryptoKeys.inboundKey,
        staticIv: cryptoKeys.inboundStaticIv
      });
      reassembler.approve();

      transferStartTime = Date.now();
      lastBytesTransferred = 0;
      lastSpeedCheckTime = Date.now();

      ui.transition(UIStates.TRANSFERRING);
      showTransferView('Receiving File...');

      await sendControlMessage(ControlActions.ACCEPT);
      break;
    }

    case ControlActions.ACCEPT: {
      // Sender starts streaming chunks
      ui.approve();
      ui.transition(UIStates.TRANSFERRING);
      showTransferView('Sending File...');
      startSenderStreaming();
      break;
    }

    case ControlActions.REJECT: {
      showAlert('The receiving device declined the transfer request.');
      ui.cancel('Transfer declined by receiver');
      resetToInitialState();
      break;
    }

    case ControlActions.COMPLETE: {
      console.log('[P2P] Received COMPLETE control frame: sender finished transmitting all chunks.');
      if (reassembler && reassembler.isComplete()) {
        // Reassembly complete; receiver finalization is in progress or completed
      } else {
        updateBadge('Receiving final data...', 'badge-info');
      }
      break;
    }

    case ControlActions.DOWNLOAD_ACK: {
      console.log('[P2P] Sender received DOWNLOAD_ACK from peer! Peer verified & saved:', msg);
      if (transferStatusMessage) {
        transferStatusMessage.classList.add('hidden');
        transferStatusMessage.textContent = '';
      }
      ui.transition(UIStates.COMPLETED);
      showCompleteView(msg.name, msg.size, msg.sha256);
      updateBadge('Transferred & Saved!', 'badge-success');
      showAlert(`✓ Transfer complete! Recipient automatically downloaded & verified ${msg.name}.`, 'success');
      break;
    }

    case ControlActions.CANCEL: {
      showAlert('Transfer was cancelled by the peer.');
      ui.cancel('Cancelled by peer');
      resetToInitialState();
      break;
    }
  }
}

// Receiver Approval Modal Gate
function displayApprovalModal(manifest) {
  ui.transition(UIStates.WAITING_APPROVAL);

  approvalFilename.textContent = manifest.name;
  approvalFilesize.textContent = formatBytes(manifest.size);
  approvalChunks.textContent = `${manifest.totalChunks} (${formatBytes(manifest.chunkSize)} each)`;

  modalApproval.classList.remove('hidden');

  approveTransferBtn.onclick = async () => {
    modalApproval.classList.add('hidden');
    ui.approve(); // Gate clearance!

    reassembler = new FileReassembler({
      manifest,
      fileIndex: 0,
      key: cryptoKeys.inboundKey,
      staticIv: cryptoKeys.inboundStaticIv
    });
    reassembler.approve();

    transferStartTime = Date.now();
    lastBytesTransferred = 0;
    lastSpeedCheckTime = Date.now();

    ui.transition(UIStates.TRANSFERRING);
    showTransferView('Receiving File...');

    await sendControlMessage(ControlActions.ACCEPT);
  };

  rejectTransferBtn.onclick = async () => {
    modalApproval.classList.add('hidden');
    await sendControlMessage(ControlActions.REJECT);
    ui.cancel('Transfer declined');
  };
}

// Sender chunk streaming loop
async function startSenderStreaming() {
  if (!chunker || !transport) return;

  transferStartTime = Date.now();
  lastBytesTransferred = 0;
  lastSpeedCheckTime = Date.now();
  console.log('[P2P] startSenderStreaming: began sending chunks');

  try {
    while (chunker.hasMoreChunks() && !isCancelled) {
      const chunkFrame = await chunker.nextChunk();
      await transport.send(chunkFrame); // Backpressure handled by FlowController

      const progress = chunker.getProgress ? chunker.getProgress() : chunker.getCurrentProgress();
      const transferredBytes = progress.bytesTransferred !== undefined
        ? progress.bytesTransferred
        : (progress.currentChunk / progress.totalChunks) * chunker.fileSize;
      updateProgressMetrics(transferredBytes, chunker.fileSize);

      // Micro-pacing & event loop yield between chunks:
      // Gives the router's half-duplex Wi-Fi radio airtime to interleave transmissions,
      // preventing wireless packet collisions, bufferbloat, and dropped ICE keepalives
      await new Promise((resolve) => setTimeout(resolve, 2));
    }

    if (!isCancelled) {
      const manifest = await chunker.getManifest();
      await sendControlMessage(ControlActions.COMPLETE, {
        name: manifest.name,
        size: manifest.size,
        sha256: manifest.sha256
      });
      console.log('[P2P] Sender: all chunks sent. Waiting for peer to verify & download...');
      updateBadge('Saving on Peer...', 'badge-info');
      transferTitle.textContent = 'Saving on Peer Device...';
      if (transferStatusMessage) {
        transferStatusMessage.classList.remove('hidden');
        transferStatusMessage.innerHTML = '⏳ <strong>All data sent!</strong> Waiting for recipient to verify & save file...';
      }
    }
  } catch (err) {
    console.error('[P2P] Sender streaming error:', err);
    showAlert(`Transfer failed: ${err.message}`);
    ui.error(err.message);
  }
}

function downloadAllExtracted(extractedFiles) {
  extractedFiles.forEach((item, idx) => {
    setTimeout(() => {
      const a = document.createElement('a');
      const blob = new Blob([item.data], { type: item.file.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      a.href = url;
      a.download = item.name;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        try { document.body.removeChild(a); } catch {}
        URL.revokeObjectURL(url);
      }, 500);
    }, idx * 180);
  });
}

async function saveExtractedToFolder(extractedFiles) {
  if (!('showDirectoryPicker' in window)) {
    downloadAllExtracted(extractedFiles);
    return;
  }

  try {
    const parentDir = await window.showDirectoryPicker({ mode: 'readwrite' });
    updateBadge('Saving to disk...', 'badge-info');

    for (const item of extractedFiles) {
      const parts = item.path.split('/').filter(Boolean);
      let cur = parentDir;
      for (let i = 0; i < parts.length - 1; i++) {
        cur = await cur.getDirectoryHandle(parts[i], { create: true });
      }
      const fname = parts[parts.length - 1];
      const fh = await cur.getFileHandle(fname, { create: true });
      const writable = await fh.createWritable();
      await writable.write(item.data);
      await writable.close();
    }

    updateBadge('Folder Saved!', 'badge-success');
    showAlert(`Successfully saved ${extractedFiles.length} files unzipped to chosen folder!`, 'success');
  } catch (err) {
    if (err.name !== 'AbortError') {
      showAlert(`Failed to save folder to disk: ${err.message}`);
    }
  }
}

// Helper to reliably trigger automatic browser file download
function triggerDirectDownload(url, filename) {
  try {
    const link = document.createElement('a');
    link.style.display = 'none';
    link.href = url;
    link.setAttribute('download', filename);
    link.setAttribute('rel', 'noopener');
    document.body.appendChild(link);

    // MouseEvent dispatch with click() fallback for maximum mobile and desktop compatibility
    try {
      const clickEvent = new MouseEvent('click', {
        view: window,
        bubbles: true,
        cancelable: true
      });
      link.dispatchEvent(clickEvent);
    } catch {
      link.click();
    }

    setTimeout(() => {
      try {
        document.body.removeChild(link);
      } catch {}
    }, 600);
  } catch (err) {
    console.warn('[P2P] Direct download trigger error:', err);
  }
}

// Receiver finalization, SHA-256 verification, and automatic unzipping
async function finalizeReceiverTransfer() {
  if (isFinalizingTransfer) return;
  isFinalizingTransfer = true;

  ui.transition(UIStates.VERIFYING);
  updateBadge('Verifying SHA-256...', 'badge-info');
  if (transferStatusMessage) {
    transferStatusMessage.classList.remove('hidden');
    transferStatusMessage.innerHTML = '🔍 <strong>Verifying file integrity (SHA-256)...</strong>';
  }

  try {
    const result = await reassembler.finalize({
      onProgress: (percent) => {
        if (transferStatusMessage) {
          transferStatusMessage.innerHTML = `🔍 <strong>Verifying file integrity... ${percent}%</strong>`;
        }
        updateBadge(`Verifying ${percent}%`, 'badge-info');
      }
    });
    console.log('[P2P] Receiver: reassembly & SHA-256 verification successful!', result.name);
    const blob = result.data instanceof Blob ? result.data : new Blob([result.data], { type: result.mimeType });
    if (activeDownloadUrl) {
      try { URL.revokeObjectURL(activeDownloadUrl); } catch {}
    }
    activeDownloadUrl = URL.createObjectURL(blob);

    if (downloadFileBtn) {
      downloadFileBtn.href = activeDownloadUrl;
      downloadFileBtn.download = result.name;
    }

    // Automatic Unzipping on Receiver
    // Limit in-browser ZIP extraction to archives <= 64 MB (64 * 1024 * 1024 bytes)
    // For archives > 64 MB, download the .zip directly to prevent tab crash/OOM
    let extractedFiles = [];
    const MAX_IN_MEMORY_ZIP_UNPACK_SIZE = 64 * 1024 * 1024;

    if (result.name.endsWith('.zip')) {
      if (blob.size <= MAX_IN_MEMORY_ZIP_UNPACK_SIZE) {
        updateBadge('Unzipping files...', 'badge-info');
        try {
          const zipBuffer = result.data instanceof Blob
            ? new Uint8Array(await result.data.arrayBuffer())
            : result.data;
          extractedFiles = await extractZipArchive(zipBuffer);
          console.log(`[P2P] Receiver: Unzipped ${extractedFiles.length} files from ${result.name}!`);
        } catch (zipErr) {
          console.warn('[P2P] Failed to unzip archive:', zipErr);
        }
      } else {
        console.log(`[P2P] ZIP archive (${Math.round(blob.size / 1024 / 1024)}MB) exceeds memory limit for in-browser extraction. Direct download enabled.`);
      }
    }

    currentExtractedFiles = extractedFiles;
    showCompleteView(result.name, blob.size, reassembler.manifest.sha256, extractedFiles);

    // Direct Automatic Download: Download immediately without waiting for user action!
    if (extractedFiles.length === 1) {
      // Single unzipped file: auto-download that file directly
      const item = extractedFiles[0];
      const singleBlob = new Blob([item.data], { type: item.file.type || 'application/octet-stream' });
      const singleUrl = URL.createObjectURL(singleBlob);
      triggerDirectDownload(singleUrl, item.name);
      setTimeout(() => {
        try { URL.revokeObjectURL(singleUrl); } catch {}
      }, 3000);
    } else {
      // Normal single file OR multi-file folder ZIP: download directly!
      triggerDirectDownload(activeDownloadUrl, result.name);
    }

    updateBadge('Downloaded!', 'badge-success');

    // Automatically send DOWNLOAD_ACK to sender so sender knows peer verified and saved file
    try {
      await sendControlMessage(ControlActions.DOWNLOAD_ACK, {
        name: result.name,
        size: blob.size,
        sha256: reassembler.manifest.sha256,
        status: 'OK'
      });
      console.log('[P2P] Receiver: Sent DOWNLOAD_ACK to sender');
    } catch (ackErr) {
      console.warn('[P2P] Could not send DOWNLOAD_ACK to peer:', ackErr);
    }
  } catch (err) {
    console.error('[P2P] Receiver finalization error:', err);
    showAlert(`Integrity verification failed: ${err.message}`);
    ui.error(err.message);
    try {
      await sendControlMessage(ControlActions.CANCEL, {
        reason: `Verification failed on receiver: ${err.message}`
      });
    } catch {}
  } finally {
    isFinalizingTransfer = false;
  }
}

// Progress metrics calculation
function updateProgressMetrics(transferredBytes, totalBytes) {
  const now = Date.now();
  const timeDelta = (now - lastSpeedCheckTime) / 1000;

  if (timeDelta >= 0.5) {
    const bytesDelta = transferredBytes - lastBytesTransferred;
    currentSpeedBps = bytesDelta / timeDelta;
    lastBytesTransferred = transferredBytes;
    lastSpeedCheckTime = now;
  }

  const percentage = totalBytes > 0 ? Math.min(100, Math.round((transferredBytes / totalBytes) * 100)) : 100;
  const eta = calculateETA({
    totalBytes,
    transferredBytes,
    bytesPerSecond: currentSpeedBps
  });

  progressThrottler.update({
    percentage,
    transferredBytes,
    totalBytes,
    speed: currentSpeedBps,
    eta
  });
}

// View Display Transitions
function showTransferView(title) {
  panelSend.classList.add('hidden');
  panelReceive.classList.add('hidden');
  viewComplete.classList.add('hidden');
  viewTransferring.classList.remove('hidden');

  if (transferStatusMessage) {
    transferStatusMessage.classList.add('hidden');
    transferStatusMessage.textContent = '';
  }

  transferTitle.textContent = title;
  transferDirectionBadge.textContent = currentRole === 'sender' ? 'Sending' : 'Receiving';
  transferFilename.textContent = selectedFile ? selectedFile.name : reassembler?.manifest?.name || 'file';
}

function renderFolderExplorer(extractedFiles, filterQuery = '') {
  if (!unzippedFilesList) return;
  unzippedFilesList.innerHTML = '';

  const q = (filterQuery || '').toLowerCase().trim();
  const filtered = q
    ? extractedFiles.filter((item) => item.path.toLowerCase().includes(q) || item.name.toLowerCase().includes(q))
    : extractedFiles;

  if (folderSearchCount) {
    folderSearchCount.textContent = q ? `Showing ${filtered.length} of ${extractedFiles.length}` : `${extractedFiles.length} files`;
  }

  if (filtered.length === 0) {
    const emptyMsg = document.createElement('div');
    emptyMsg.className = 'hint-text text-center';
    emptyMsg.style.padding = '16px';
    emptyMsg.textContent = 'No matching notes or subfolders found.';
    unzippedFilesList.appendChild(emptyMsg);
    return;
  }

  // Group files by immediate parent subfolder
  const groups = new Map();
  filtered.forEach((item) => {
    const parts = item.path.split('/').filter(Boolean);
    const folder = parts.length > 1 ? parts.slice(0, -1).join('/') : 'Main Folder';
    if (!groups.has(folder)) {
      groups.set(folder, []);
    }
    groups.get(folder).push(item);
  });

  groups.forEach((items, folderPath) => {
    const groupEl = document.createElement('div');
    groupEl.className = 'folder-group';

    const groupHeader = document.createElement('div');
    groupHeader.className = 'folder-group-header';
    groupHeader.innerHTML = `📁 <span>${sanitizeText(folderPath)}</span> <small style="color: var(--text-muted); margin-left: auto;">(${items.length} ${items.length === 1 ? 'file' : 'files'})</small>`;
    groupEl.appendChild(groupHeader);

    const itemsContainer = document.createElement('div');
    itemsContainer.className = 'folder-group-items';

    items.forEach((item) => {
      const el = document.createElement('div');
      el.className = 'unzipped-item';

      const info = document.createElement('div');
      info.className = 'unzipped-item-info';
      const pathSpan = document.createElement('span');
      pathSpan.className = 'unzipped-item-path';
      pathSpan.textContent = `📄 ${item.name}`;
      const sizeSpan = document.createElement('span');
      sizeSpan.className = 'unzipped-item-size';
      sizeSpan.textContent = formatBytes(item.size);
      info.appendChild(pathSpan);
      info.appendChild(sizeSpan);

      const actions = document.createElement('div');
      actions.className = 'item-actions';

      const itemBlob = new Blob([item.data], { type: item.file.type || 'application/octet-stream' });
      const itemUrl = URL.createObjectURL(itemBlob);

      // In-browser preview / view button
      const viewBtn = document.createElement('a');
      viewBtn.className = 'btn btn-outline btn-sm';
      viewBtn.textContent = '👁️ View';
      viewBtn.href = itemUrl;
      viewBtn.target = '_blank';
      viewBtn.rel = 'noopener';

      // Direct download button for individual file
      const dlBtn = document.createElement('a');
      dlBtn.className = 'btn btn-secondary btn-sm';
      dlBtn.textContent = '⬇️ Save';
      dlBtn.href = itemUrl;
      dlBtn.download = item.name;

      actions.appendChild(viewBtn);
      actions.appendChild(dlBtn);

      el.appendChild(info);
      el.appendChild(actions);
      itemsContainer.appendChild(el);
    });

    groupEl.appendChild(itemsContainer);
    unzippedFilesList.appendChild(groupEl);
  });
}

function showCompleteView(name, size, sha256, extractedFiles = []) {
  if (transferStatusMessage) {
    transferStatusMessage.classList.add('hidden');
    transferStatusMessage.textContent = '';
  }
  viewTransferring.classList.add('hidden');
  viewComplete.classList.remove('hidden');

  completeFilename.textContent = name;
  completeFilesize.textContent = formatBytes(size);
  completeSha256.textContent = sha256;

  if (extractedFiles && extractedFiles.length > 0) {
    unzippedCard.classList.remove('hidden');

    const folderSet = new Set();
    extractedFiles.forEach((f) => {
      const parts = f.path.split('/').filter(Boolean);
      if (parts.length > 1) {
        folderSet.add(parts.slice(0, -1).join('/'));
      }
    });
    const subfolderCount = folderSet.size;

    unzippedTitle.textContent = `📂 Folder & Notes Explorer`;
    if (unzippedStats) {
      unzippedStats.textContent = `${extractedFiles.length} files in ${subfolderCount} subfolders (${formatBytes(size)})`;
    }

    if ('showDirectoryPicker' in window) {
      saveFolderDiskBtn.classList.remove('hidden');
      saveFolderDiskBtn.onclick = () => saveExtractedToFolder(extractedFiles);
    } else {
      saveFolderDiskBtn.classList.add('hidden');
    }

    downloadAllUnzippedBtn.onclick = () => {
      if (confirm(`Downloading ${extractedFiles.length} loose files will save them all into your Downloads root folder without subdirectories. Continue?`)) {
        downloadAllExtracted(extractedFiles);
      }
    };

    if (folderSearchInput) {
      folderSearchInput.value = '';
      folderSearchInput.oninput = (e) => {
        renderFolderExplorer(extractedFiles, e.target.value);
      };
    }

    renderFolderExplorer(extractedFiles);
    updateBadge('Folder Ready & Verified', 'badge-success');
  } else {
    unzippedCard.classList.add('hidden');
    unzippedFilesList.innerHTML = '';
    updateBadge('Transfer Complete', 'badge-success');
  }
}

// Event Listeners Setup
function setupEventListeners() {
  tabSend.addEventListener('click', () => setTab('send'));
  tabReceive.addEventListener('click', () => setTab('receive'));

  alertClose.addEventListener('click', hideAlert);

  // File & Folder Picker & Dropzone
  browseBtn.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => handleFilesSelected(e.target.files));

  if (browseFolderBtn && folderInput) {
    browseFolderBtn.addEventListener('click', () => folderInput.click());
    folderInput.addEventListener('change', (e) => handleFilesSelected(e.target.files, true));
  }

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', async (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer) {
      await handleDataTransferDrop(e.dataTransfer);
    }
  });

  removeFileBtn.addEventListener('click', clearSelectedFile);

  // Manual Pair Form
  manualPairForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!selectedFile && selectedFilesList.length === 0) {
      showAlert('Please choose files or a folder to send first.');
      return;
    }

    try {
      // Prepare file or ZIP archive before starting WebRTC
      await ensureSelectedFileReady();

      let cleanHost = inputHost.value.trim();
      let cleanPort = inputPort.value.trim();

      // Handle cases where user pastes URL or host:port into host field
      if (cleanHost.includes('://')) {
        try {
          const parsed = new URL(cleanHost);
          cleanHost = parsed.hostname;
          if (parsed.port) cleanPort = parsed.port;
        } catch {}
      } else if (cleanHost.includes(':')) {
        const parts = cleanHost.split(':');
        cleanHost = parts[0];
        if (parts[1]) cleanPort = parts[1];
      }

      inputHost.value = cleanHost;
      if (cleanPort) inputPort.value = cleanPort;

      const payload = parseAndValidateQRPayload({
        v: 1,
        h: cleanHost,
        p: parseInt(cleanPort, 10),
        s: inputSessionId.value.trim(),
        t: inputToken.value.trim()
      });

      if (ui.getState() !== UIStates.IDLE && ui.getState() !== UIStates.SELECTING_FILES) {
        ui.reset();
      }
      ui.transition(UIStates.PAIRING);
      updateBadge('Connecting...', 'badge-info');

      await startPeerConnection({
        role: 'initiator',
        sessionId: payload.sessionId,
        token: payload.token,
        host: payload.host,
        port: payload.port
      });
    } catch (err) {
      ui.error(err.message);
      showAlert(`Connection error: ${err.message}`);
    }
  });


  // Camera QR Scanner Modal
  openScannerBtn.addEventListener('click', async () => {
    if (!selectedFile && selectedFilesList.length === 0) {
      showAlert('Please choose files or a folder to send first.');
      return;
    }

    await ensureSelectedFileReady();

    modalScanner.classList.remove('hidden');

    // On desktop browsers without BarcodeDetector, inform user and highlight paste option
    if (!globalThis.BarcodeDetector) {
      if (scannerStatus) {
        scannerStatus.textContent = 'ℹ️ Camera scanning is optimized for phones. On desktop/laptop, paste the pairing link below to pair instantly!';
      }
      return;
    }

    await qrScanner.start(
      scannerVideo,
      async (scannedPayload) => {
        modalScanner.classList.add('hidden');
        inputHost.value = scannedPayload.host;
        inputPort.value = scannedPayload.port;
        inputSessionId.value = scannedPayload.sessionId;
        inputToken.value = scannedPayload.token;

        if (ui.getState() !== UIStates.IDLE && ui.getState() !== UIStates.SELECTING_FILES) {
          ui.reset();
        }
        ui.transition(UIStates.PAIRING);
        updateBadge('Connecting...', 'badge-info');

        await startPeerConnection({
          role: 'initiator',
          sessionId: scannedPayload.sessionId,
          token: scannedPayload.token,
          host: scannedPayload.host,
          port: scannedPayload.port
        });
      },
      (err) => {
        showAlert(`QR scanner error: ${err.message}`);
      }
    );
  });

  // Modal Paste Input & Button
  if (scannerModalPasteBtn && scannerModalPasteInput) {
    const handleModalPaste = async () => {
      const val = scannerModalPasteInput.value.trim();
      if (!val) {
        showAlert('Please enter or paste a pairing link or session details.');
        return;
      }
      try {
        const payload = parsePairingInput(val);
        qrScanner.stop();
        modalScanner.classList.add('hidden');

        inputHost.value = payload.host;
        inputPort.value = payload.port;
        inputSessionId.value = payload.sessionId;
        inputToken.value = payload.token;

        if (ui.getState() !== UIStates.IDLE && ui.getState() !== UIStates.SELECTING_FILES) {
          ui.reset();
        }
        ui.transition(UIStates.PAIRING);
        updateBadge('Connecting...', 'badge-info');

        await startPeerConnection({
          role: 'initiator',
          sessionId: payload.sessionId,
          token: payload.token,
          host: payload.host,
          port: payload.port
        });
      } catch (err) {
        showAlert(`Failed to parse pairing details: ${err.message}`);
      }
    };

    scannerModalPasteBtn.addEventListener('click', handleModalPaste);
    scannerModalPasteInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleModalPaste();
      }
    });
  }

  closeScannerBtn.addEventListener('click', () => {
    qrScanner.stop();
    modalScanner.classList.add('hidden');
  });

  scannerUploadBtn.addEventListener('click', () => scannerFileInput.click());
  scannerFileInput.addEventListener('change', async (e) => {
    if (e.target.files && e.target.files[0]) {
      try {
        const payload = await qrScanner.scanImage(e.target.files[0]);
        qrScanner.stop();
        modalScanner.classList.add('hidden');

        inputHost.value = payload.host;
        inputPort.value = payload.port;
        inputSessionId.value = payload.sessionId;
        inputToken.value = payload.token;

        if (ui.getState() !== UIStates.IDLE && ui.getState() !== UIStates.SELECTING_FILES) {
          ui.reset();
        }
        ui.transition(UIStates.PAIRING);
        updateBadge('Connecting...', 'badge-info');

        await startPeerConnection({
          role: 'initiator',
          sessionId: payload.sessionId,
          token: payload.token,
          host: payload.host,
          port: payload.port
        });
      } catch (err) {
        if (err.message && err.message.includes('BarcodeDetector')) {
          showAlert('Image QR scanning requires a mobile browser with BarcodeDetector. On desktop, please click "Paste Link / Auto-Pair" or use the direct link!');
        } else {
          showAlert(`Failed to scan image: ${err.message}`);
        }
      }
    }
  });

  // SAS Modal Confirm / Reject
  sasConfirmBtn.addEventListener('click', async () => {
    modalSas.classList.add('hidden');
    console.log(`[P2P] SAS confirmed by user. currentRole: ${currentRole}`);
    if (currentRole === 'sender') {
      if (!selectedFile) {
        showAlert('No file selected to transfer. Please select a file.');
        return;
      }
      // Prepare file chunker and send manifest
      chunker = new FileChunker({
        file: selectedFile,
        fileName: selectedFile.name,
        mimeType: selectedFile.type,
        key: cryptoKeys.outboundKey,
        staticIv: cryptoKeys.outboundStaticIv
      });

      const manifest = await chunker.getManifest();
      console.log('[P2P] Sending MANIFEST to receiver:', manifest);
      await sendControlMessage(ControlActions.MANIFEST, { manifest });
      updateBadge('Waiting for receiver approval...', 'badge-info');
    } else {
      updateBadge('Waiting for file from sender...', 'badge-info');
    }
  });

  sasRejectBtn.addEventListener('click', async () => {
    modalSas.classList.add('hidden');
    await sendControlMessage(ControlActions.CANCEL, { reason: 'SAS fingerprint mismatch' });
    ui.cancel('SAS fingerprint mismatch');
    showAlert('Transfer cancelled due to SAS fingerprint mismatch.');
  });

  // Cancel Transfer
  cancelTransferBtn.addEventListener('click', async () => {
    isCancelled = true;
    await sendControlMessage(ControlActions.CANCEL, { reason: 'Cancelled by user' });
    ui.cancel('Transfer cancelled');
    resetToInitialState();
  });

  // Start New Transfer
  startNewBtn.addEventListener('click', () => {
    resetToInitialState();
  });

  // Helper to attach copy handler to individual field copy buttons
  const attachFieldCopy = (btn, getValueFn, label) => {
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const val = getValueFn();
      if (!val || val === 'Generating...' || val === 'Detecting...') return;
      try {
        await navigator.clipboard.writeText(val);
        btn.textContent = '✓ Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 Copy';
          btn.classList.remove('copied');
        }, 1500);
        showAlert(`✓ ${label} copied to clipboard!`, 'success');
      } catch {
        showAlert(`Failed to copy ${label} to clipboard.`);
      }
    });
  };

  attachFieldCopy(
    copyFieldLink,
    () => {
      if (!currentSession) return '';
      return `${window.location.origin}/?s=${encodeURIComponent(currentSession.sessionId)}&t=${encodeURIComponent(currentSession.token)}&h=${encodeURIComponent(currentSession.host)}&p=${currentSession.port}`;
    },
    'Direct Pairing Link'
  );

  attachFieldCopy(
    copyFieldSession,
    () => currentSession?.sessionId || displaySessionId?.textContent || '',
    'Session ID'
  );

  attachFieldCopy(
    copyFieldToken,
    () => currentSession?.token || displayToken?.textContent || '',
    'Auth Token'
  );

  attachFieldCopy(
    copyFieldHost,
    () => {
      if (!currentSession) return displayHost?.textContent || '';
      return `${currentSession.host}:${currentSession.port}`;
    },
    'Signaling Host & Port'
  );

  // Copy All Details Button
  copyDetailsBtn.addEventListener('click', async () => {
    if (!currentSession) return;
    const directUrl = `${window.location.origin}/?s=${encodeURIComponent(currentSession.sessionId)}&t=${encodeURIComponent(currentSession.token)}&h=${encodeURIComponent(currentSession.host)}&p=${currentSession.port}`;
    const text = `Direct Link: ${directUrl}\nSession ID: ${currentSession.sessionId}\nToken: ${currentSession.token}\nHost: ${currentSession.host}:${currentSession.port}`;
    try {
      await navigator.clipboard.writeText(text);
      copyDetailsBtn.textContent = '✓ Copied All 4 Details!';
      setTimeout(() => {
        copyDetailsBtn.textContent = '📋 Copy All Session Details';
      }, 2000);
      showAlert('All session details copied to clipboard!', 'success');
    } catch {
      showAlert('Failed to copy to clipboard.');
    }
  });

  // New Code / Refresh Session Button
  if (refreshSessionBtn) {
    refreshSessionBtn.addEventListener('click', () => {
      if (transport) {
        try { transport.close(); } catch {}
        transport = null;
      }
      ui.reset();
      initReceiverSession();
    });
  }

  // Default host & port to current page's host & port for convenient pairing
  if (!inputHost.value) {
    inputHost.value = window.location.hostname || 'localhost';
  }
  if (!inputPort.value) {
    inputPort.value = window.location.port || (window.location.protocol === 'https:' ? '443' : '3000');
  }

  // Auto-populate pairing fields from URL query parameters if present
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.has('s') && params.has('t')) {
      inputSessionId.value = params.get('s');
      inputToken.value = params.get('t');
      if (params.has('h')) inputHost.value = params.get('h');
      if (params.has('p')) inputPort.value = params.get('p');
      setTab('send');
    }
  } catch {}
}

function resetToInitialState() {
  isFinalizingTransfer = false;
  if (activeDownloadUrl) {
    try { URL.revokeObjectURL(activeDownloadUrl); } catch {}
    activeDownloadUrl = null;
  }
  if (transport) {
    transport.close();
    transport = null;
  }
  selectedFile = null;
  currentSession = null;
  localKeyPair = null;
  cryptoKeys = null;
  chunker = null;
  reassembler = null;
  isCancelled = false;
  handshakeSent = false;

  viewTransferring.classList.add('hidden');
  viewComplete.classList.add('hidden');
  if (transferStatusMessage) {
    transferStatusMessage.classList.add('hidden');
    transferStatusMessage.textContent = '';
  }
  panelSend.classList.remove('hidden');
  panelReceive.classList.add('hidden');

  if (unzippedCard) unzippedCard.classList.add('hidden');
  if (unzippedFilesList) unzippedFilesList.innerHTML = '';
  currentExtractedFiles = [];

  clearSelectedFile();
  ui.reset();
  updateBadge('Ready', 'badge-idle');
  setTab('send');
}

// Initialize on DOM load or immediately if DOM is already ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    updateBadge('Ready', 'badge-idle');
  });
} else {
  setupEventListeners();
  updateBadge('Ready', 'badge-idle');
}
