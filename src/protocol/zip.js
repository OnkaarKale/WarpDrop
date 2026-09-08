/**
 * Zero-dependency ZIP Archive Packager.
 *
 * Implements the standard PKZIP specification (Store method, 0 compression)
 * with UTF-8 filename encoding and 32-bit CRC checksums.
 * Enables zero-dependency bundling of multiple files and recursive directory
 * trees into a single standard .zip archive for fast, atomic WebRTC transfer.
 */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

/**
 * Compute standard CRC-32 checksum.
 * @param {Uint8Array} buffer
 * @returns {number} 32-bit unsigned integer
 */
export function crc32(buffer) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buffer.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/**
 * Compute CRC-32 checksum in bounded memory slices (2 MB) to support arbitrarily large files.
 * @param {File | Blob} file
 * @returns {Promise<number>}
 */
export async function computeFileCrc32(file) {
  if (!file || file.size === 0) return 0;
  let crc = 0xFFFFFFFF;
  const sliceSize = 2 * 1024 * 1024; // 2 MB slice
  let offset = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, Math.min(offset + sliceSize, file.size));
    const buf = new Uint8Array(await slice.arrayBuffer());
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xFF];
    }
    offset += sliceSize;
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

/**
 * Sanitize relative file path inside a ZIP archive to prevent Zip Slip directory traversal attacks.
 * Strips '..', '.', leading slashes, and null bytes.
 *
 * @param {string} rawPath
 * @returns {string} Safe relative path
 */
export function sanitizeZipPath(rawPath) {
  if (!rawPath || typeof rawPath !== 'string') return 'file';
  // Normalize backslashes to forward slashes, strip null bytes
  const normalized = rawPath.replace(/\0/g, '').replace(/\\/g, '/');
  // Split into path segments and eliminate empty, '.' and '..' components
  const safeParts = normalized
    .split('/')
    .map((p) => p.trim())
    .filter((p) => p && p !== '.' && p !== '..');
  return safeParts.length > 0 ? safeParts.join('/') : 'file';
}

/**
 * Package multiple files or a directory tree into a single standard .zip File object.
 * Uses zero-copy Blob composition so large folders never exhaust browser memory.
 *
 * @param {Array<{ file: File | Blob, path: string }>} fileList
 * @param {string} [zipName='archive.zip']
 * @returns {Promise<File>} A standard File object representing the .zip archive
 */
export async function createZipArchive(fileList, zipName = 'archive.zip') {
  if (!Array.isArray(fileList) || fileList.length === 0) {
    throw new Error('fileList must be a non-empty array');
  }

  const zipParts = [];
  const centralEntries = [];
  let offset = 0;

  for (const item of fileList) {
    const file = item.file;
    const rawPath = item.path || file.name || 'file';
    const cleanPath = sanitizeZipPath(rawPath);
    const nameBytes = new TextEncoder().encode(cleanPath);
    const size = file.size;
    const checksum = await computeFileCrc32(file);

    // Date & Time in MS-DOS format
    const modTime = file.lastModified ? new Date(file.lastModified) : new Date();
    const dosTime = ((modTime.getHours() << 11) | (modTime.getMinutes() << 5) | (modTime.getSeconds() >> 1)) & 0xFFFF;
    const dosDate = (((modTime.getFullYear() - 1980) << 9) | ((modTime.getMonth() + 1) << 5) | modTime.getDate()) & 0xFFFF;

    // Local file header (30 bytes + name length)
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    lv.setUint32(0, 0x04034b50, true); // Local header signature 'PK\x03\x04'
    lv.setUint16(4, 20, true);         // Version needed: 2.0
    lv.setUint16(6, 0x0800, true);     // Flags: bit 11 set (UTF-8 filename)
    lv.setUint16(8, 0, true);          // Compression method: 0 (stored / uncompressed)
    lv.setUint16(10, dosTime, true);
    lv.setUint16(12, dosDate, true);
    lv.setUint32(14, checksum, true);  // CRC-32
    lv.setUint32(18, size, true);      // Compressed size
    lv.setUint32(22, size, true);      // Uncompressed size
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);         // Extra field length
    localHeader.set(nameBytes, 30);

    zipParts.push(localHeader);
    zipParts.push(file); // Zero-copy stream from disk/virtual backing!

    // Central directory file header (46 bytes + name length)
    const centralEntry = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(centralEntry.buffer);
    cv.setUint32(0, 0x02014b50, true); // Central header signature 'PK\x01\x02'
    cv.setUint16(4, 20, true);         // Version made by: 2.0
    cv.setUint16(6, 20, true);         // Version needed: 2.0
    cv.setUint16(8, 0x0800, true);     // Flags: bit 11 (UTF-8)
    cv.setUint16(10, 0, true);         // Compression: 0
    cv.setUint16(12, dosTime, true);
    cv.setUint16(14, dosDate, true);
    cv.setUint32(16, checksum, true);  // CRC-32
    cv.setUint32(20, size, true);      // Compressed size
    cv.setUint32(24, size, true);      // Uncompressed size
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);         // Extra field length
    cv.setUint16(32, 0, true);         // File comment length
    cv.setUint16(34, 0, true);         // Disk number start
    cv.setUint16(36, 0, true);         // Internal attributes
    cv.setUint32(38, 0, true);         // External attributes
    cv.setUint32(42, offset, true);    // Relative offset of local header
    centralEntry.set(nameBytes, 46);

    centralEntries.push(centralEntry);
    offset += localHeader.length + size;
  }

  // Central directory records
  let centralDirSize = 0;
  for (const entry of centralEntries) {
    centralDirSize += entry.length;
    zipParts.push(entry);
  }

  // End of central directory record (EOCD, 22 bytes)
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); // EOCD signature 'PK\x05\x06'
  ev.setUint16(4, 0, true);          // Disk number
  ev.setUint16(6, 0, true);          // Disk with central directory
  ev.setUint16(8, fileList.length, true);  // Total entries on this disk
  ev.setUint16(10, fileList.length, true); // Total entries across all disks
  ev.setUint32(12, centralDirSize, true);  // Central directory byte size
  ev.setUint32(16, offset, true);          // Offset of central directory
  ev.setUint16(20, 0, true);               // Comment length

  zipParts.push(eocd);

  return new File(zipParts, zipName, { type: 'application/zip' });
}

/**
 * Extract files from a standard uncompressed (Store) ZIP archive.
 *
 * @param {ArrayBuffer | Uint8Array | Blob | File} zipInput
 * @returns {Promise<Array<{ path: string, name: string, size: number, data: Uint8Array, file: File }>>}
 */
export async function extractZipArchive(zipInput) {
  let arrayBuffer;
  if (zipInput instanceof ArrayBuffer) {
    arrayBuffer = zipInput;
  } else if (zipInput instanceof Uint8Array) {
    arrayBuffer = zipInput.buffer.slice(zipInput.byteOffset, zipInput.byteOffset + zipInput.byteLength);
  } else if (zipInput && typeof zipInput.arrayBuffer === 'function') {
    arrayBuffer = await zipInput.arrayBuffer();
  } else {
    throw new Error('Invalid ZIP input: expected ArrayBuffer, Uint8Array, Blob, or File');
  }

  const bytes = new Uint8Array(arrayBuffer);
  const view = new DataView(arrayBuffer);
  const entries = [];

  let offset = 0;
  while (offset < bytes.length - 30) {
    const sig = view.getUint32(offset, true);
    if (sig === 0x04034b50) {
      // Local File Header
      const compressedSize = view.getUint32(offset + 18, true);
      const uncompressedSize = view.getUint32(offset + 22, true);
      const nameLen = view.getUint16(offset + 26, true);
      const extraLen = view.getUint16(offset + 28, true);

      const nameBytes = bytes.subarray(offset + 30, offset + 30 + nameLen);
      const rawPath = new TextDecoder().decode(nameBytes);
      const path = sanitizeZipPath(rawPath);

      const dataStart = offset + 30 + nameLen + extraLen;
      const dataEnd = dataStart + compressedSize;

      if (dataEnd <= bytes.length) {
        const fileData = bytes.subarray(dataStart, dataEnd);
        const fileName = path.split('/').pop() || 'file';

        // Infer common MIME types
        let mimeType = 'application/octet-stream';
        const ext = fileName.split('.').pop()?.toLowerCase();
        if (ext === 'txt') mimeType = 'text/plain';
        else if (ext === 'html') mimeType = 'text/html';
        else if (ext === 'json') mimeType = 'application/json';
        else if (ext === 'png') mimeType = 'image/png';
        else if (ext === 'jpg' || ext === 'jpeg') mimeType = 'image/jpeg';
        else if (ext === 'pdf') mimeType = 'application/pdf';

        const file = new File([fileData], fileName, { type: mimeType });

        entries.push({
          path,
          name: fileName,
          size: uncompressedSize || compressedSize,
          data: fileData,
          file
        });

        offset = dataEnd;
      } else {
        break;
      }
    } else if (sig === 0x02014b50 || sig === 0x06054b50) {
      break;
    } else {
      offset++;
    }
  }

  return entries;
}
