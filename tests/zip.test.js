import test from 'node:test';
import assert from 'node:assert/strict';
import { createZipArchive, extractZipArchive, crc32 } from '../src/protocol/zip.js';

test('Zero-Dependency ZIP Packager Test Suite', async (t) => {
  await t.test('calculates correct CRC-32 checksums', () => {
    const data = new TextEncoder().encode('123456789');
    // Standard test vector: CRC32 of "123456789" is 0xCBF43926 (3421780262)
    assert.equal(crc32(data), 0xCBF43926);
  });

  await t.test('packages multiple files into a valid ZIP File object', async () => {
    const f1 = new File([new TextEncoder().encode('File 1 content')], 'doc1.txt', { type: 'text/plain' });
    const f2 = new File([new TextEncoder().encode('File 2 content')], 'nested/doc2.txt', { type: 'text/plain' });

    const zipFile = await createZipArchive([
      { file: f1, path: 'doc1.txt' },
      { file: f2, path: 'nested/doc2.txt' }
    ], 'my_archive.zip');

    assert.equal(zipFile.name, 'my_archive.zip');
    assert.equal(zipFile.type, 'application/zip');
    assert.ok(zipFile.size > 0);

    const buf = new Uint8Array(await zipFile.arrayBuffer());
    // Verify PK\x03\x04 header at start
    assert.equal(buf[0], 0x50);
    assert.equal(buf[1], 0x4b);
    assert.equal(buf[2], 0x03);
    assert.equal(buf[3], 0x04);
  });

  await t.test('extracts files from a ZIP archive roundtrip', async () => {
    const f1 = new File([new TextEncoder().encode('Hello from doc 1')], 'docs/one.txt', { type: 'text/plain' });
    const f2 = new File([new TextEncoder().encode('Second file data')], 'images/sub/pic.png', { type: 'image/png' });

    const zip = await createZipArchive([
      { file: f1, path: 'docs/one.txt' },
      { file: f2, path: 'images/sub/pic.png' }
    ], 'bundle.zip');

    const extracted = await extractZipArchive(zip);
    assert.equal(extracted.length, 2);
    assert.equal(extracted[0].path, 'docs/one.txt');
    assert.equal(extracted[0].name, 'one.txt');
    assert.equal(new TextDecoder().decode(extracted[0].data), 'Hello from doc 1');

    assert.equal(extracted[1].path, 'images/sub/pic.png');
    assert.equal(extracted[1].name, 'pic.png');
    assert.equal(new TextDecoder().decode(extracted[1].data), 'Second file data');
  });

  await t.test('rejects empty file list', async () => {
    await assert.rejects(
      async () => createZipArchive([]),
      /fileList must be a non-empty array/i
    );
  });

  await t.test('sanitizes malicious Zip Slip paths and prevents directory traversal', async () => {
    const maliciousFile = new File([new TextEncoder().encode('evil data')], 'exploit.txt', { type: 'text/plain' });

    const zip = await createZipArchive([
      { file: maliciousFile, path: '../../../../etc/passwd' },
      { file: maliciousFile, path: 'normal/../../secret.env' },
      { file: maliciousFile, path: '/absolute/path/file.txt' }
    ], 'safe.zip');

    const extracted = await extractZipArchive(zip);
    assert.equal(extracted.length, 3);
    assert.equal(extracted[0].path, 'etc/passwd');
    assert.equal(extracted[0].name, 'passwd');

    assert.equal(extracted[1].path, 'normal/secret.env');
    assert.equal(extracted[1].name, 'secret.env');

    assert.equal(extracted[2].path, 'absolute/path/file.txt');
    assert.equal(extracted[2].name, 'file.txt');
  });
});
