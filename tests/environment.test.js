import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import QRCode from 'qrcode';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

test('Environment & Project Structure Scaffolding', async (t) => {
  await t.test('verifies required project directories exist', () => {
    // Arrange
    const requiredDirs = [
      'server',
      'src/crypto',
      'src/protocol',
      'src/transport',
      'public',
      'tests'
    ];

    // Act & Assert
    for (const dir of requiredDirs) {
      const fullPath = path.join(rootDir, dir);
      assert.ok(fs.existsSync(fullPath), `Directory ${dir} should exist`);
      assert.ok(fs.statSync(fullPath).isDirectory(), `${dir} should be a directory`);
    }
  });

  await t.test('verifies package.json configuration', () => {
    // Arrange
    const pkgPath = path.join(rootDir, 'package.json');

    // Act
    assert.ok(fs.existsSync(pkgPath), 'package.json should exist');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

    // Assert
    assert.equal(pkg.type, 'module', 'package.json must specify "type": "module"');
    assert.ok(pkg.dependencies.ws, 'ws dependency should be present');
    assert.ok(pkg.dependencies.qrcode, 'qrcode dependency should be present');
  });

  await t.test('verifies required dependencies can be loaded', async () => {
    // Arrange & Act
    assert.equal(typeof WebSocket, 'function', 'WebSocket from ws should be a constructor');
    assert.equal(typeof QRCode.toString, 'function', 'QRCode.toString should be a function');

    const qrText = await QRCode.toString('test-pairing-token', { type: 'utf8' });

    // Assert
    assert.ok(qrText.length > 0, 'QRCode should generate output string');
  });
});

test('Platform Cryptographic Capability Verification', async (t) => {
  await t.test('verifies Web Crypto API availability and random generation', () => {
    // Arrange & Act
    const subtle = globalThis.crypto?.subtle;
    const randomBuffer = new Uint8Array(16);
    globalThis.crypto.getRandomValues(randomBuffer);

    // Assert
    assert.ok(subtle, 'globalThis.crypto.subtle must be defined');
    assert.ok(randomBuffer.some((byte) => byte !== 0), 'getRandomValues should populate non-zero random bytes');
  });

  await t.test('verifies ECDH key agreement capability (P-256)', async () => {
    // Arrange
    const subtle = globalThis.crypto.subtle;

    // Act
    const keyPair = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    // Assert
    assert.ok(keyPair.publicKey, 'ECDH public key should be generated');
    assert.ok(keyPair.privateKey, 'ECDH private key should be generated');
    assert.equal(keyPair.publicKey.algorithm.name, 'ECDH');
  });

  await t.test('verifies HKDF derivation capability', async () => {
    // Arrange
    const subtle = globalThis.crypto.subtle;
    const rawKeyMaterial = new Uint8Array(32);
    globalThis.crypto.getRandomValues(rawKeyMaterial);

    const baseKey = await subtle.importKey(
      'raw',
      rawKeyMaterial,
      'HKDF',
      false,
      ['deriveKey']
    );

    // Act
    const derivedAesKey = await subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(16),
        info: new TextEncoder().encode('file-transfer-test')
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    // Assert
    assert.ok(derivedAesKey, 'HKDF should derive AES-GCM key');
    assert.equal(derivedAesKey.algorithm.name, 'AES-GCM');
  });

  await t.test('verifies AES-256-GCM authenticated encryption & decryption', async () => {
    // Arrange
    const subtle = globalThis.crypto.subtle;
    const rawKey = new Uint8Array(32);
    globalThis.crypto.getRandomValues(rawKey);

    const key = await subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );

    const iv = new Uint8Array(12); // 96-bit standard GCM nonce
    globalThis.crypto.getRandomValues(iv);
    const plaintext = new TextEncoder().encode('Confidential P2P Payload');

    // Act
    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext
    );

    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    // Assert
    assert.equal(
      new TextDecoder().decode(decrypted),
      'Confidential P2P Payload',
      'Decrypted text must match plaintext exactly'
    );
  });

  await t.test('verifies SHA-256 digest computation for file integrity', async () => {
    // Arrange
    const subtle = globalThis.crypto.subtle;
    const data = new TextEncoder().encode('hello world');

    // Act
    const digest = await subtle.digest('SHA-256', data);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // Assert - known SHA-256 of "hello world"
    assert.equal(
      hex,
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    );
  });
});
