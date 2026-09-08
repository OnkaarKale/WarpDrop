/**
 * Phase 7 Performance Benchmark Suite.
 * Measures duration, throughput (MB/s), and memory consumption (heap/RSS)
 * for 10 MB and 50 MB authenticated, encrypted transfers.
 */

import { performance } from 'node:perf_hooks';
import process from 'node:process';
import {
  generateSessionKeyPair,
  exportPublicKey,
  importPeerPublicKey,
  deriveSharedSecretBits
} from '../src/crypto/keyExchange.js';
import { deriveSessionKeys } from '../src/crypto/kdf.js';
import { FileChunker } from '../src/protocol/chunker.js';
import { FileReassembler } from '../src/protocol/reassembler.js';

async function setupCryptoChannel(sessionId = 'benchmark-session') {
  const alicePair = await generateSessionKeyPair();
  const bobPair = await generateSessionKeyPair();

  const alicePub = await exportPublicKey(alicePair.publicKey);
  const bobPub = await exportPublicKey(bobPair.publicKey);

  const aliceImportedBob = await importPeerPublicKey(bobPub);
  const bobImportedAlice = await importPeerPublicKey(alicePub);

  const aliceSecret = await deriveSharedSecretBits(alicePair.privateKey, aliceImportedBob);
  const bobSecret = await deriveSharedSecretBits(bobPair.privateKey, bobImportedAlice);

  const aliceKeys = await deriveSessionKeys({
    sharedSecretBits: aliceSecret,
    sessionId,
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: true
  });

  const bobKeys = await deriveSessionKeys({
    sharedSecretBits: bobSecret,
    sessionId,
    initiatorPubKey: alicePub,
    responderPubKey: bobPub,
    isInitiator: false
  });

  return { aliceKeys, bobKeys };
}

function getMemoryUsageMB() {
  const mem = process.memoryUsage();
  return {
    rss: (mem.rss / (1024 * 1024)).toFixed(2),
    heapUsed: (mem.heapUsed / (1024 * 1024)).toFixed(2),
    heapTotal: (mem.heapTotal / (1024 * 1024)).toFixed(2)
  };
}

async function runBenchmark(sizeMB, chunkSize = 64 * 1024) {
  const byteLength = sizeMB * 1024 * 1024;
  console.log(`\n========================================`);
  console.log(`Starting Benchmark: ${sizeMB} MB Transfer (Chunk Size: ${chunkSize / 1024} KB)`);
  console.log(`========================================`);

  const memBefore = getMemoryUsageMB();
  console.log(`[Memory Before] Heap Used: ${memBefore.heapUsed} MB | Heap Total: ${memBefore.heapTotal} MB | RSS: ${memBefore.rss} MB`);

  const { aliceKeys, bobKeys } = await setupCryptoChannel(`benchmark-${sizeMB}mb`);

  // Generate synthetic payload
  const payload = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i += 4096) {
    payload[i] = (i * 17) % 256;
  }

  const chunker = new FileChunker({
    file: payload,
    fileName: `benchmark_${sizeMB}mb.bin`,
    chunkSize,
    key: aliceKeys.outboundKey,
    staticIv: aliceKeys.outboundStaticIv
  });

  const manifest = await chunker.getManifest();
  const reassembler = new FileReassembler({
    manifest,
    key: bobKeys.inboundKey,
    staticIv: bobKeys.inboundStaticIv
  });
  reassembler.approve();

  let maxHeapDuring = 0;
  let maxRssDuring = 0;

  const tStart = performance.now();
  let chunkCount = 0;

  while (chunker.hasMoreChunks()) {
    const chunkFrame = await chunker.nextChunk();
    await reassembler.receiveChunk(chunkFrame);
    chunkCount++;

    if (chunkCount % 50 === 0) {
      const memCurrent = process.memoryUsage();
      const currentHeapMB = memCurrent.heapUsed / (1024 * 1024);
      const currentRssMB = memCurrent.rss / (1024 * 1024);
      if (currentHeapMB > maxHeapDuring) maxHeapDuring = currentHeapMB;
      if (currentRssMB > maxRssDuring) maxRssDuring = currentRssMB;
    }
  }

  const result = await reassembler.finalize();
  const tEnd = performance.now();

  const elapsedSec = (tEnd - tStart) / 1000;
  const throughputMBs = sizeMB / elapsedSec;

  const memAfter = getMemoryUsageMB();
  console.log(`[Result] Verified: ${result.verified}`);
  console.log(`[Duration] ${elapsedSec.toFixed(3)} seconds`);
  console.log(`[Throughput] ${throughputMBs.toFixed(2)} MB/s`);
  console.log(`[Peak Heap During] ${maxHeapDuring.toFixed(2)} MB`);
  console.log(`[Peak RSS During] ${maxRssDuring.toFixed(2)} MB`);
  console.log(`[Memory After] Heap Used: ${memAfter.heapUsed} MB | Heap Total: ${memAfter.heapTotal} MB | RSS: ${memAfter.rss} MB`);

  return {
    sizeMB,
    chunkSize,
    chunks: chunkCount,
    elapsedSec: elapsedSec.toFixed(3),
    throughputMBs: throughputMBs.toFixed(2),
    memBefore,
    memPeak: { heap: maxHeapDuring.toFixed(2), rss: maxRssDuring.toFixed(2) },
    memAfter
  };
}

async function main() {
  console.log('Running Transfer Performance Benchmarks...');
  const res10MB = await runBenchmark(10);
  const res50MB = await runBenchmark(50);

  console.log('\n========================================');
  console.log('           BENCHMARK SUMMARY            ');
  console.log('========================================');
  console.table([
    {
      Size: '10 MB',
      Duration: `${res10MB.elapsedSec} s`,
      Throughput: `${res10MB.throughputMBs} MB/s`,
      PeakHeap: `${res10MB.memPeak.heap} MB`,
      PeakRSS: `${res10MB.memPeak.rss} MB`
    },
    {
      Size: '50 MB',
      Duration: `${res50MB.elapsedSec} s`,
      Throughput: `${res50MB.throughputMBs} MB/s`,
      PeakHeap: `${res50MB.memPeak.heap} MB`,
      PeakRSS: `${res50MB.memPeak.rss} MB`
    }
  ]);
}

main().catch(console.error);
