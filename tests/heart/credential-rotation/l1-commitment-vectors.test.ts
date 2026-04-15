/**
 * L1 commitment test vectors (SOMA-ROTATION-SPEC.md §3.3 / §15 item 6).
 *
 * Loads the JSON vectors from `vectors/l1-commitment.json` and verifies
 * that `computeManifestCommitment` reproduces each committed digest
 * exactly. Also cross-checks the four §3.3 requirements:
 *   1. Fixed triple → known digest.
 *   2. Same publicKey, different algorithmSuite → different digests.
 *   3. Same publicKey, different backendId → different digests.
 *   4. Base64 padding correctness across all three residue classes.
 *
 * These are conformance vectors, not round-trip tests: the expected
 * `commitment` fields are hardcoded in the JSON so any silent drift in
 * the encoder, hash, or base64 path breaks the build.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { describe, it, expect } from 'vitest';

import {
  computeManifestCommitment,
  type AlgorithmSuite,
  type CredentialManifest,
} from '../../../src/heart/credential-rotation/index.js';
import { getCryptoProvider } from '../../../src/core/crypto-provider.js';

interface Vector {
  name: string;
  description: string;
  backendId: string;
  algorithmSuite: AlgorithmSuite;
  publicKeyHex: string;
  publicKeyBase64: string;
  input: string;
  commitment: string;
}

interface VectorFile {
  hashAlgorithm: string;
  encoding: string;
  vectors: Vector[];
}

const provider = getCryptoProvider();

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, 'vectors/l1-commitment.json');
const file: VectorFile = JSON.parse(readFileSync(vectorsPath, 'utf8'));

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`odd-length hex: ${hex}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toManifest(v: Vector): CredentialManifest {
  return {
    backendId: v.backendId,
    algorithmSuite: v.algorithmSuite,
    publicKey: hexToBytes(v.publicKeyHex),
  };
}

describe('L1 commitment test vectors (§3.3 / §15.6)', () => {
  it('vector file declares the canonical hash and encoding', () => {
    expect(file.hashAlgorithm).toBe('sha256');
    expect(file.encoding).toBe(
      'soma-manifest:<backendId>|<algorithmSuite>|<base64(publicKey)>',
    );
    expect(file.vectors.length).toBeGreaterThanOrEqual(7);
  });

  it.each(file.vectors)(
    'reproduces commitment for vector "$name"',
    (v: Vector) => {
      const manifest = toManifest(v);
      const digest = computeManifestCommitment(manifest, provider);
      expect(digest).toBe(v.commitment);
    },
  );

  it('reproduces base64 encoding for every vector', () => {
    for (const v of file.vectors) {
      const encoded = provider.encoding.encodeBase64(hexToBytes(v.publicKeyHex));
      expect(encoded).toBe(v.publicKeyBase64);
    }
  });

  it('reproduces the pre-hash input string for every vector', () => {
    for (const v of file.vectors) {
      const rebuilt = `soma-manifest:${v.backendId}|${v.algorithmSuite}|${v.publicKeyBase64}`;
      expect(rebuilt).toBe(v.input);
    }
  });

  it('§3.3 case 2 — cross-suite distinguishability', () => {
    const zero = file.vectors.find(v => v.name === 'baseline-zero-key');
    const crossSuite = file.vectors.find(
      v => v.name === 'cross-suite-distinguishability',
    );
    expect(zero).toBeDefined();
    expect(crossSuite).toBeDefined();
    expect(zero!.publicKeyHex).toBe(crossSuite!.publicKeyHex);
    expect(zero!.backendId).toBe(crossSuite!.backendId);
    expect(zero!.algorithmSuite).not.toBe(crossSuite!.algorithmSuite);
    expect(zero!.commitment).not.toBe(crossSuite!.commitment);
  });

  it('§3.3 case 3 — cross-backend distinguishability', () => {
    const zero = file.vectors.find(v => v.name === 'baseline-zero-key');
    const crossBackend = file.vectors.find(
      v => v.name === 'cross-backend-distinguishability',
    );
    expect(zero).toBeDefined();
    expect(crossBackend).toBeDefined();
    expect(zero!.publicKeyHex).toBe(crossBackend!.publicKeyHex);
    expect(zero!.algorithmSuite).toBe(crossBackend!.algorithmSuite);
    expect(zero!.backendId).not.toBe(crossBackend!.backendId);
    expect(zero!.commitment).not.toBe(crossBackend!.commitment);
  });

  it('§3.3 case 4 — base64 padding covers residues 0, 1, and 2', () => {
    const r0 = file.vectors.find(v => v.name === 'base64-padding-residue-0');
    const r1 = file.vectors.find(v => v.name === 'base64-padding-residue-1');
    const r2 = file.vectors.find(v => v.name === 'base64-padding-residue-2');
    expect(r0).toBeDefined();
    expect(r1).toBeDefined();
    expect(r2).toBeDefined();
    const len = (hex: string) => hex.length / 2;
    expect(len(r0!.publicKeyHex) % 3).toBe(0);
    expect(len(r1!.publicKeyHex) % 3).toBe(1);
    expect(len(r2!.publicKeyHex) % 3).toBe(2);
    // residue 0 → no '=' pad; residue 1 → '=='; residue 2 → '='.
    expect(r0!.publicKeyBase64.endsWith('=')).toBe(false);
    expect(r1!.publicKeyBase64.endsWith('==')).toBe(true);
    expect(r2!.publicKeyBase64.endsWith('=')).toBe(true);
    expect(r2!.publicKeyBase64.endsWith('==')).toBe(false);
  });
});
