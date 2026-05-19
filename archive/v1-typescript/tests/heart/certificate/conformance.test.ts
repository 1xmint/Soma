import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  canonicalizePayload,
  computeCertificateId,
  computeSignatureInputHash,
} from '../../../src/heart/certificate/canonical.js';
import {
  loadManifest,
  VectorLoadError,
} from '../../../src/heart/certificate/vectors.js';

// Spec section 19.2: normative vector conformance.
// Every entry in the v0.1 manifest is tested with no skips,
// no xfail, and no conditional branches that mask a failure.

const repoRoot = resolve(__dirname, '../../..');
const manifest = loadManifest(repoRoot);

describe('manifest shape', () => {
  it('has schema soma-heart-certificate-vectors/0.1', () => {
    expect(manifest.schema).toBe('soma-heart-certificate-vectors/0.1');
  });

  it('has at least one vector', () => {
    expect(manifest.vectors.length).toBeGreaterThan(0);
  });

  it('every vector has a non-empty id', () => {
    for (const v of manifest.vectors) {
      expect(v.id).toBeTruthy();
    }
  });

  it('every vector has at least one signature_input entry', () => {
    for (const v of manifest.vectors) {
      expect(v.signature_inputs.length).toBeGreaterThan(0);
    }
  });

  it('vector ids are unique', () => {
    const ids = manifest.vectors.map((v) => v.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('v0.1 vector conformance', () => {
  for (const vector of manifest.vectors) {
    describe(vector.id, () => {
      const canonical = canonicalizePayload(
        vector.certificate as Record<string, unknown>,
      );

      it('canonical_json matches', () => {
        expect(canonical.toString('utf8')).toBe(vector.canonical_json);
      });

      it('canonical_utf8_hex matches', () => {
        expect(canonical.toString('hex')).toBe(vector.canonical_utf8_hex);
      });

      it('expected_certificate_id matches', () => {
        expect(computeCertificateId(canonical)).toBe(
          vector.expected_certificate_id,
        );
      });

      for (const si of vector.signature_inputs) {
        it(`signature_input sha256 matches for role ${si.signer_role}`, () => {
          expect(
            computeSignatureInputHash(canonical, si.signer_role),
          ).toBe(si.input_sha256);
        });
      }
    });
  }
});

// -- Loader failure tests ----------------------------------------------------

describe('loadManifest failure handling', () => {
  function withTmpManifest(content: string, fn: (root: string) => void) {
    const root = mkdtempSync(resolve(tmpdir(), 'soma-vec-'));
    const dir = resolve(
      root,
      'test-vectors/soma-heart-certificate/v0.1',
    );
    mkdirSync(dir, { recursive: true });
    writeFileSync(resolve(dir, 'manifest.json'), content, 'utf8');
    try {
      fn(root);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  it('rejects invalid JSON', () => {
    withTmpManifest('not json {{{', (root) => {
      expect(() => loadManifest(root)).toThrow(VectorLoadError);
    });
  });

  it('rejects null vector entry', () => {
    const m = JSON.stringify({
      schema: 'test',
      vectors: [null],
    });
    withTmpManifest(m, (root) => {
      expect(() => loadManifest(root)).toThrow(VectorLoadError);
      expect(() => loadManifest(root)).toThrow(
        /vectors\[0\] is not an object/,
      );
    });
  });

  it('rejects null signature_input entry', () => {
    const m = JSON.stringify({
      schema: 'test',
      vectors: [
        {
          id: 'v1',
          certificate: {},
          canonical_json: '',
          canonical_utf8_hex: '',
          expected_certificate_id: '',
          signature_inputs: [null],
        },
      ],
    });
    withTmpManifest(m, (root) => {
      expect(() => loadManifest(root)).toThrow(VectorLoadError);
      expect(() => loadManifest(root)).toThrow(
        /signature_inputs\[0\] is not an object/,
      );
    });
  });

  it('rejects invalid signer role', () => {
    const m = JSON.stringify({
      schema: 'test',
      vectors: [
        {
          id: 'v1',
          certificate: {},
          canonical_json: '',
          canonical_utf8_hex: '',
          expected_certificate_id: '',
          signature_inputs: [
            { signer_role: 'admin', input_sha256: 'abc' },
          ],
        },
      ],
    });
    withTmpManifest(m, (root) => {
      expect(() => loadManifest(root)).toThrow(VectorLoadError);
      expect(() => loadManifest(root)).toThrow(/not a valid v0\.1 role/);
    });
  });
});
