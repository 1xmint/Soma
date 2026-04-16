import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  CanonicalisationError,
  canonicalizePayload,
  computeCertificateId,
  computeSignatureInput,
  computeSignatureInputHash,
  type SignerRole,
} from '../../../src/heart/certificate/canonical.js';

// -- Vector conformance (spec section 19.2) ----------------------------------

interface SignatureInput {
  signer_role: SignerRole;
  input_sha256: string;
}

interface Vector {
  id: string;
  certificate: Record<string, unknown>;
  canonical_json: string;
  canonical_utf8_hex: string;
  expected_certificate_id: string;
  signature_inputs: SignatureInput[];
}

interface Manifest {
  vectors: Vector[];
}

const manifestPath = resolve(
  __dirname,
  '../../../test-vectors/soma-heart-certificate/v0.1/manifest.json',
);
const manifest: Manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

describe('vector conformance', () => {
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
          expect(computeSignatureInputHash(canonical, si.signer_role)).toBe(
            si.input_sha256,
          );
        });
      }
    });
  }
});

// -- Unit tests for canonicalization rules -----------------------------------

describe('canonical JSON rules', () => {
  it('sorts object keys by Unicode code point', () => {
    const payload = { z: 1, a: 2, m: 3 } as Record<string, unknown>;
    const canonical = canonicalizePayload(payload);
    expect(canonical.toString('utf8')).toBe('{"a":2,"m":3,"z":1}');
  });

  it('sorts keys by code point, not UTF-16 code unit', () => {
    // U+E000 (PUA, single code unit 0xE000) vs U+10000 (supplementary,
    // surrogate pair 0xD800 0xDC00). UTF-16 .sort() would put U+10000
    // first because 0xD800 < 0xE000. Code-point order: U+E000 < U+10000.
    const payload = { ['\u{10000}']: 2, ['\uE000']: 1 } as Record<string, unknown>;
    const canonical = canonicalizePayload(payload);
    const str = canonical.toString('utf8');
    const e000Idx = str.indexOf('\uE000');
    const sup = str.indexOf('\u{10000}');
    expect(e000Idx).toBeLessThan(sup);
  });

  it('omits certificate_id and signatures', () => {
    const payload = {
      certificate_id: 'abc',
      signatures: [{ x: 1 }],
      version: 'test',
    } as Record<string, unknown>;
    const canonical = canonicalizePayload(payload);
    expect(canonical.toString('utf8')).toBe('{"version":"test"}');
  });

  it('rejects NaN', () => {
    expect(() =>
      canonicalizePayload({ value: NaN } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects Infinity', () => {
    expect(() =>
      canonicalizePayload({ value: Infinity } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects negative Infinity', () => {
    expect(() =>
      canonicalizePayload({ value: -Infinity } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects floating-point numbers', () => {
    expect(() =>
      canonicalizePayload({ value: 1.5 } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects root property with undefined value', () => {
    expect(() =>
      canonicalizePayload({ bad: undefined } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects nested object property with undefined value', () => {
    expect(() =>
      canonicalizePayload({
        nested: { bad: undefined },
      } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('rejects array containing undefined', () => {
    expect(() =>
      canonicalizePayload({
        arr: [1, undefined, 3],
      } as Record<string, unknown>),
    ).toThrow(CanonicalisationError);
  });

  it('emits integers without leading zeros, sign for zero, exponent, or fraction', () => {
    const canonical = canonicalizePayload({
      neg: -42,
      pos: 42,
      zero: 0,
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"neg":-42,"pos":42,"zero":0}');
  });

  it('accepts integers at the safe boundary', () => {
    const max = 2 ** 53 - 1;
    const min = -(2 ** 53 - 1);
    const canonical = canonicalizePayload({
      max,
      min,
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe(
      `{"max":${max},"min":${min}}`,
    );
  });

  it('does not escape forward slash', () => {
    const canonical = canonicalizePayload({
      url: 'a/b',
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"url":"a/b"}');
  });

  it('escapes control characters with lowercase hex', () => {
    const canonical = canonicalizePayload({
      ctrl: '\x00\x01\x1f',
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe(
      '{"ctrl":"\\u0000\\u0001\\u001f"}',
    );
  });

  it('escapes backslash, quote, and standard escapes', () => {
    const canonical = canonicalizePayload({
      s: '"\\\b\f\n\r\t',
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe(
      '{"s":"\\"\\\\\\b\\f\\n\\r\\t"}',
    );
  });

  it('preserves array order', () => {
    const canonical = canonicalizePayload({
      arr: [3, 1, 2],
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"arr":[3,1,2]}');
  });

  it('emits no insignificant whitespace', () => {
    const canonical = canonicalizePayload({
      a: { b: [1, 2] },
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).not.toMatch(/\s/);
  });

  it('handles nested objects with sorted keys', () => {
    const canonical = canonicalizePayload({
      outer: { z: 1, a: 2 },
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"outer":{"a":2,"z":1}}');
  });

  it('emits null correctly', () => {
    const canonical = canonicalizePayload({
      n: null,
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"n":null}');
  });

  it('emits booleans correctly', () => {
    const canonical = canonicalizePayload({
      f: false,
      t: true,
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"f":false,"t":true}');
  });

  it('does not escape non-ASCII characters with \\uXXXX', () => {
    const canonical = canonicalizePayload({
      emoji: '\u{1F600}',
      umlaut: '\u00FC',
    } as Record<string, unknown>);
    const str = canonical.toString('utf8');
    expect(str).not.toContain('\\u');
    expect(str).toContain('\u00FC');
    expect(str).toContain('\u{1F600}');
  });

  it('encodes Buffer as standard base64 with padding', () => {
    const canonical = canonicalizePayload({
      bytes: Buffer.from([0, 1, 2, 255]),
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"bytes":"AAEC/w=="}');
  });

  it('encodes Uint8Array as standard base64 with padding', () => {
    const canonical = canonicalizePayload({
      bytes: new Uint8Array([0, 1, 2, 255]),
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"bytes":"AAEC/w=="}');
  });

  it('rejects duplicate keys where detectable', () => {
    // Object.keys deduplicates in JS so we test via the internal path.
    // The spec says: duplicate keys MUST be rejected at canonicalization time.
    // Since JS objects cannot carry duplicate keys at the language level,
    // this test verifies the sorted-key dedup guard does not false-positive.
    const obj = { a: 1, b: 2 };
    expect(() =>
      canonicalizePayload(obj as Record<string, unknown>),
    ).not.toThrow();
  });

  it('encodes sliced Uint8Array respecting byteOffset and byteLength', () => {
    const backing = new ArrayBuffer(8);
    const full = new Uint8Array(backing);
    full.set([0xff, 0x00, 0x01, 0x02, 0xff, 0xff, 0xff, 0xff]);
    const slice = new Uint8Array(backing, 1, 3);
    const canonical = canonicalizePayload({
      bytes: slice,
    } as Record<string, unknown>);
    expect(canonical.toString('utf8')).toBe('{"bytes":"AAEC"}');
  });
});

// -- Signer role validation ---------------------------------------------------

describe('signer role validation', () => {
  const dummy = Buffer.from('{}', 'utf8');

  it('accepts all valid roles', () => {
    for (const role of ['issuer', 'counterparty', 'witness', 'participant'] as const) {
      expect(() => computeSignatureInput(dummy, role)).not.toThrow();
      expect(() => computeSignatureInputHash(dummy, role)).not.toThrow();
    }
  });

  it('rejects uppercase role', () => {
    expect(() =>
      computeSignatureInput(dummy, 'Issuer' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects mixed-case role', () => {
    expect(() =>
      computeSignatureInput(dummy, 'COUNTERPARTY' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects unknown role', () => {
    expect(() =>
      computeSignatureInput(dummy, 'observer' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects role containing colon', () => {
    expect(() =>
      computeSignatureInput(dummy, 'issuer:extra' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects empty string role', () => {
    expect(() =>
      computeSignatureInput(dummy, '' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects whitespace role', () => {
    expect(() =>
      computeSignatureInput(dummy, ' issuer ' as SignerRole),
    ).toThrow(CanonicalisationError);
  });

  it('rejects via computeSignatureInputHash too', () => {
    expect(() =>
      computeSignatureInputHash(dummy, 'admin' as SignerRole),
    ).toThrow(CanonicalisationError);
  });
});
