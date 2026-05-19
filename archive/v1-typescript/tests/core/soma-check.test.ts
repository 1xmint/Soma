import { describe, it, expect } from 'vitest';
import {
  SomaCheckHashStore,
  extractIfSomaHash,
  verifyDataHashConsistency,
  SOMA_CHECK_MIN_HASH_LENGTH,
} from '../../src/core/soma-check.js';

const VALID_HASH = 'a'.repeat(64); // 64-char hex — full SHA-256
const SHORT_HASH = 'abc123'; // only 6 chars — below minimum

describe('Hash length validation — SomaCheckHashStore.set', () => {
  it('accepts a hash at exactly the minimum length', () => {
    const store = new SomaCheckHashStore();
    const minHash = '0'.repeat(SOMA_CHECK_MIN_HASH_LENGTH);
    expect(() => store.set('key', minHash)).not.toThrow();
    expect(store.get('key')).toBe(minHash);
  });

  it('accepts a full SHA-256 hash', () => {
    const store = new SomaCheckHashStore();
    expect(() => store.set('url', VALID_HASH)).not.toThrow();
  });

  it('rejects a hash shorter than 16 hex chars', () => {
    const store = new SomaCheckHashStore();
    expect(() => store.set('url', SHORT_HASH)).toThrow(/at least 16 hex characters/);
  });

  it('rejects an empty string', () => {
    const store = new SomaCheckHashStore();
    expect(() => store.set('url', '')).toThrow(/at least 16 hex characters/);
  });

  it('rejects a non-hex string that is long enough', () => {
    const store = new SomaCheckHashStore();
    expect(() => store.set('url', 'g'.repeat(16))).toThrow(/at least 16 hex characters/);
  });

  it('does not store a rejected hash', () => {
    const store = new SomaCheckHashStore();
    try { store.set('url', SHORT_HASH); } catch { /* expected */ }
    expect(store.has('url')).toBe(false);
  });
});

describe('Hash length validation — extractIfSomaHash', () => {
  it('returns null when the header is absent', () => {
    expect(extractIfSomaHash({})).toBeNull();
    expect(extractIfSomaHash(null)).toBeNull();
  });

  it('returns the hash when it meets the minimum length', () => {
    const headers = { 'If-Soma-Hash': VALID_HASH };
    expect(extractIfSomaHash(headers)).toBe(VALID_HASH);
  });

  it('throws when the If-Soma-Hash value is shorter than 16 hex chars', () => {
    const headers = { 'If-Soma-Hash': SHORT_HASH };
    expect(() => extractIfSomaHash(headers)).toThrow(/at least 16 hex characters/);
  });

  it('is case-insensitive for the header name', () => {
    const headers = { 'if-soma-hash': VALID_HASH };
    expect(extractIfSomaHash(headers)).toBe(VALID_HASH);
  });
});

describe('verifyDataHashConsistency', () => {
  it('returns true when birth cert dataHash matches X-Soma-Hash', () => {
    expect(verifyDataHashConsistency(VALID_HASH, VALID_HASH)).toBe(true);
  });

  it('returns false when they differ', () => {
    const other = 'b'.repeat(64);
    expect(verifyDataHashConsistency(VALID_HASH, other)).toBe(false);
  });

  it('returns false for a partial match', () => {
    expect(verifyDataHashConsistency(VALID_HASH, VALID_HASH.slice(0, 32))).toBe(false);
  });

  it('returns false for empty vs non-empty', () => {
    expect(verifyDataHashConsistency('', VALID_HASH)).toBe(false);
    expect(verifyDataHashConsistency(VALID_HASH, '')).toBe(false);
  });
});
