import { describe, it, expect } from 'vitest';
import {
  validatePolicyRef,
  type PolicyRef,
} from '../../../src/heart/certificate/policy-ref.js';

describe('policy_ref shape validator (§12)', () => {
  it('accepts a valid policy_ref with all fields', () => {
    const ref: PolicyRef = {
      policy_id: 'soma-heart-policy:v0.1:strict',
      policy_hash: 'a'.repeat(64),
      policy_version: 'v0.1',
      policy_uri: 'https://example.com/policy',
    };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(true);
  });

  it('accepts a valid policy_ref with only policy_id', () => {
    const ref: PolicyRef = { policy_id: 'my-policy' };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(true);
  });

  it('rejects missing policy_id', () => {
    const ref = {} as PolicyRef;
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toMatch(/policy_id/);
    }
  });

  it('rejects empty string policy_id', () => {
    const ref: PolicyRef = { policy_id: '' };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toMatch(/policy_id/);
    }
  });

  it('rejects non-ASCII policy_id', () => {
    const ref: PolicyRef = { policy_id: 'policy-\u00E9' };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toMatch(/ASCII/);
    }
  });

  it('rejects policy_id with control characters', () => {
    const ref: PolicyRef = { policy_id: 'policy\x01id' };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
  });

  it('rejects policy_hash with wrong length', () => {
    const ref: PolicyRef = {
      policy_id: 'my-policy',
      policy_hash: 'abcdef',
    };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toMatch(/policy_hash/);
    }
  });

  it('rejects policy_hash with uppercase hex', () => {
    const ref: PolicyRef = {
      policy_id: 'my-policy',
      policy_hash: 'A'.repeat(64),
    };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.detail).toMatch(/policy_hash/);
    }
  });

  it('accepts valid lowercase SHA-256 policy_hash', () => {
    const ref: PolicyRef = {
      policy_id: 'my-policy',
      policy_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    };
    const result = validatePolicyRef(ref);
    expect(result.valid).toBe(true);
  });
});
