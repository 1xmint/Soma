/**
 * backendId delimiter validation (SOMA-ROTATION-SPEC.md §3.2 / §15 item 7).
 *
 * §3.2 forbids `|` (U+007C), `:` (U+003A), and NUL (U+0000) inside any
 * backendId because the canonical commitment encoder uses those bytes as
 * structural delimiters or reserves them for forward-compatible encoding
 * extensions. §15 item 7 requires rejection to happen before the backend
 * is admitted to the `backendAllowlist`, via a clear typed error.
 *
 * v0.1 raises bare `InvariantViolation(9)` rather than a dedicated
 * subclass because SOMA-ROTATION-SPEC.md §11 forbids adding new
 * `InvariantViolation` subclasses without a superseding ADR. Invariant 9
 * is the semantic attachment point: the delimiter rule exists to defend
 * pre-rotation commitment integrity, even though the enforcement site
 * is allowlist admission.
 */

import { describe, it, expect } from 'vitest';

import {
  CredentialRotationController,
  DEFAULT_POLICY,
  InvariantViolation,
  MockCredentialBackend,
  type ControllerPolicy,
} from '../../../src/heart/credential-rotation/index.js';

function policyWithAllowlist(allowlist: readonly string[]): ControllerPolicy {
  return { ...DEFAULT_POLICY, backendAllowlist: allowlist };
}

const FORBIDDEN: readonly { label: string; char: string; fragment: string }[] = [
  { label: "'|' (U+007C)", char: '|', fragment: "'|' (U+007C)" },
  { label: "':' (U+003A)", char: ':', fragment: "':' (U+003A)" },
  { label: 'NUL (U+0000)', char: '\u0000', fragment: 'NUL (U+0000)' },
];

describe('backendId delimiter validation (§3.2 / §15.7)', () => {
  describe('validatePolicy rejects malformed allowlist entries', () => {
    it.each(FORBIDDEN)(
      'rejects %s inside a backendAllowlist entry',
      ({ char, fragment }) => {
        const bad = `bad${char}id`;
        let thrown: unknown;
        try {
          new CredentialRotationController({
            policy: policyWithAllowlist([bad]),
          });
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(InvariantViolation);
        const err = thrown as InvariantViolation;
        expect(err.invariant).toBe(9);
        expect(err.message).toContain(fragment);
        expect(err.message).toContain('§3.2');
      },
    );

    it('rejects delimiter bytes at the start of the id', () => {
      expect(() =>
        new CredentialRotationController({
          policy: policyWithAllowlist(['|leading']),
        }),
      ).toThrow(InvariantViolation);
    });

    it('rejects delimiter bytes at the end of the id', () => {
      expect(() =>
        new CredentialRotationController({
          policy: policyWithAllowlist(['trailing:']),
        }),
      ).toThrow(InvariantViolation);
    });

    it('rejects when the forbidden byte sits in a later allowlist entry', () => {
      let thrown: unknown;
      try {
        new CredentialRotationController({
          policy: policyWithAllowlist(['good', 'also-good', 'bad\u0000id']),
        });
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeInstanceOf(InvariantViolation);
      expect((thrown as InvariantViolation).invariant).toBe(9);
    });

    it('accepts allowlist entries that contain only permitted bytes', () => {
      expect(() =>
        new CredentialRotationController({
          policy: policyWithAllowlist(['soma-heart-ed25519', 'mock-a', 'backend_42']),
        }),
      ).not.toThrow();
    });
  });

  describe('registerBackend rejects malformed backend instances', () => {
    it.each(FORBIDDEN)(
      'rejects a backend instance whose backendId contains %s',
      ({ char, fragment }) => {
        // The allowlist is well-formed; the defense-in-depth check fires
        // on the instance-level backendId. We use a bypass policy that
        // lists *some* valid id so the constructor succeeds, then try to
        // register a backend whose actual `backendId` is malformed.
        const controller = new CredentialRotationController({
          policy: policyWithAllowlist(['mock-a']),
        });
        const backend = new MockCredentialBackend({
          backendId: `bad${char}id`,
        });
        let thrown: unknown;
        try {
          controller.registerBackend(backend);
        } catch (err) {
          thrown = err;
        }
        expect(thrown).toBeInstanceOf(InvariantViolation);
        const err = thrown as InvariantViolation;
        expect(err.invariant).toBe(9);
        expect(err.message).toContain(fragment);
        expect(err.message).toContain('§3.2');
      },
    );

    it('still accepts a well-formed backend id', () => {
      const controller = new CredentialRotationController({
        policy: policyWithAllowlist(['mock-a']),
      });
      expect(() =>
        controller.registerBackend(new MockCredentialBackend({ backendId: 'mock-a' })),
      ).not.toThrow();
    });
  });

  it('does NOT use BackendNotAllowlisted for the malformed-id case', () => {
    // If a reader greps for BackendNotAllowlisted expecting to find the
    // delimiter-rejection site, this test is the pin that says the
    // rejection is intentionally raised as bare InvariantViolation(9),
    // per SOMA-ROTATION-SPEC.md §11 (no new InvariantViolation
    // subclasses without a superseding ADR).
    let thrown: unknown;
    try {
      new CredentialRotationController({
        policy: policyWithAllowlist(['bad|id']),
      });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(InvariantViolation);
    expect((thrown as InvariantViolation).name).toBe('InvariantViolation');
    expect((thrown as InvariantViolation).constructor.name).toBe(
      'InvariantViolation',
    );
  });
});
