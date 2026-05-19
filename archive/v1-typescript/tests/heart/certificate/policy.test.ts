import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { FAILURE_MODES } from '../../../src/heart/certificate/failure-modes.js';
import { loadManifest } from '../../../src/heart/certificate/vectors.js';
import {
  evaluatePolicy,
  type VerifierPolicy,
  type PolicyCertificateInput,
} from '../../../src/heart/certificate/policy.js';

const repoRoot = resolve(__dirname, '../../..');
const manifest = loadManifest(repoRoot);

// Strict test-vector policy from the manifest.
const STRICT_POLICY: VerifierPolicy = {
  policy_id: 'soma-heart-policy:v0.1:test-vector-strict',
  accepted_profiles: ['birth', 'freshness-receipt-bound', 'heart-to-heart', 'one-sided'],
  accepted_claim_kinds: [
    'content_hash_commitment', 'credential_validity', 'endpoint_observation',
    'freshness_receipt', 'identity_control', 'payment_receipt_reference',
    'policy_statement',
  ],
  accepted_evidence_kinds: [
    'hash_commitment', 'payment_rail_receipt_reference', 'receipt_reference',
    'request_response_transcript_hash', 'signature', 'timestamp',
    'verifier_policy_reference',
  ],
  fail_closed: true,
  max_chain_depth: 2,
  require_rotation_lookup: true,
};

function certInput(cert: Record<string, unknown>): PolicyCertificateInput {
  return {
    profile: cert.profile as string,
    claim_set: cert.claim_set as { kind: string }[],
    evidence_references: cert.evidence_references as { kind: string }[],
    prior_certificate_ids: cert.prior_certificate_ids as string[] | undefined,
  };
}

// -- Vector-driven tests: accepted vectors pass policy ----------------------

describe('vector policy evaluation - accepted vectors', () => {
  const accepted = manifest.vectors.filter((v) => v.expected_result === 'accept');

  for (const vector of accepted) {
    it(`${vector.id} passes policy evaluation`, () => {
      const result = evaluatePolicy(
        STRICT_POLICY,
        certInput(vector.certificate),
      );
      expect(result.accepted).toBe(true);
    });
  }
});

// -- Vector-driven tests: rejected vocabulary vectors fail policy -----------

describe('vector policy evaluation - vocabulary rejections', () => {
  const vocabRejects = manifest.vectors.filter(
    (v) =>
      v.expected_result === 'reject' &&
      (v.expected_failure === 'profile-deferred' ||
        v.expected_failure === 'claim-deferred' ||
        v.expected_failure === 'evidence-deferred'),
  );

  for (const vector of vocabRejects) {
    it(`${vector.id} fails with ${vector.expected_failure}`, () => {
      const result = evaluatePolicy(
        STRICT_POLICY,
        certInput(vector.certificate),
      );
      expect(result.accepted).toBe(false);
      if (!result.accepted) {
        expect(result.violations[0].failureMode).toBe(vector.expected_failure);
      }
    });
  }
});

// -- Focused synthetic tests ------------------------------------------------

describe('policy evaluator - focused rejections', () => {
  const baseCert: PolicyCertificateInput = {
    profile: 'birth',
    claim_set: [{ kind: 'identity_control' }],
    evidence_references: [{ kind: 'signature' }],
  };

  it('rejects profile not in accepted_profiles', () => {
    const narrowPolicy = { ...STRICT_POLICY, accepted_profiles: ['one-sided'] };
    const result = evaluatePolicy(narrowPolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.PROFILE_NOT_ALLOWED,
      );
    }
  });

  it('rejects deferred profile (policy-statement)', () => {
    const cert = { ...baseCert, profile: 'policy-statement' };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.PROFILE_DEFERRED,
      );
    }
  });

  it('rejects unknown profile', () => {
    const cert = { ...baseCert, profile: 'totally-made-up' };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.PROFILE_NOT_ALLOWED,
      );
    }
  });

  it('rejects claim kind not in accepted_claim_kinds', () => {
    const narrowPolicy = { ...STRICT_POLICY, accepted_claim_kinds: ['freshness_receipt'] };
    const result = evaluatePolicy(narrowPolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_NOT_ALLOWED,
      );
    }
  });

  it('rejects deferred claim kind (capability_statement)', () => {
    const cert = {
      ...baseCert,
      claim_set: [{ kind: 'capability_statement' }],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_DEFERRED,
      );
    }
  });

  it('rejects unknown claim kind', () => {
    const cert = {
      ...baseCert,
      claim_set: [{ kind: 'invented_claim' }],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_NOT_ALLOWED,
      );
    }
  });

  it('rejects evidence kind not in accepted_evidence_kinds', () => {
    const narrowPolicy = {
      ...STRICT_POLICY,
      accepted_evidence_kinds: ['timestamp'],
    };
    const result = evaluatePolicy(narrowPolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
      );
    }
  });

  it('rejects deferred evidence kind (credential_presentation_reference)', () => {
    const cert = {
      ...baseCert,
      evidence_references: [{ kind: 'credential_presentation_reference' }],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_DEFERRED,
      );
    }
  });

  it('rejects unknown evidence kind', () => {
    const cert = {
      ...baseCert,
      evidence_references: [{ kind: 'invented_evidence' }],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
      );
    }
  });

  it('rejects open evidence kind (observation_log_reference)', () => {
    const cert = {
      ...baseCert,
      evidence_references: [{ kind: 'observation_log_reference' }],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
      );
    }
  });

  it('rejects missing claim_set', () => {
    const cert = {
      ...baseCert,
      claim_set: [] as { kind: string }[],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_NOT_ALLOWED,
      );
    }
  });

  it('rejects missing evidence_references', () => {
    const cert = {
      ...baseCert,
      evidence_references: [] as { kind: string }[],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_MISSING,
      );
    }
  });

  it('rejects prior_certificate_ids exceeding max_chain_depth', () => {
    const cert = {
      ...baseCert,
      prior_certificate_ids: ['cert-a', 'cert-b', 'cert-c'],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
      );
    }
  });

  it('accepts prior_certificate_ids within max_chain_depth', () => {
    const cert = {
      ...baseCert,
      prior_certificate_ids: ['cert-a', 'cert-b'],
    };
    const result = evaluatePolicy(STRICT_POLICY, cert);
    expect(result.accepted).toBe(true);
  });

  it('accepts absent prior_certificate_ids (depth 0)', () => {
    const result = evaluatePolicy(STRICT_POLICY, baseCert);
    expect(result.accepted).toBe(true);
  });
});

// -- Fail-closed discipline --------------------------------------------------

describe('policy evaluator - fail-closed discipline', () => {
  const baseCert: PolicyCertificateInput = {
    profile: 'birth',
    claim_set: [{ kind: 'identity_control' }],
    evidence_references: [{ kind: 'signature' }],
  };

  it('rejects fail_closed: false in v0.1', () => {
    const openPolicy = { ...STRICT_POLICY, fail_closed: false };
    const result = evaluatePolicy(openPolicy, baseCert);
    expect(result.accepted).toBe(false);
  });

  it('absent policy field does not default to accept (missing accepted_profiles item)', () => {
    const emptyProfilePolicy = {
      ...STRICT_POLICY,
      accepted_profiles: [] as string[],
    };
    const result = evaluatePolicy(emptyProfilePolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.PROFILE_NOT_ALLOWED,
      );
    }
  });

  it('absent policy field does not default to accept (missing accepted_claim_kinds item)', () => {
    const emptyClaimPolicy = {
      ...STRICT_POLICY,
      accepted_claim_kinds: [] as string[],
    };
    const result = evaluatePolicy(emptyClaimPolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_NOT_ALLOWED,
      );
    }
  });

  it('absent policy field does not default to accept (missing accepted_evidence_kinds item)', () => {
    const emptyEvPolicy = {
      ...STRICT_POLICY,
      accepted_evidence_kinds: [] as string[],
    };
    const result = evaluatePolicy(emptyEvPolicy, baseCert);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_NOT_ALLOWED,
      );
    }
  });

  it('rejects undefined claim_set (malformed runtime input)', () => {
    const malformed = {
      profile: 'birth',
      evidence_references: [{ kind: 'signature' }],
    } as unknown as PolicyCertificateInput;
    const result = evaluatePolicy(STRICT_POLICY, malformed);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.CLAIM_NOT_ALLOWED,
      );
    }
  });

  it('rejects undefined evidence_references (malformed runtime input)', () => {
    const malformed = {
      profile: 'birth',
      claim_set: [{ kind: 'identity_control' }],
    } as unknown as PolicyCertificateInput;
    const result = evaluatePolicy(STRICT_POLICY, malformed);
    expect(result.accepted).toBe(false);
    if (!result.accepted) {
      expect(result.violations[0].failureMode).toBe(
        FAILURE_MODES.EVIDENCE_MISSING,
      );
    }
  });
});
