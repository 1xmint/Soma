import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { SignerRole } from './canonical.js';

// Internal read-only helper for loading the v0.1 vector corpus.
// No public package export yet; used by conformance tests.

const VALID_SIGNER_ROLES: ReadonlySet<string> = new Set([
  'issuer',
  'counterparty',
  'witness',
  'participant',
]);

export interface VectorSignatureInput {
  signer_role: SignerRole;
  input_sha256: string;
}

export interface VectorVerifierPolicy {
  policy_id: string;
  accepted_claim_kinds: string[];
  accepted_evidence_kinds: string[];
  accepted_profiles: string[];
  fail_closed: boolean;
  max_chain_depth: number;
  require_rotation_lookup: boolean;
}

export interface Vector {
  id: string;
  certificate: Record<string, unknown>;
  canonical_json: string;
  canonical_utf8_hex: string;
  expected_certificate_id: string;
  expected_result: 'accept' | 'reject';
  expected_failure: string | null;
  signature_inputs: VectorSignatureInput[];
  verifier_policy: VectorVerifierPolicy;
  coverage: string[];
  notes: string;
}

export interface RotationFixtureIdentity {
  identity_id: string;
  credential_id: string;
  algorithm_suite: string;
  public_key_spki_der_base64: string;
  effective_at: number;
  revoked_at: number | null;
  rotation_event_hash: string;
}

export interface Manifest {
  schema: string;
  spec: string;
  generated_against: {
    canonical_encoding: string;
    certificate_id_domain_prefix: string;
    hash_algorithm: string;
    signature_input_prefix_template: string;
  };
  scope: string;
  coverage_summary: Record<string, string[]>;
  rotation_fixture: { identities: RotationFixtureIdentity[] };
  vectors: Vector[];
}

export class VectorLoadError extends Error {
  override readonly name = 'VectorLoadError';
}

export function loadManifest(repoRoot: string): Manifest {
  const path = resolve(
    repoRoot,
    'test-vectors/soma-heart-certificate/v0.1/manifest.json',
  );
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw new VectorLoadError(`cannot read manifest: ${path}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new VectorLoadError(
      `manifest is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  validateManifest(parsed);
  return parsed;
}

function validateManifest(m: unknown): asserts m is Manifest {
  if (m === null || typeof m !== 'object') {
    throw new VectorLoadError('manifest is not an object');
  }
  const obj = m as Record<string, unknown>;
  if (typeof obj.schema !== 'string') {
    throw new VectorLoadError('manifest.schema is not a string');
  }
  if (!Array.isArray(obj.vectors)) {
    throw new VectorLoadError('manifest.vectors is not an array');
  }
  for (let i = 0; i < obj.vectors.length; i++) {
    const entry: unknown = obj.vectors[i];
    if (entry === null || typeof entry !== 'object') {
      throw new VectorLoadError(
        `manifest.vectors[${i}] is not an object`,
      );
    }
    validateVector(entry as Record<string, unknown>, i);
  }
}

function validateVector(v: Record<string, unknown>, idx: number): void {
  const loc = `manifest.vectors[${idx}]`;
  if (typeof v.id !== 'string') {
    throw new VectorLoadError(`${loc}.id is not a string`);
  }
  if (v.certificate === null || typeof v.certificate !== 'object') {
    throw new VectorLoadError(`${loc}.certificate is not an object`);
  }
  if (typeof v.canonical_json !== 'string') {
    throw new VectorLoadError(`${loc}.canonical_json is not a string`);
  }
  if (typeof v.canonical_utf8_hex !== 'string') {
    throw new VectorLoadError(`${loc}.canonical_utf8_hex is not a string`);
  }
  if (typeof v.expected_certificate_id !== 'string') {
    throw new VectorLoadError(
      `${loc}.expected_certificate_id is not a string`,
    );
  }
  if (!Array.isArray(v.signature_inputs)) {
    throw new VectorLoadError(
      `${loc}.signature_inputs is not an array`,
    );
  }
  for (let j = 0; j < v.signature_inputs.length; j++) {
    const entry: unknown = v.signature_inputs[j];
    if (entry === null || typeof entry !== 'object') {
      throw new VectorLoadError(
        `${loc}.signature_inputs[${j}] is not an object`,
      );
    }
    const si = entry as Record<string, unknown>;
    if (typeof si.signer_role !== 'string') {
      throw new VectorLoadError(
        `${loc}.signature_inputs[${j}].signer_role is not a string`,
      );
    }
    if (!VALID_SIGNER_ROLES.has(si.signer_role)) {
      throw new VectorLoadError(
        `${loc}.signature_inputs[${j}].signer_role ` +
        `${JSON.stringify(si.signer_role)} is not a valid v0.1 role`,
      );
    }
    if (typeof si.input_sha256 !== 'string') {
      throw new VectorLoadError(
        `${loc}.signature_inputs[${j}].input_sha256 is not a string`,
      );
    }
  }
}
