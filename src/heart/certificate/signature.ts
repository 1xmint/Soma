import { verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { computeSignatureInput, type SignerRole } from './canonical.js';
import { FAILURE_MODES, type FailureMode } from './failure-modes.js';

// SPKI DER prefix for Ed25519 (12 bytes) matching crypto-provider.ts.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SPKI_ED25519_TOTAL = 44; // 12 prefix + 32 key

const VALID_ROLES: ReadonlySet<string> = new Set<SignerRole>([
  'issuer',
  'counterparty',
  'witness',
  'participant',
]);

export interface CredentialRotationReference {
  readonly identity_id: string;
  readonly credential_id: string;
  readonly rotation_event_hash: string;
}

export interface CertificateSignatureEntry {
  readonly signer_role: string;
  readonly identity_id: string;
  readonly credential_rotation_reference: CredentialRotationReference;
  readonly signature_bytes: string;
}

export interface ResolvedCredential {
  readonly credential_id: string;
  readonly identity_id: string;
  readonly algorithm_suite: string;
  readonly public_key_spki_der_base64: string;
  readonly effective_at: number;
  readonly revoked_at: number | null;
}

export interface CredentialLookupHit {
  readonly found: true;
  readonly credential: ResolvedCredential;
}

export interface CredentialLookupMiss {
  readonly found: false;
  readonly reason: 'unknown-identity' | 'credential-not-in-chain';
}

export type CredentialLookupResult = CredentialLookupHit | CredentialLookupMiss;

export interface CredentialLookup {
  resolve(ref: CredentialRotationReference): CredentialLookupResult;
}

export interface SignatureVerifyOk {
  readonly valid: true;
  readonly signer_role: SignerRole;
}

export interface SignatureVerifyFail {
  readonly valid: false;
  readonly failureMode: FailureMode;
  readonly signer_role: string;
}

export type SignatureVerifyResult = SignatureVerifyOk | SignatureVerifyFail;

export function verifyCertificateSignature(
  canonicalBytes: Buffer,
  sig: CertificateSignatureEntry,
  issuedAt: number,
  lookup: CredentialLookup,
): SignatureVerifyResult {
  if (!VALID_ROLES.has(sig.signer_role)) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      signer_role: sig.signer_role,
    };
  }
  const role = sig.signer_role as SignerRole;

  // Guard: issuedAt must be a finite integer for lifecycle comparison.
  if (!Number.isFinite(issuedAt) || !Number.isInteger(issuedAt)) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      signer_role: role,
    };
  }

  // Binding: sig.identity_id must match the credential rotation reference.
  if (sig.identity_id !== sig.credential_rotation_reference.identity_id) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }

  let resolved: CredentialLookupResult;
  try {
    resolved = lookup.resolve(sig.credential_rotation_reference);
  } catch {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }
  if (!resolved.found) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }

  const cred = resolved.credential;

  // Binding: resolved credential must match the rotation reference identity/credential.
  if (
    cred.identity_id !== sig.credential_rotation_reference.identity_id ||
    cred.credential_id !== sig.credential_rotation_reference.credential_id
  ) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }

  // Algorithm suite: v0.1 only supports ed25519.
  if (cred.algorithm_suite !== 'ed25519') {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }

  if (cred.revoked_at !== null && cred.revoked_at <= issuedAt) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_REVOKED,
      signer_role: role,
    };
  }

  if (cred.effective_at > issuedAt) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_INEFFECTIVE,
      signer_role: role,
    };
  }

  const pubKeyDer = Buffer.from(cred.public_key_spki_der_base64, 'base64');
  if (
    pubKeyDer.length !== SPKI_ED25519_TOTAL ||
    !pubKeyDer.subarray(0, SPKI_ED25519_PREFIX.length).equals(SPKI_ED25519_PREFIX)
  ) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CREDENTIAL_UNRESOLVABLE,
      signer_role: role,
    };
  }

  const signatureInput = computeSignatureInput(canonicalBytes, role);
  const signatureBytes = Buffer.from(sig.signature_bytes, 'base64');

  if (signatureBytes.length !== 64) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      signer_role: role,
    };
  }

  try {
    const keyObj = createPublicKey({
      key: pubKeyDer,
      format: 'der',
      type: 'spki',
    });
    const ok = cryptoVerify(null, signatureInput, keyObj, signatureBytes);
    if (!ok) {
      return {
        valid: false,
        failureMode: FAILURE_MODES.SIGNATURE_INVALID,
        signer_role: role,
      };
    }
  } catch {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      signer_role: role,
    };
  }

  return { valid: true, signer_role: role };
}
