// Heart-to-heart integrated verifier (§5).
//
// For certificates with profile "heart-to-heart", enforces that BOTH
// issuer AND counterparty signatures are present and individually valid.
// Each signature is verified via verifyCertificateSignature.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';
import {
  verifyCertificateSignature,
  type CertificateSignatureEntry,
  type CredentialLookup,
} from './signature.js';
import { canonicalizePayload } from './canonical.js';

// -- Types ------------------------------------------------------------------

export interface HeartToHeartCertificateInput {
  readonly profile: string;
  readonly issued_at: number;
  readonly signatures: readonly CertificateSignatureEntry[];
  readonly [key: string]: unknown;
}

export interface HeartToHeartOk {
  readonly valid: true;
}

export interface HeartToHeartFail {
  readonly valid: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
}

export type HeartToHeartResult = HeartToHeartOk | HeartToHeartFail;

// -- Verifier ----------------------------------------------------------------

export function verifyHeartToHeartSignatures(
  cert: HeartToHeartCertificateInput,
  credentialLookup: CredentialLookup,
): HeartToHeartResult {
  if (cert.profile !== 'heart-to-heart') {
    return { valid: true };
  }

  const sigs = cert.signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      detail: 'heart-to-heart certificate has no signatures',
    };
  }

  const issuerSig = sigs.find((s) => s.signer_role === 'issuer');
  const counterpartySig = sigs.find((s) => s.signer_role === 'counterparty');

  if (!issuerSig) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      detail: 'heart-to-heart certificate missing issuer signature',
    };
  }

  if (!counterpartySig) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.SIGNATURE_INVALID,
      detail: 'heart-to-heart certificate missing counterparty signature',
    };
  }

  const certRecord = cert as unknown as Record<string, unknown>;
  const canonicalBytes = canonicalizePayload(certRecord);

  const issuerResult = verifyCertificateSignature(
    canonicalBytes,
    issuerSig,
    cert.issued_at,
    credentialLookup,
  );
  if (!issuerResult.valid) {
    return {
      valid: false,
      failureMode: issuerResult.failureMode,
      detail: `issuer signature verification failed: ${issuerResult.failureMode}`,
    };
  }

  const counterpartyResult = verifyCertificateSignature(
    canonicalBytes,
    counterpartySig,
    cert.issued_at,
    credentialLookup,
  );
  if (!counterpartyResult.valid) {
    return {
      valid: false,
      failureMode: counterpartyResult.failureMode,
      detail: `counterparty signature verification failed: ${counterpartyResult.failureMode}`,
    };
  }

  return { valid: true };
}
