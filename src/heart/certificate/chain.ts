// Certificate chain evaluation (§11.3).
//
// Evaluates a chain of certificates where each link is verified
// independently via verifyCertificateSignature. The chain fails closed
// if ANY link fails.
//
// MUST NOT expose any "is-this-trusted" API (§11.2 prohibition).
// This is a chain EVALUATOR, not a trust oracle.

import { FAILURE_MODES, type FailureMode } from './failure-modes.js';
import {
  verifyCertificateSignature,
  type CertificateSignatureEntry,
  type CredentialLookup,
} from './signature.js';
import { canonicalizePayload } from './canonical.js';

// -- Types ------------------------------------------------------------------

export interface CertificateChainLink {
  readonly certificate: Record<string, unknown>;
  readonly issuer_identity_id: string;
  readonly subject_identity_id: string;
}

export interface CertificateChainInput {
  readonly links: readonly CertificateChainLink[];
}

export interface ChainEvalOk {
  readonly valid: true;
  readonly links_verified: number;
}

export interface ChainEvalFail {
  readonly valid: false;
  readonly failureMode: FailureMode;
  readonly detail: string;
  readonly failed_link_index: number;
}

export type CertificateChainResult = ChainEvalOk | ChainEvalFail;

// -- Evaluator ---------------------------------------------------------------

export function evaluateChain(
  chain: CertificateChainInput,
  credentialLookup: CredentialLookup,
): CertificateChainResult {
  const { links } = chain;

  if (!Array.isArray(links) || links.length === 0) {
    return {
      valid: false,
      failureMode: FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
      detail: 'chain has no links',
      failed_link_index: -1,
    };
  }

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const cert = link.certificate;

    // Adjacent link validation first (cheaper than crypto).
    if (i > 0) {
      const parent = links[i - 1];
      if (link.issuer_identity_id !== parent.subject_identity_id) {
        return {
          valid: false,
          failureMode: FAILURE_MODES.CHAIN_LINK_MISMATCH,
          detail:
            `link ${i} issuer_identity_id "${link.issuer_identity_id}" ` +
            `does not match parent subject_identity_id "${parent.subject_identity_id}"`,
          failed_link_index: i,
        };
      }
    }

    const sigs = cert.signatures as CertificateSignatureEntry[] | undefined;
    if (!Array.isArray(sigs) || sigs.length === 0) {
      return {
        valid: false,
        failureMode: FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
        detail: `link ${i} has no signatures`,
        failed_link_index: i,
      };
    }

    let canonicalBytes: Buffer;
    try {
      canonicalBytes = canonicalizePayload(cert);
    } catch {
      return {
        valid: false,
        failureMode: FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
        detail: `link ${i} failed canonicalisation`,
        failed_link_index: i,
      };
    }

    const issuerSig = sigs.find((s) => s.signer_role === 'issuer');
    if (!issuerSig) {
      return {
        valid: false,
        failureMode: FAILURE_MODES.CHAIN_LINK_UNRESOLVABLE,
        detail: `link ${i} has no issuer signature`,
        failed_link_index: i,
      };
    }

    const issuedAt = cert.issued_at as number;
    const sigResult = verifyCertificateSignature(
      canonicalBytes,
      issuerSig,
      issuedAt,
      credentialLookup,
    );
    if (!sigResult.valid) {
      return {
        valid: false,
        failureMode: sigResult.failureMode,
        detail: `link ${i} signature verification failed: ${sigResult.failureMode}`,
        failed_link_index: i,
      };
    }
  }

  return { valid: true, links_verified: links.length };
}
