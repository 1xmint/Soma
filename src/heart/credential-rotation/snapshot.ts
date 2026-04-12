/**
 * Wire-format helpers for snapshotting credential-rotation state.
 *
 * The in-memory shapes hold `Uint8Array` in a few places (public keys,
 * secret keys). JSON can't carry those, and every hot-swap recovery
 * path we care about (encrypted disk, pulse-tree export, operator
 * backup) goes through JSON at some point. These helpers convert to
 * and from base64-encoded wire shapes that are safe to stringify.
 *
 * Snapshots are the only cross-process handoff for the rotation
 * primitive. They must preserve everything a restored controller
 * needs to keep producing L1/L2/L3-correct events: event chain,
 * ratchet anchor, rate-limit bucket, accepted-pool grace windows,
 * and the backend's own durable material.
 *
 * Versioned explicitly so we can migrate without silently decoding
 * an older shape as a newer one.
 */

import type { CryptoProvider } from '../../core/crypto-provider.js';
import type {
  AlgorithmSuite,
  ControllerPolicy,
  Credential,
  CredentialClass,
  RotationEvent,
  RotationEventStatus,
} from './types.js';

export const SNAPSHOT_VERSION = 1 as const;

// ─── Credential wire ────────────────────────────────────────────────────────

export interface CredentialWire {
  readonly credentialId: string;
  readonly identityId: string;
  readonly backendId: string;
  readonly algorithmSuite: AlgorithmSuite;
  readonly class: CredentialClass;
  /** base64-encoded public key. */
  readonly publicKey: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nextManifestCommitment: string;
}

export function credentialToWire(
  credential: Credential,
  provider: CryptoProvider,
): CredentialWire {
  return {
    credentialId: credential.credentialId,
    identityId: credential.identityId,
    backendId: credential.backendId,
    algorithmSuite: credential.algorithmSuite,
    class: credential.class,
    publicKey: provider.encoding.encodeBase64(credential.publicKey),
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    nextManifestCommitment: credential.nextManifestCommitment,
  };
}

export function credentialFromWire(
  wire: CredentialWire,
  provider: CryptoProvider,
): Credential {
  return {
    credentialId: wire.credentialId,
    identityId: wire.identityId,
    backendId: wire.backendId,
    algorithmSuite: wire.algorithmSuite,
    class: wire.class,
    publicKey: provider.encoding.decodeBase64(wire.publicKey),
    issuedAt: wire.issuedAt,
    expiresAt: wire.expiresAt,
    nextManifestCommitment: wire.nextManifestCommitment,
  };
}

// ─── RotationEvent wire ─────────────────────────────────────────────────────

export interface RotationEventWire {
  readonly identityId: string;
  readonly backendId: string;
  readonly sequence: number;
  readonly previousEventHash: string;
  readonly oldCredentialId: string | null;
  readonly newCredential: CredentialWire;
  readonly ratchetAnchor: string;
  readonly timestamp: number;
  readonly nonce: string;
  readonly oldKeySignature: string;
  readonly newKeyProofOfPossession: string;
  readonly hash: string;
  readonly status: RotationEventStatus;
  readonly pulseTreeRoot: string | null;
  readonly externalWitnessCount: number;
}

export function rotationEventToWire(
  event: RotationEvent,
  provider: CryptoProvider,
): RotationEventWire {
  return {
    identityId: event.identityId,
    backendId: event.backendId,
    sequence: event.sequence,
    previousEventHash: event.previousEventHash,
    oldCredentialId: event.oldCredentialId,
    newCredential: credentialToWire(event.newCredential, provider),
    ratchetAnchor: event.ratchetAnchor,
    timestamp: event.timestamp,
    nonce: event.nonce,
    oldKeySignature: event.oldKeySignature,
    newKeyProofOfPossession: event.newKeyProofOfPossession,
    hash: event.hash,
    status: event.status,
    pulseTreeRoot: event.pulseTreeRoot,
    externalWitnessCount: event.externalWitnessCount,
  };
}

export function rotationEventFromWire(
  wire: RotationEventWire,
  provider: CryptoProvider,
): RotationEvent {
  return {
    identityId: wire.identityId,
    backendId: wire.backendId,
    sequence: wire.sequence,
    previousEventHash: wire.previousEventHash,
    oldCredentialId: wire.oldCredentialId,
    newCredential: credentialFromWire(wire.newCredential, provider),
    ratchetAnchor: wire.ratchetAnchor,
    timestamp: wire.timestamp,
    nonce: wire.nonce,
    oldKeySignature: wire.oldKeySignature,
    newKeyProofOfPossession: wire.newKeyProofOfPossession,
    hash: wire.hash,
    status: wire.status,
    pulseTreeRoot: wire.pulseTreeRoot,
    externalWitnessCount: wire.externalWitnessCount,
  };
}

// ─── Per-identity controller snapshot ───────────────────────────────────────

export interface AcceptedCredentialSnapshot {
  readonly credentialId: string;
  readonly credential: CredentialWire;
  readonly graceUntil: number;
}

export interface IdentityStateSnapshot {
  readonly identityId: string;
  readonly backendId: string;
  readonly events: RotationEventWire[];
  readonly currentCredentialId: string | null;
  readonly accepted: AcceptedCredentialSnapshot[];
  readonly ratchetAnchor: string;
  readonly rotationTimestamps: number[];
  readonly challengePeriodUnlockAt: number | null;
}

export interface ControllerSnapshot {
  readonly version: typeof SNAPSHOT_VERSION;
  readonly policy: ControllerPolicy;
  readonly identities: IdentityStateSnapshot[];
}
