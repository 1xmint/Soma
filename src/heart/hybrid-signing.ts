/**
 * Hybrid signing — crypto-agility envelope for post-quantum migration.
 *
 * NIST's PQ transition is not "replace Ed25519 with ML-DSA one day." It's
 * "sign with BOTH for a long time, so a breakthrough against either
 * algorithm doesn't lose you the property." That migration period needs
 * an on-the-wire format that:
 *   1. Carries multiple signatures from different algorithms side-by-side.
 *   2. Self-describes its algorithms so verifiers know what to check.
 *   3. Lets verifiers enforce a policy ("require both", "require any",
 *      "require ≥N post-quantum algos", "require specific set") so the
 *      same signature can age gracefully as the policy hardens.
 *   4. Binds every signature to the full set of public keys used, so an
 *      attacker can't swap one algorithm's key for another ("cross-algo
 *      key substitution" attack).
 *
 * This module implements that envelope. It does NOT ship an ML-DSA
 * provider — that's a separate package. What it ships is the composite
 * format, so the day a real ML-DSA `SigningProvider` drops in, the
 * existing signing call-sites just add a second algorithm to the mix
 * and keep working.
 *
 * Signed payload for each algorithm:
 *   canonicalJson({
 *     protocol: "soma-hybrid-sig/1",
 *     binding: [ {algorithmId, publicKeyB64}, ... ],  // ALL pks, in order
 *     messageB64: base64(message),
 *   })
 *
 * Why bind all pks into each per-algo signature? Consider: Alice has
 * (ed-sk, ed-pk) and (pq-sk, pq-pk). She publishes Hybrid(ed-pk, pq-pk).
 * Without pk-binding, Eve could take Alice's legit Ed25519 signature
 * over `msg` and stick it in an envelope advertising (ed-pk, eve-pq-pk).
 * If Eve can later forge a PQ sig, she'd pass a require-all check
 * under Alice's identity. Binding the full pk set into each signature
 * makes the Ed25519 signature invalid the moment Eve substitutes her
 * own PQ key. Closes cross-algo key substitution (NIST SP 800-208
 * recommendation).
 *
 * Non-goals:
 *   - Implementing ML-DSA, SLH-DSA, or any PQ algorithm here (use a
 *     dedicated library and pass its `SigningProvider` to the registry).
 *   - Transcribing an existing hybrid-sig IETF draft byte-for-byte
 *     (soma has its own canonical-JSON envelope convention).
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
  type SigningProvider,
} from '../core/crypto-provider.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** A single-algorithm key pair inside a hybrid bundle. */
export interface AlgorithmKeyPair {
  algorithmId: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** A bundle of per-algorithm key pairs — one identity, many sigs. */
export interface HybridKeyPair {
  algorithms: readonly AlgorithmKeyPair[];
}

/** One signature from one algorithm. */
export interface AlgorithmSignature {
  algorithmId: string;
  signatureB64: string;
}

/** Wire format: an envelope carrying N signatures over the same message. */
export interface HybridSignature {
  version: 1;
  /** Algorithm IDs in the canonical order used for binding. */
  algorithms: readonly string[];
  /** Public keys, base64, in the same order as `algorithms`. */
  publicKeysB64: readonly string[];
  /** Signatures — not necessarily in `algorithms` order, matched by id. */
  signatures: readonly AlgorithmSignature[];
}

/** What the verifier demands before declaring a hybrid signature good. */
export type VerificationPolicy =
  /** Every algorithm advertised in the envelope must verify. Strongest. */
  | { readonly type: 'require-all' }
  /** At least one algorithm must verify. Weakest. */
  | { readonly type: 'require-any' }
  /** These specific algorithm IDs must all verify. */
  | {
      readonly type: 'require-algorithms';
      readonly algorithms: readonly string[];
    }
  /** At least `minPq` of the listed PQ algorithms must verify. */
  | {
      readonly type: 'prefer-pq';
      readonly pqAlgorithms: readonly string[];
      readonly minPq: number;
    };

/** Result of verifying a hybrid signature. */
export interface HybridVerification {
  ok: boolean;
  verifiedAlgorithms: string[];
  failedAlgorithms: string[];
  reason?: string;
}

// ─── AlgorithmRegistry ──────────────────────────────────────────────────────

/**
 * Maps algorithmId → SigningProvider. Signers register the algorithms
 * they hold keys for; verifiers register the algorithms they trust.
 * Missing providers at verify time count as failures, not errors — that
 * way a signer adding a new PQ algorithm doesn't crash old verifiers.
 */
export class AlgorithmRegistry {
  private readonly providers = new Map<string, SigningProvider>();

  register(provider: SigningProvider): void {
    if (this.providers.has(provider.algorithmId)) {
      throw new Error(`algorithm already registered: ${provider.algorithmId}`);
    }
    this.providers.set(provider.algorithmId, provider);
  }

  get(algorithmId: string): SigningProvider {
    const p = this.providers.get(algorithmId);
    if (!p) throw new Error(`no provider for algorithm: ${algorithmId}`);
    return p;
  }

  has(algorithmId: string): boolean {
    return this.providers.has(algorithmId);
  }

  list(): string[] {
    return Array.from(this.providers.keys()).sort();
  }

  size(): number {
    return this.providers.size;
  }
}

// ─── Key generation ─────────────────────────────────────────────────────────

/**
 * Generate one fresh key pair per algorithm. Order is preserved — the
 * resulting `HybridKeyPair.algorithms` matches `algorithmIds`.
 */
export function generateHybridKeyPair(
  algorithmIds: readonly string[],
  registry: AlgorithmRegistry,
): HybridKeyPair {
  if (algorithmIds.length === 0) {
    throw new Error('hybrid key pair requires at least one algorithm');
  }
  const seen = new Set<string>();
  for (const id of algorithmIds) {
    if (seen.has(id)) {
      throw new Error(`duplicate algorithm in hybrid key pair: ${id}`);
    }
    seen.add(id);
  }
  const algorithms = algorithmIds.map((algorithmId) => {
    const provider = registry.get(algorithmId);
    const kp = provider.generateKeyPair();
    return {
      algorithmId,
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
    };
  });
  return { algorithms };
}

// ─── Binding payload ────────────────────────────────────────────────────────

function buildBindingPayload(
  algorithms: readonly string[],
  publicKeysB64: readonly string[],
  message: Uint8Array,
  p: CryptoProvider,
): Uint8Array {
  const payload = {
    protocol: 'soma-hybrid-sig/1',
    binding: algorithms.map((algorithmId, i) => ({
      algorithmId,
      publicKeyB64: publicKeysB64[i],
    })),
    messageB64: p.encoding.encodeBase64(message),
  };
  return new TextEncoder().encode(canonicalJson(payload));
}

// ─── Sign ───────────────────────────────────────────────────────────────────

/**
 * Produce one signature per algorithm in `keyPair`, all over the same
 * domain-separated binding payload. Returns a `HybridSignature` envelope
 * ready for on-the-wire transport.
 */
export function hybridSign(
  keyPair: HybridKeyPair,
  message: Uint8Array,
  registry: AlgorithmRegistry,
  provider?: CryptoProvider,
): HybridSignature {
  const p = provider ?? getCryptoProvider();
  if (keyPair.algorithms.length === 0) {
    throw new Error('cannot sign with empty hybrid key pair');
  }
  const algorithms = keyPair.algorithms.map((a) => a.algorithmId);
  const publicKeysB64 = keyPair.algorithms.map((a) =>
    p.encoding.encodeBase64(a.publicKey),
  );
  const bindingPayload = buildBindingPayload(
    algorithms,
    publicKeysB64,
    message,
    p,
  );
  const signatures: AlgorithmSignature[] = keyPair.algorithms.map((a) => {
    const providerImpl = registry.get(a.algorithmId);
    const sig = providerImpl.sign(bindingPayload, a.secretKey);
    return {
      algorithmId: a.algorithmId,
      signatureB64: p.encoding.encodeBase64(sig),
    };
  });
  return { version: 1, algorithms, publicKeysB64, signatures };
}

// ─── Verify ─────────────────────────────────────────────────────────────────

/**
 * Verify a `HybridSignature` against `message`, applying the given policy.
 * Unknown algorithms (no provider in registry) count as failures, not
 * errors — forward-compat: a future signer adding "ml-dsa-87" won't
 * crash an old verifier that only knows "ed25519" + "ml-dsa-65".
 */
export function verifyHybridSignature(
  sig: HybridSignature,
  message: Uint8Array,
  registry: AlgorithmRegistry,
  policy: VerificationPolicy,
  provider?: CryptoProvider,
): HybridVerification {
  const p = provider ?? getCryptoProvider();

  if (sig.version !== 1) {
    return {
      ok: false,
      verifiedAlgorithms: [],
      failedAlgorithms: [],
      reason: `unsupported hybrid-sig version: ${sig.version}`,
    };
  }
  if (sig.algorithms.length !== sig.publicKeysB64.length) {
    return {
      ok: false,
      verifiedAlgorithms: [],
      failedAlgorithms: [],
      reason: 'algorithms and publicKeysB64 length mismatch',
    };
  }
  if (sig.algorithms.length === 0) {
    return {
      ok: false,
      verifiedAlgorithms: [],
      failedAlgorithms: [],
      reason: 'hybrid signature has no algorithms',
    };
  }
  // Reject duplicate algorithm IDs — would confuse policy matching.
  const seen = new Set<string>();
  for (const id of sig.algorithms) {
    if (seen.has(id)) {
      return {
        ok: false,
        verifiedAlgorithms: [],
        failedAlgorithms: [],
        reason: `duplicate algorithm in envelope: ${id}`,
      };
    }
    seen.add(id);
  }

  const bindingPayload = buildBindingPayload(
    sig.algorithms,
    sig.publicKeysB64,
    message,
    p,
  );

  const verified: string[] = [];
  const failed: string[] = [];
  // Track which algorithm IDs were actually present in `signatures`.
  const presentInSigs = new Set<string>();

  for (const as of sig.signatures) {
    presentInSigs.add(as.algorithmId);
    const idx = sig.algorithms.indexOf(as.algorithmId);
    if (idx === -1) {
      failed.push(as.algorithmId);
      continue;
    }
    if (!registry.has(as.algorithmId)) {
      failed.push(as.algorithmId);
      continue;
    }
    const providerImpl = registry.get(as.algorithmId);
    let pk: Uint8Array;
    let sigBytes: Uint8Array;
    try {
      pk = p.encoding.decodeBase64(sig.publicKeysB64[idx]);
      sigBytes = p.encoding.decodeBase64(as.signatureB64);
    } catch {
      failed.push(as.algorithmId);
      continue;
    }
    try {
      if (providerImpl.verify(bindingPayload, sigBytes, pk)) {
        verified.push(as.algorithmId);
      } else {
        failed.push(as.algorithmId);
      }
    } catch {
      failed.push(as.algorithmId);
    }
  }

  // Algorithms advertised but missing a signature: always a failure.
  for (const a of sig.algorithms) {
    if (!presentInSigs.has(a) && !failed.includes(a)) {
      failed.push(a);
    }
  }

  // Apply policy.
  switch (policy.type) {
    case 'require-all': {
      const allOk = sig.algorithms.every((a) => verified.includes(a));
      return {
        ok: allOk,
        verifiedAlgorithms: verified,
        failedAlgorithms: failed,
        reason: allOk ? undefined : 'not all advertised algorithms verified',
      };
    }
    case 'require-any': {
      const anyOk = verified.length > 0;
      return {
        ok: anyOk,
        verifiedAlgorithms: verified,
        failedAlgorithms: failed,
        reason: anyOk ? undefined : 'no algorithm verified',
      };
    }
    case 'require-algorithms': {
      if (policy.algorithms.length === 0) {
        return {
          ok: false,
          verifiedAlgorithms: verified,
          failedAlgorithms: failed,
          reason: 'require-algorithms policy with empty list',
        };
      }
      const missing = policy.algorithms.filter((a) => !verified.includes(a));
      return {
        ok: missing.length === 0,
        verifiedAlgorithms: verified,
        failedAlgorithms: failed,
        reason:
          missing.length > 0
            ? `missing required algorithms: ${missing.join(', ')}`
            : undefined,
      };
    }
    case 'prefer-pq': {
      const pqCount = verified.filter((a) =>
        policy.pqAlgorithms.includes(a),
      ).length;
      const ok = pqCount >= policy.minPq;
      return {
        ok,
        verifiedAlgorithms: verified,
        failedAlgorithms: failed,
        reason: ok
          ? undefined
          : `need ${policy.minPq} PQ sigs, got ${pqCount}`,
      };
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Extract the bundle of public keys from a hybrid key pair. Useful for
 * publishing a hybrid identity without the secret material.
 */
export function hybridPublicKeys(
  keyPair: HybridKeyPair,
): { algorithmId: string; publicKey: Uint8Array }[] {
  return keyPair.algorithms.map((a) => ({
    algorithmId: a.algorithmId,
    publicKey: a.publicKey,
  }));
}

/**
 * Stable fingerprint of a hybrid public-key set. Binds algorithms and
 * public keys together so two identities with the same classical key
 * but different PQ keys get different fingerprints. Output is a hex
 * SHA-256 prefixed with "soma-hybrid-fp:v1:".
 */
export function hybridFingerprint(
  publicKeys: readonly { algorithmId: string; publicKey: Uint8Array }[],
  provider?: CryptoProvider,
): string {
  const p = provider ?? getCryptoProvider();
  const payload = {
    protocol: 'soma-hybrid-fp/1',
    keys: publicKeys.map((k) => ({
      algorithmId: k.algorithmId,
      publicKeyB64: p.encoding.encodeBase64(k.publicKey),
    })),
  };
  const hex = p.hashing.hash(canonicalJson(payload));
  return `soma-hybrid-fp:v1:${hex}`;
}
