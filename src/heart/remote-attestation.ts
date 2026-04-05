/**
 * Remote attestation — bind a heart's identity to a TEE platform quote.
 *
 * When a heart runs in a hardware-enforced enclave (SGX, TDX, Nitro, SEV-SNP,
 * Apple Secure Enclave, etc.), the platform can issue a *quote* that proves
 * "code with measurement M is running on hardware signed by vendor V with
 * configuration C". Pairing that quote with the heart's public key turns
 * "here is a signing key" into "here is a signing key *bound to* this
 * specific binary running on genuine Intel/AMD/Apple/AWS hardware."
 *
 * This module doesn't verify quotes directly — vendor verification is a
 * maze of per-platform root certs, PCRs, debug flags, TCB levels, and
 * revocation lists. Instead, it defines:
 *
 *   1. `AttestationDocument`: a portable envelope binding {quote, measurements,
 *      platform, heart public key, nonce} together, signed by the heart so
 *      verifiers know the quote was issued *for this key*.
 *   2. `RemoteAttestationVerifier`: pluggable interface. Operators inject
 *      platform-specific verifiers (e.g. `IntelSgxVerifier`, `NitroVerifier`).
 *   3. `AttestationRegistry`: trust-policy layer. Pin expected measurements
 *      per platform; reject documents whose measurements aren't whitelisted.
 *
 * Defence-in-depth, not a standalone trust root: a malicious host can still
 * spoof non-TEE deployments, but a valid TEE attestation + measurement pin
 * rules out "attacker runs modified binary on normal cloud instance".
 *
 * Reference implementations: `NoopVerifier` (always accepts — dev only) and
 * `MockTeeVerifier` (accepts quotes signed by a test root, for tests).
 */

import { canonicalJson } from '../core/canonicalize.js';
import {
  getCryptoProvider,
  type CryptoProvider,
} from '../core/crypto-provider.js';
import { publicKeyToDid } from '../core/genome.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * TEE platforms we know about. Callers can use 'custom' + a string in
 * `platformDetail` for unknown / proprietary platforms.
 */
export type TeePlatform =
  | 'intel-sgx'
  | 'intel-tdx'
  | 'amd-sev-snp'
  | 'aws-nitro'
  | 'apple-sep'
  | 'azure-cvm'
  | 'custom';

/**
 * An attestation document: binds a TEE quote to the heart's public key so
 * verifiers know the quote came FROM this key, not was replayed from
 * somewhere else.
 */
export interface AttestationDocument {
  /** Opaque id. */
  id: string;
  /** TEE platform identifier. */
  platform: TeePlatform;
  /** Optional platform-specific detail (e.g. 'sgx-dcap-v3', 'nitro-v2'). */
  platformDetail: string | null;
  /** Base64 of the raw vendor quote — opaque to us. */
  quoteB64: string;
  /** Enclave / firmware measurements extracted from the quote (hex). */
  measurements: Record<string, string>;
  /** DID of the heart being attested. */
  heartDid: string;
  /** Base64 public key of the heart being attested. */
  heartPublicKey: string;
  /** Freshness nonce — supplied by verifier during challenge. */
  nonceB64: string;
  /** When the heart signed this document (ms epoch). */
  issuedAt: number;
  /** When it expires, or null for never. */
  expiresAt: number | null;
  /** Base64 Ed25519 signature by the heart over canonical envelope. */
  signature: string;
}

/** Verification result from a platform-specific verifier. */
export type QuoteVerification =
  | {
      valid: true;
      /** Measurements the verifier extracted from the quote. */
      measurements: Record<string, string>;
      /** Public key the platform vouches for (the enclave's key). */
      attestedPublicKey: string;
    }
  | { valid: false; reason: string };

/** Pluggable verifier per TEE platform. */
export interface RemoteAttestationVerifier {
  /** Which platforms this verifier handles. */
  readonly platforms: readonly TeePlatform[];
  /** Verify the raw vendor quote bytes. */
  verifyQuote(
    quote: Uint8Array,
    expectedNonce: string,
    expectedPublicKey: string,
  ): Promise<QuoteVerification> | QuoteVerification;
}

export type AttestationVerification =
  | {
      valid: true;
      platform: TeePlatform;
      measurements: Record<string, string>;
      heartDid: string;
    }
  | { valid: false; reason: string };

/** Trust policy: which measurements are acceptable per platform. */
export interface MeasurementPolicy {
  platform: TeePlatform;
  /** Required measurement keys → set of acceptable hex values. */
  allow: Record<string, readonly string[]>;
}

// ─── Envelope construction (what gets signed) ──────────────────────────────

function buildEnvelope(
  d: Omit<AttestationDocument, 'signature'>,
): Record<string, unknown> {
  return {
    protocol: 'soma-remote-attestation/1',
    id: d.id,
    platform: d.platform,
    platformDetail: d.platformDetail,
    quoteB64: d.quoteB64,
    measurements: d.measurements,
    heartDid: d.heartDid,
    heartPublicKey: d.heartPublicKey,
    nonceB64: d.nonceB64,
    issuedAt: d.issuedAt,
    expiresAt: d.expiresAt,
  };
}

// ─── Creation (heart signs a quote binding it to its own key) ──────────────

export function createAttestationDocument(opts: {
  platform: TeePlatform;
  platformDetail?: string | null;
  quote: Uint8Array;
  measurements: Record<string, string>;
  heartDid: string;
  heartPublicKey: string;
  heartSigningKey: Uint8Array;
  nonceB64: string;
  expiresAt?: number | null;
  provider?: CryptoProvider;
}): AttestationDocument {
  const p = opts.provider ?? getCryptoProvider();
  const id = `att-${p.encoding.encodeBase64(p.random.randomBytes(12))}`;
  const base: Omit<AttestationDocument, 'signature'> = {
    id,
    platform: opts.platform,
    platformDetail: opts.platformDetail ?? null,
    quoteB64: p.encoding.encodeBase64(opts.quote),
    measurements: { ...opts.measurements },
    heartDid: opts.heartDid,
    heartPublicKey: opts.heartPublicKey,
    nonceB64: opts.nonceB64,
    issuedAt: Date.now(),
    expiresAt: opts.expiresAt ?? null,
  };
  const signingInput = new TextEncoder().encode(
    canonicalJson(buildEnvelope(base)),
  );
  const signature = p.signing.sign(signingInput, opts.heartSigningKey);
  return { ...base, signature: p.encoding.encodeBase64(signature) };
}

// ─── Verification ──────────────────────────────────────────────────────────

/**
 * Full verification:
 *   1. Heart's signature over envelope is valid.
 *   2. Heart DID matches heart public key.
 *   3. Platform-specific verifier accepts the quote.
 *   4. Nonce in quote matches document nonce (binding freshness).
 *   5. Attested public key (from quote) matches heart public key.
 *   6. Optional: measurement policy satisfied.
 *   7. Not expired.
 */
export async function verifyAttestationDocument(
  doc: AttestationDocument,
  opts: {
    verifiers: readonly RemoteAttestationVerifier[];
    /** Optional policies — enforces measurement allowlists per platform. */
    policies?: readonly MeasurementPolicy[];
    /** Expected nonce (if the verifier issued one). */
    expectedNonce?: string;
    /** Current time for expiry check. */
    now?: number;
    provider?: CryptoProvider;
  },
): Promise<AttestationVerification> {
  const p = opts.provider ?? getCryptoProvider();
  const now = opts.now ?? Date.now();

  // 1. Basic envelope signature.
  const envelope = buildEnvelope(doc);
  const signingInput = new TextEncoder().encode(canonicalJson(envelope));
  let sigBytes: Uint8Array;
  let heartPubKey: Uint8Array;
  try {
    sigBytes = p.encoding.decodeBase64(doc.signature);
    heartPubKey = p.encoding.decodeBase64(doc.heartPublicKey);
  } catch {
    return { valid: false, reason: 'malformed base64' };
  }
  if (!p.signing.verify(signingInput, sigBytes, heartPubKey)) {
    return { valid: false, reason: 'invalid heart signature' };
  }

  // 2. DID/key binding.
  if (publicKeyToDid(heartPubKey, p) !== doc.heartDid) {
    return { valid: false, reason: 'heart DID/key mismatch' };
  }

  // 3. Expiry.
  if (doc.expiresAt !== null && doc.expiresAt < now) {
    return { valid: false, reason: 'attestation expired' };
  }

  // 4. Nonce match (if caller required one).
  if (opts.expectedNonce !== undefined && doc.nonceB64 !== opts.expectedNonce) {
    return { valid: false, reason: 'nonce mismatch' };
  }

  // 5. Platform verifier.
  const verifier = opts.verifiers.find((v) =>
    v.platforms.includes(doc.platform),
  );
  if (!verifier) {
    return {
      valid: false,
      reason: `no verifier registered for platform: ${doc.platform}`,
    };
  }
  const quoteBytes = p.encoding.decodeBase64(doc.quoteB64);
  const quoteResult = await verifier.verifyQuote(
    quoteBytes,
    doc.nonceB64,
    doc.heartPublicKey,
  );
  if (!quoteResult.valid) {
    return { valid: false, reason: `quote rejected: ${quoteResult.reason}` };
  }

  // 6. Attested key must match heart's public key.
  if (quoteResult.attestedPublicKey !== doc.heartPublicKey) {
    return {
      valid: false,
      reason: 'attested public key does not match heart key',
    };
  }

  // 7. Measurements must agree between doc and verifier (quote is source of truth).
  for (const [k, v] of Object.entries(quoteResult.measurements)) {
    if (doc.measurements[k] !== undefined && doc.measurements[k] !== v) {
      return {
        valid: false,
        reason: `measurement mismatch for ${k}`,
      };
    }
  }

  // 8. Measurement policy check (optional).
  if (opts.policies) {
    const policy = opts.policies.find((p) => p.platform === doc.platform);
    if (policy) {
      for (const [key, allowed] of Object.entries(policy.allow)) {
        const actual = quoteResult.measurements[key];
        if (actual === undefined) {
          return {
            valid: false,
            reason: `required measurement missing: ${key}`,
          };
        }
        if (!allowed.includes(actual)) {
          return {
            valid: false,
            reason: `measurement ${key}=${actual} not in allowlist`,
          };
        }
      }
    }
  }

  return {
    valid: true,
    platform: doc.platform,
    measurements: quoteResult.measurements,
    heartDid: doc.heartDid,
  };
}

// ─── Reference verifier: NoOp (accepts all quotes) ──────────────────────────

/**
 * Development-only verifier. Accepts ANY quote bytes and trusts the
 * document's stated measurements. DO NOT USE IN PRODUCTION — no security.
 */
export class NoopVerifier implements RemoteAttestationVerifier {
  readonly platforms: readonly TeePlatform[] = ['custom'];

  constructor(
    private readonly acceptedPublicKey: string,
    private readonly measurements: Record<string, string> = {},
  ) {}

  verifyQuote(
    _quote: Uint8Array,
    _expectedNonce: string,
    expectedPublicKey: string,
  ): QuoteVerification {
    return {
      valid: true,
      measurements: this.measurements,
      attestedPublicKey: this.acceptedPublicKey || expectedPublicKey,
    };
  }
}

// ─── Reference verifier: MockTeeVerifier (for tests) ───────────────────────

/**
 * Mock TEE verifier: a quote is `canonicalJson({nonce, publicKey, measurements})`
 * signed by a known "vendor" key. Useful in tests and integration harnesses.
 * Not secure against real attackers — the vendor key is embedded in-process.
 */
export class MockTeeVerifier implements RemoteAttestationVerifier {
  readonly platforms: readonly TeePlatform[];

  constructor(
    private readonly vendorPublicKey: Uint8Array,
    platforms: readonly TeePlatform[] = ['custom'],
    private readonly provider: CryptoProvider = getCryptoProvider(),
  ) {
    this.platforms = platforms;
  }

  verifyQuote(
    quote: Uint8Array,
    expectedNonce: string,
    expectedPublicKey: string,
  ): QuoteVerification {
    const p = this.provider;
    // Quote format: canonicalJson({v, nonce, publicKey, measurements}) || signature
    // We split at the last 64 bytes (signature size).
    if (quote.length <= 64) {
      return { valid: false, reason: 'quote too short' };
    }
    const body = quote.slice(0, quote.length - 64);
    const sig = quote.slice(quote.length - 64);
    if (!p.signing.verify(body, sig, this.vendorPublicKey)) {
      return { valid: false, reason: 'vendor signature invalid' };
    }
    let parsed: {
      v: number;
      nonce: string;
      publicKey: string;
      measurements: Record<string, string>;
    };
    try {
      parsed = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return { valid: false, reason: 'quote body not JSON' };
    }
    if (parsed.nonce !== expectedNonce) {
      return { valid: false, reason: 'nonce mismatch in quote' };
    }
    if (parsed.publicKey !== expectedPublicKey) {
      return { valid: false, reason: 'public key mismatch in quote' };
    }
    return {
      valid: true,
      measurements: parsed.measurements,
      attestedPublicKey: parsed.publicKey,
    };
  }

  /** Test helper: construct a quote signed by the matching vendor key. */
  static issueQuote(
    vendorSigningKey: Uint8Array,
    opts: {
      nonce: string;
      publicKey: string;
      measurements: Record<string, string>;
    },
    provider?: CryptoProvider,
  ): Uint8Array {
    const p = provider ?? getCryptoProvider();
    const body = new TextEncoder().encode(
      JSON.stringify({
        v: 1,
        nonce: opts.nonce,
        publicKey: opts.publicKey,
        measurements: opts.measurements,
      }),
    );
    const sig = p.signing.sign(body, vendorSigningKey);
    const out = new Uint8Array(body.length + sig.length);
    out.set(body, 0);
    out.set(sig, body.length);
    return out;
  }
}
