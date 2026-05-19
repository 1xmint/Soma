import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createHumanDelegation,
  verifyHumanDelegation,
  computeChallengeHash,
  type AttestationVerifier,
  type HumanAttestation,
  type CeremonyTier,
} from "../../src/heart/human-delegation.js";
import type { Caveat } from "../../src/heart/delegation.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  const did = publicKeyToDid(kp.publicKey);
  const publicKey = crypto.encoding.encodeBase64(kp.publicKey);
  return { kp, did, publicKey };
}

/**
 * Mock attestation verifier — treats `payload` as a base64 tier string
 * ("L0".."L3") and `challengeHash` as the authoritative challenge. The
 * real verifier (PR-C) will parse a WebAuthn blob; the point of this
 * test double is to let us drive every branch of `verifyHumanDelegation`
 * without needing browser crypto.
 */
function makeMockVerifier(tier: CeremonyTier): AttestationVerifier {
  return (att, _ctx) => {
    if (att.kind !== "mock") return { ok: false, reason: "kind not mock" };
    return { ok: true, tier };
  };
}

function buildFixture(opts?: {
  envelope?: Caveat[];
  tier?: CeremonyTier;
  now?: number;
  expiresAt?: number;
}) {
  const now = opts?.now ?? 1_700_000_000_000;
  const human = makeIdentity();
  const agent = makeIdentity();
  const envelope: Caveat[] =
    opts?.envelope ?? [
      { kind: "expires-at", timestamp: now + 60_000 },
      { kind: "budget", credits: 1000 },
    ];
  const challengeHash = computeChallengeHash(
    envelope,
    "sess-1",
    agent.kp.publicKey,
  );
  const attestation: HumanAttestation = {
    kind: "mock",
    payload: new TextEncoder().encode("mock-payload"),
    challengeHash,
  };
  const delegation = createHumanDelegation({
    sessionId: "sess-1",
    humanDid: human.did,
    humanCredentialId: "cred-1",
    humanPublicKey: human.publicKey,
    humanSigningKey: human.kp.secretKey,
    agentEphemeralDid: agent.did,
    agentEphemeralPublicKey: agent.publicKey,
    envelope,
    issuedAt: now,
    expiresAt: opts?.expiresAt ?? now + 60_000,
    ceremonyTier: opts?.tier ?? "L1",
    attestation,
  });
  return { human, agent, envelope, delegation, now, attestation };
}

describe("HumanDelegation — creation + canonical signing", () => {
  it("creates a delegation whose signature verifies under the human pubkey", () => {
    const { delegation, now } = buildFixture();
    const result = verifyHumanDelegation(
      delegation,
      makeMockVerifier("L1"),
      now + 1,
    );
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe("L1");
  });

  it("rejects expiresAt <= issuedAt at creation time", () => {
    const human = makeIdentity();
    const agent = makeIdentity();
    expect(() =>
      createHumanDelegation({
        sessionId: "sess-x",
        humanDid: human.did,
        humanCredentialId: "cred-1",
        humanPublicKey: human.publicKey,
        humanSigningKey: human.kp.secretKey,
        agentEphemeralDid: agent.did,
        agentEphemeralPublicKey: agent.publicKey,
        envelope: [],
        issuedAt: 1000,
        expiresAt: 1000,
        ceremonyTier: "L1",
        attestation: {
          kind: "mock",
          payload: new Uint8Array(),
          challengeHash: new Uint8Array(32),
        },
      }),
    ).toThrow(/expiresAt must be after issuedAt/);
  });
});

describe("HumanDelegation — verification failure modes", () => {
  it("rejects a tampered envelope", () => {
    const { delegation, now } = buildFixture();
    const tampered = {
      ...delegation,
      envelope: [{ kind: "budget" as const, credits: 999_999 }],
    };
    const result = verifyHumanDelegation(
      tampered,
      makeMockVerifier("L1"),
      now + 1,
    );
    expect(result.valid).toBe(false);
  });

  it("rejects an expired delegation", () => {
    const { delegation, now } = buildFixture();
    const result = verifyHumanDelegation(
      delegation,
      makeMockVerifier("L1"),
      now + 120_000,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/expired/);
  });

  it("rejects a delegation used before issuedAt", () => {
    const { delegation, now } = buildFixture();
    const result = verifyHumanDelegation(
      delegation,
      makeMockVerifier("L1"),
      now - 1,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/issued in the future/);
  });

  it("rejects when the attestation verifier says no", () => {
    const { delegation, now } = buildFixture();
    const deny: AttestationVerifier = () => ({
      ok: false,
      reason: "hardware key revoked",
    });
    const result = verifyHumanDelegation(delegation, deny, now + 1);
    expect(result.valid).toBe(false);
    if (!result.valid)
      expect(result.reason).toMatch(/hardware key revoked/);
  });

  it("rejects when the claimed tier exceeds the attested tier", () => {
    // Delegation claims L3 but the authenticator only reaches L1.
    const { delegation, now } = buildFixture({ tier: "L3" });
    const result = verifyHumanDelegation(
      delegation,
      makeMockVerifier("L1"),
      now + 1,
    );
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/exceeds attested/);
  });

  it("rejects when the challenge hash was computed for a different session", () => {
    const { human, agent, envelope, now } = buildFixture();
    // Build a delegation whose attestation carries a hash for the WRONG
    // session id — the signature covers it, but the independent
    // recomputation inside verify should reject.
    const wrongChallenge = computeChallengeHash(
      envelope,
      "sess-OTHER",
      agent.kp.publicKey,
    );
    const forged = createHumanDelegation({
      sessionId: "sess-1",
      humanDid: human.did,
      humanCredentialId: "cred-1",
      humanPublicKey: human.publicKey,
      humanSigningKey: human.kp.secretKey,
      agentEphemeralDid: agent.did,
      agentEphemeralPublicKey: agent.publicKey,
      envelope,
      issuedAt: now,
      expiresAt: now + 60_000,
      ceremonyTier: "L1",
      attestation: {
        kind: "mock",
        payload: new Uint8Array(),
        challengeHash: wrongChallenge,
      },
    });
    const result = verifyHumanDelegation(
      forged,
      makeMockVerifier("L1"),
      now + 1,
    );
    expect(result.valid).toBe(false);
    if (!result.valid)
      expect(result.reason).toMatch(/challenge hash mismatch/);
  });

  it("rejects a delegation whose humanDid doesn't bind to humanPublicKey", () => {
    const { delegation, now } = buildFixture();
    const imposter = makeIdentity();
    const mismatched = { ...delegation, humanDid: imposter.did };
    const result = verifyHumanDelegation(
      mismatched,
      makeMockVerifier("L1"),
      now + 1,
    );
    expect(result.valid).toBe(false);
  });
});
