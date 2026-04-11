import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createHumanDelegation,
  computeChallengeHash,
  type AttestationVerifier,
  type CeremonyTier,
} from "../../src/heart/human-delegation.js";
import type { Caveat } from "../../src/heart/delegation.js";
import { HumanSessionRegistry } from "../../src/heart/human-session.js";
import { createCeremonyPolicy } from "../../src/heart/ceremony-policy.js";

const crypto = getCryptoProvider();

const acceptAll = (tier: CeremonyTier): AttestationVerifier => (att) => {
  if (att.kind !== "mock") return { ok: false, reason: "not mock" };
  return { ok: true, tier };
};

function mintDelegation(opts: {
  envelope: Caveat[];
  tier?: CeremonyTier;
  issuedAt?: number;
  expiresAt?: number;
  sessionId?: string;
}) {
  const now = opts.issuedAt ?? 1_700_000_000_000;
  const human = {
    kp: crypto.signing.generateKeyPair(),
    get did() {
      return publicKeyToDid(this.kp.publicKey);
    },
    get pub() {
      return crypto.encoding.encodeBase64(this.kp.publicKey);
    },
  };
  const agent = {
    kp: crypto.signing.generateKeyPair(),
    get did() {
      return publicKeyToDid(this.kp.publicKey);
    },
    get pub() {
      return crypto.encoding.encodeBase64(this.kp.publicKey);
    },
  };
  const sessionId = opts.sessionId ?? "sess-1";
  const challengeHash = computeChallengeHash(
    opts.envelope,
    sessionId,
    agent.kp.publicKey,
  );
  const delegation = createHumanDelegation({
    sessionId,
    humanDid: human.did,
    humanCredentialId: "cred-1",
    humanPublicKey: human.pub,
    humanSigningKey: human.kp.secretKey,
    agentEphemeralDid: agent.did,
    agentEphemeralPublicKey: agent.pub,
    envelope: opts.envelope,
    issuedAt: now,
    expiresAt: opts.expiresAt ?? now + 60_000,
    ceremonyTier: opts.tier ?? "L2",
    attestation: {
      kind: "mock",
      payload: new TextEncoder().encode("mock"),
      challengeHash,
    },
  });
  return { delegation, now };
}

describe("HumanSessionRegistry — open", () => {
  it("verifies and opens a valid delegation", () => {
    const { delegation, now } = mintDelegation({
      envelope: [
        { kind: "budget", credits: 500 },
        { kind: "max-invocations", count: 3 },
      ],
    });
    const reg = new HumanSessionRegistry({ attestationVerifier: acceptAll("L2") });
    const result = reg.open(delegation, now + 1);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.status).toBe("active");
      expect(result.session.remainingCredits).toBe(500);
      expect(result.session.remainingInvocations).toBe(3);
    }
  });

  it("is idempotent by sessionId", () => {
    const { delegation, now } = mintDelegation({
      envelope: [{ kind: "budget", credits: 100 }],
    });
    const reg = new HumanSessionRegistry({ attestationVerifier: acceptAll("L2") });
    const r1 = reg.open(delegation, now + 1);
    reg.invoke(delegation.sessionId, {
      actionClass: "spend",
      cost: 30,
      now: now + 2,
    });
    const r2 = reg.open(delegation, now + 3);
    expect(r1.ok && r2.ok).toBe(true);
    if (r2.ok) expect(r2.session.remainingCredits).toBe(70);
  });

  it("rejects a delegation whose attestation the verifier denies", () => {
    const { delegation, now } = mintDelegation({ envelope: [] });
    const deny: AttestationVerifier = () => ({ ok: false, reason: "nope" });
    const reg = new HumanSessionRegistry({ attestationVerifier: deny });
    const result = reg.open(delegation, now + 1);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.session.status).toBe("revoked");
      expect(result.reason).toMatch(/nope/);
    }
  });
});

describe("HumanSessionRegistry — invoke", () => {
  function freshRegistry(opts?: Parameters<typeof mintDelegation>[0]) {
    const { delegation, now } = mintDelegation(
      opts ?? {
        envelope: [
          { kind: "budget", credits: 100 },
          { kind: "max-invocations", count: 2 },
        ],
      },
    );
    const reg = new HumanSessionRegistry({ attestationVerifier: acceptAll("L2") });
    reg.open(delegation, now + 1);
    return { reg, sessionId: delegation.sessionId, now };
  }

  it("drains budget and invocations on success", () => {
    const { reg, sessionId, now } = freshRegistry();
    const r = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 40,
      now: now + 2,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.session.remainingCredits).toBe(60);
      expect(r.session.remainingInvocations).toBe(1);
    }
  });

  it("terminates with budget-exhausted on overdraft", () => {
    const { reg, sessionId, now } = freshRegistry();
    const r = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 500,
      now: now + 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.session.status).toBe("budget-exhausted");
      expect(r.session.remainingCredits).toBe(100); // unchanged on rejection
    }
  });

  it("terminates with invocations-exhausted on last call", () => {
    const { reg, sessionId, now } = freshRegistry();
    reg.invoke(sessionId, { actionClass: "spend", cost: 10, now: now + 2 });
    const r = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 10,
      now: now + 3,
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.session.status).toBe("invocations-exhausted");

    const r2 = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 10,
      now: now + 4,
    });
    expect(r2.ok).toBe(false);
  });

  it("rejects when policy tier < required tier", () => {
    // L0 tier but trying 'admin' (requires L3)
    const { delegation, now } = mintDelegation({
      envelope: [],
      tier: "L0",
    });
    const reg = new HumanSessionRegistry({ attestationVerifier: acceptAll("L0") });
    reg.open(delegation, now + 1);
    const r = reg.invoke(delegation.sessionId, {
      actionClass: "admin",
      now: now + 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/requires L3/);
  });

  it("enforces host-allowlist caveats", () => {
    const { reg, sessionId, now } = freshRegistry({
      envelope: [{ kind: "host-allowlist", hosts: ["api.claw-net.org"] }],
    });
    const rBad = reg.invoke(sessionId, {
      actionClass: "read",
      host: "evil.com",
      now: now + 2,
    });
    expect(rBad.ok).toBe(false);

    const rGood = reg.invoke(sessionId, {
      actionClass: "read",
      host: "api.claw-net.org",
      now: now + 3,
    });
    expect(rGood.ok).toBe(true);
  });

  it("flips to expired when now ≥ expiresAt", () => {
    const { reg, sessionId, now } = freshRegistry();
    const r = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 1,
      now: now + 10_000_000,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.session.status).toBe("expired");
  });

  it("revoke() terminates an active session", () => {
    const { reg, sessionId, now } = freshRegistry();
    expect(reg.revoke(sessionId)).toBe(true);
    const r = reg.invoke(sessionId, {
      actionClass: "spend",
      cost: 1,
      now: now + 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.session.status).toBe("revoked");
  });

  it("prune() drops terminated sessions", () => {
    const { reg, sessionId, now } = freshRegistry();
    reg.revoke(sessionId);
    expect(reg.size).toBe(1);
    const removed = reg.prune(now + 1);
    expect(removed).toBe(1);
    expect(reg.size).toBe(0);
  });
});

describe("HumanSessionRegistry — custom policy composition", () => {
  it("respects a caller-supplied CeremonyPolicy", () => {
    const policy = createCeremonyPolicy({
      overrides: { "voice-call": "L3" },
    });
    const { delegation, now } = mintDelegation({
      envelope: [],
      tier: "L2",
    });
    const reg = new HumanSessionRegistry({
      attestationVerifier: acceptAll("L2"),
      policy,
    });
    reg.open(delegation, now + 1);
    const r = reg.invoke(delegation.sessionId, {
      actionClass: "voice-call",
      now: now + 2,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/requires L3/);
  });
});
