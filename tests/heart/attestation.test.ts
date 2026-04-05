import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createAttestation,
  verifyAttestation,
  AttestationRegistry,
  type AttestationType,
} from "../../src/heart/attestation.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function makeAttestation(
  issuer: ReturnType<typeof makeIdentity>,
  subjectDid: string,
  type: AttestationType,
  overrides: Partial<{
    weight: number;
    expiresAt: number | null;
    evidence: string | null;
    customLabel: string | null;
  }> = {},
) {
  return createAttestation({
    subjectDid,
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKey,
    issuerSigningKey: issuer.kp.secretKey,
    attestationType: type,
    weight: overrides.weight ?? 50,
    expiresAt: overrides.expiresAt ?? null,
    evidence: overrides.evidence ?? null,
    customLabel: overrides.customLabel ?? null,
  });
}

describe("createAttestation / verifyAttestation", () => {
  it("creates and verifies a peer-vouched attestation", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched", { weight: 30 });
    expect(verifyAttestation(at).valid).toBe(true);
    expect(at.attestationType).toBe("peer-vouched");
    expect(at.weight).toBe(30);
    expect(at.subjectDid).toBe(subject.did);
    expect(at.issuerDid).toBe(issuer.did);
  });

  it("generates unique ids and nonces across attestations", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const a1 = makeAttestation(issuer, subject.did, "peer-vouched");
    const a2 = makeAttestation(issuer, subject.did, "peer-vouched");
    expect(a1.id).not.toBe(a2.id);
    expect(a1.nonce).not.toBe(a2.nonce);
    expect(a1.signature).not.toBe(a2.signature);
  });

  it("rejects weight outside [0, 100]", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    expect(() =>
      makeAttestation(issuer, subject.did, "peer-vouched", { weight: -1 }),
    ).toThrow(/weight/);
    expect(() =>
      makeAttestation(issuer, subject.did, "peer-vouched", { weight: 101 }),
    ).toThrow(/weight/);
  });

  it("accepts weight 0 and 100 at boundaries", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const low = makeAttestation(issuer, subject.did, "peer-vouched", { weight: 0 });
    const high = makeAttestation(issuer, subject.did, "kyc-verified", { weight: 100 });
    expect(verifyAttestation(low).valid).toBe(true);
    expect(verifyAttestation(high).valid).toBe(true);
  });

  it("rejects tampered subjectDid", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    const tampered = { ...at, subjectDid: "did:key:zImposter" };
    const result = verifyAttestation(tampered);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toMatch(/signature/);
  });

  it("rejects tampered weight", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched", { weight: 10 });
    const tampered = { ...at, weight: 95 };
    expect(verifyAttestation(tampered).valid).toBe(false);
  });

  it("rejects tampered attestationType", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    const tampered = { ...at, attestationType: "kyc-verified" as const };
    expect(verifyAttestation(tampered).valid).toBe(false);
  });

  it("rejects when issuerDid does not match the public key", () => {
    const issuer = makeIdentity();
    const impostor = makeIdentity();
    const subject = makeIdentity();
    const at = createAttestation({
      subjectDid: subject.did,
      issuerDid: impostor.did, // lies about issuer
      issuerPublicKey: issuer.publicKey, // but signs with real key
      issuerSigningKey: issuer.kp.secretKey,
      attestationType: "peer-vouched",
      weight: 50,
    });
    // Signature itself is valid, but the DID/publicKey mismatch should be caught.
    const result = verifyAttestation(at);
    expect(result.valid).toBe(false);
  });

  it("supports evidence and customLabel fields", () => {
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "custom", {
      evidence: "abcd1234",
      customLabel: "github-verified",
    });
    expect(verifyAttestation(at).valid).toBe(true);
    expect(at.evidence).toBe("abcd1234");
    expect(at.customLabel).toBe("github-verified");
  });
});

describe("AttestationRegistry — basic add/get", () => {
  it("accepts valid attestations and stores by subject", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    expect(reg.add(at)).toBe(true);
    expect(reg.size).toBe(1);
    expect(reg.getForSubject(subject.did)).toHaveLength(1);
  });

  it("rejects invalid attestations", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    const tampered = { ...at, weight: 99 };
    expect(reg.add(tampered)).toBe(false);
    expect(reg.size).toBe(0);
  });

  it("rejects duplicates by id", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    expect(reg.add(at)).toBe(true);
    expect(reg.add(at)).toBe(false);
    expect(reg.size).toBe(1);
  });

  it("returns empty list for unknown subject", () => {
    const reg = new AttestationRegistry();
    expect(reg.getForSubject("did:key:zUnknown")).toEqual([]);
    expect(reg.getActiveForSubject("did:key:zUnknown")).toEqual([]);
  });
});

describe("AttestationRegistry — revocation and expiry", () => {
  it("marks attestations as inactive when revoked", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "peer-vouched");
    reg.add(at);
    expect(reg.isActive(at.id)).toBe(true);
    expect(reg.revoke(at.id)).toBe(true);
    expect(reg.isActive(at.id)).toBe(false);
  });

  it("revoke() returns false for unknown attestation", () => {
    const reg = new AttestationRegistry();
    expect(reg.revoke("at-nonexistent")).toBe(false);
  });

  it("filters revoked attestations out of active list", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const a1 = makeAttestation(issuer, subject.did, "peer-vouched");
    const a2 = makeAttestation(issuer, subject.did, "organization-member");
    reg.add(a1);
    reg.add(a2);
    reg.revoke(a1.id);
    const active = reg.getActiveForSubject(subject.did);
    expect(active).toHaveLength(1);
    expect(active[0]!.id).toBe(a2.id);
  });

  it("treats expired attestations as inactive", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const past = Date.now() - 1000;
    const at = makeAttestation(issuer, subject.did, "peer-vouched", {
      expiresAt: past,
    });
    reg.add(at);
    expect(reg.isActive(at.id)).toBe(false);
    expect(reg.getActiveForSubject(subject.did)).toEqual([]);
  });

  it("keeps un-expired attestations active", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const future = Date.now() + 1_000_000;
    const at = makeAttestation(issuer, subject.did, "peer-vouched", {
      expiresAt: future,
    });
    reg.add(at);
    expect(reg.isActive(at.id)).toBe(true);
    expect(reg.getActiveForSubject(subject.did)).toHaveLength(1);
  });

  it("getForSubject returns all including revoked/expired", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const a1 = makeAttestation(issuer, subject.did, "peer-vouched");
    const a2 = makeAttestation(issuer, subject.did, "stake-bonded", {
      expiresAt: Date.now() - 1,
    });
    reg.add(a1);
    reg.add(a2);
    reg.revoke(a1.id);
    expect(reg.getForSubject(subject.did)).toHaveLength(2);
    expect(reg.getActiveForSubject(subject.did)).toHaveLength(0);
  });
});

describe("AttestationRegistry — getTier", () => {
  it("returns 'anonymous' when no attestations", () => {
    const reg = new AttestationRegistry();
    expect(reg.getTier("did:key:zUnknown")).toBe("anonymous");
  });

  it("returns 'attested' with only peer-vouched or org-member", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched"));
    reg.add(makeAttestation(issuer, subject.did, "organization-member"));
    expect(reg.getTier(subject.did)).toBe("attested");
  });

  it("returns 'staked' with stake-bonded but no kyc", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "stake-bonded"));
    expect(reg.getTier(subject.did)).toBe("staked");
  });

  it("returns 'verified' with both kyc-verified and stake-bonded", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "kyc-verified"));
    reg.add(makeAttestation(issuer, subject.did, "stake-bonded"));
    expect(reg.getTier(subject.did)).toBe("verified");
  });

  it("returns 'attested' with kyc-verified alone (no stake)", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "kyc-verified"));
    expect(reg.getTier(subject.did)).toBe("attested");
  });

  it("drops tier when relevant attestation is revoked", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const stake = makeAttestation(issuer, subject.did, "stake-bonded");
    reg.add(stake);
    expect(reg.getTier(subject.did)).toBe("staked");
    reg.revoke(stake.id);
    expect(reg.getTier(subject.did)).toBe("anonymous");
  });

  it("honors trustedIssuers filter", () => {
    const reg = new AttestationRegistry();
    const trusted = makeIdentity();
    const untrusted = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(untrusted, subject.did, "kyc-verified"));
    reg.add(makeAttestation(untrusted, subject.did, "stake-bonded"));
    // with no filter, reaches "verified"
    expect(reg.getTier(subject.did)).toBe("verified");
    // but if we only trust 'trusted' issuer, falls back to anonymous
    expect(
      reg.getTier(subject.did, { trustedIssuers: [trusted.did] }),
    ).toBe("anonymous");
  });
});

describe("AttestationRegistry — getScore", () => {
  it("returns zero score for anonymous subject", () => {
    const reg = new AttestationRegistry();
    const s = reg.getScore("did:key:zNone");
    expect(s.score).toBe(0);
    expect(s.tier).toBe("anonymous");
    expect(s.attestationCount).toBe(0);
  });

  it("kyc attestation scores higher than peer-vouched with equal weight", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const peerSubject = makeIdentity();
    const kycSubject = makeIdentity();
    reg.add(makeAttestation(issuer, peerSubject.did, "peer-vouched", { weight: 50 }));
    reg.add(makeAttestation(issuer, kycSubject.did, "kyc-verified", { weight: 50 }));
    const peerScore = reg.getScore(peerSubject.did);
    const kycScore = reg.getScore(kycSubject.did);
    expect(kycScore.score).toBeGreaterThan(peerScore.score);
  });

  it("applies freshness decay to old attestations", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    // peer-vouched × 40 weight × 0.5 multiplier = 20 raw — below cap, decay visible.
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched", { weight: 40 }));
    const now = Date.now();
    const fresh = reg.getScore(subject.did, { now });
    // one half-life later → ~half the raw contribution
    const oneHalfLifeLater = now + 180 * 24 * 60 * 60 * 1000;
    const stale = reg.getScore(subject.did, { now: oneHalfLifeLater });
    expect(stale.score).toBeLessThan(fresh.score);
    expect(stale.score).toBeCloseTo(fresh.score * 0.5, 2);
  });

  it("caps score at 100", () => {
    const reg = new AttestationRegistry();
    const subject = makeIdentity();
    // Pile on many high-weight kyc attestations from different issuers
    for (let i = 0; i < 5; i++) {
      const issuer = makeIdentity();
      reg.add(makeAttestation(issuer, subject.did, "kyc-verified", { weight: 100 }));
    }
    const s = reg.getScore(subject.did);
    expect(s.score).toBe(100);
  });

  it("counts attestations by type", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched"));
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched"));
    reg.add(makeAttestation(issuer, subject.did, "stake-bonded"));
    const s = reg.getScore(subject.did);
    expect(s.countByType["peer-vouched"]).toBe(2);
    expect(s.countByType["stake-bonded"]).toBe(1);
    expect(s.attestationCount).toBe(3);
  });

  it("respects trustedIssuers filter in score", () => {
    const reg = new AttestationRegistry();
    const trusted = makeIdentity();
    const untrusted = makeIdentity();
    const subject = makeIdentity();
    // Use peer-vouched (mul 0.5) so we stay under the cap: 10*0.5 + 20*0.5 = 15 raw
    reg.add(makeAttestation(trusted, subject.did, "peer-vouched", { weight: 10 }));
    reg.add(makeAttestation(untrusted, subject.did, "peer-vouched", { weight: 20 }));
    const scoreAll = reg.getScore(subject.did);
    const scoreTrusted = reg.getScore(subject.did, {
      trustedIssuers: [trusted.did],
    });
    expect(scoreTrusted.score).toBeLessThan(scoreAll.score);
    expect(scoreTrusted.attestationCount).toBe(1);
  });

  it("honors custom typeMultipliers", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched", { weight: 50 }));
    const defaultScore = reg.getScore(subject.did);
    const boostedScore = reg.getScore(subject.did, {
      typeMultipliers: {
        "peer-vouched": 2.0,
        "time-in-network": 0.8,
        "organization-member": 1.5,
        "stake-bonded": 2.0,
        "kyc-verified": 2.5,
        "skill-verified": 1.2,
        custom: 1.0,
      },
    });
    expect(boostedScore.score).toBeGreaterThan(defaultScore.score);
  });

  it("excludes revoked attestations from score", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const at = makeAttestation(issuer, subject.did, "stake-bonded", { weight: 60 });
    reg.add(at);
    const before = reg.getScore(subject.did);
    reg.revoke(at.id);
    const after = reg.getScore(subject.did);
    expect(before.score).toBeGreaterThan(0);
    expect(after.score).toBe(0);
  });

  it("excludes expired attestations from score", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(
      makeAttestation(issuer, subject.did, "stake-bonded", {
        weight: 60,
        expiresAt: Date.now() - 1,
      }),
    );
    const s = reg.getScore(subject.did);
    expect(s.score).toBe(0);
    expect(s.attestationCount).toBe(0);
  });
});

describe("AttestationRegistry — import/export", () => {
  it("round-trips attestations", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    reg.add(makeAttestation(issuer, subject.did, "peer-vouched"));
    reg.add(makeAttestation(issuer, subject.did, "kyc-verified"));
    const dump = reg.export();
    expect(dump).toHaveLength(2);

    const reg2 = new AttestationRegistry();
    expect(reg2.import(dump)).toBe(2);
    expect(reg2.size).toBe(2);
    expect(reg2.getForSubject(subject.did)).toHaveLength(2);
  });

  it("re-verifies signatures on import — drops tampered entries", () => {
    const reg = new AttestationRegistry();
    const issuer = makeIdentity();
    const subject = makeIdentity();
    const good = makeAttestation(issuer, subject.did, "peer-vouched");
    const bad = { ...makeAttestation(issuer, subject.did, "peer-vouched"), weight: 99 };
    const reg2 = new AttestationRegistry();
    expect(reg2.import([good, bad])).toBe(1);
    expect(reg2.size).toBe(1);
  });
});
