import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  SystemTimeSource,
  MonotonicTimeSource,
  issueTimeWitness,
  verifyTimeWitness,
  verifyWitnessQuorum,
  type TimeSource,
  type TimeWitness,
} from "../../src/heart/time-oracle.js";

const crypto = getCryptoProvider();

function makeAuthority() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  };
}

class FakeTimeSource implements TimeSource {
  readonly kind = "fake";
  constructor(private t: number) {}
  now(): number {
    return this.t;
  }
  set(t: number) {
    this.t = t;
  }
}

describe("SystemTimeSource", () => {
  it("returns current time close to Date.now()", () => {
    const s = new SystemTimeSource();
    const before = Date.now();
    const t = s.now();
    const after = Date.now();
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(after);
  });
});

describe("MonotonicTimeSource", () => {
  it("advances forward normally", () => {
    const fake = new FakeTimeSource(1000);
    const mono = new MonotonicTimeSource(fake);
    expect(mono.now()).toBe(1000);
    fake.set(2000);
    expect(mono.now()).toBe(2000);
    fake.set(3000);
    expect(mono.now()).toBe(3000);
  });

  it("refuses to go backwards when underlying clock jumps back", () => {
    const fake = new FakeTimeSource(5000);
    const mono = new MonotonicTimeSource(fake);
    expect(mono.now()).toBe(5000);
    fake.set(3000); // clock moved backwards
    expect(mono.now()).toBe(5001); // monotonic guard: last+1
    expect(mono.now()).toBe(5002);
  });

  it("allows forward progress after guard kicks in", () => {
    const fake = new FakeTimeSource(5000);
    const mono = new MonotonicTimeSource(fake);
    mono.now();
    fake.set(4000);
    expect(mono.now()).toBe(5001);
    fake.set(10000);
    expect(mono.now()).toBe(10000);
  });
});

describe("issueTimeWitness + verifyTimeWitness", () => {
  it("issues a valid witness that verifies", () => {
    const a = makeAuthority();
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
    });
    expect(w.authorityDid).toBe(a.did);
    expect(verifyTimeWitness(w).valid).toBe(true);
  });

  it("detects tampered observedAt", () => {
    const a = makeAuthority();
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
    });
    const tampered = { ...w, observedAt: 0 };
    expect(verifyTimeWitness(tampered).valid).toBe(false);
  });

  it("nonce is bound to the signature", () => {
    const a = makeAuthority();
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
      nonce: "challenge-xyz",
    });
    expect(w.nonce).toBe("challenge-xyz");
    // right nonce
    expect(verifyTimeWitness(w, { expectedNonce: "challenge-xyz" }).valid).toBe(true);
    // wrong nonce
    const bad = verifyTimeWitness(w, { expectedNonce: "challenge-abc" });
    expect(bad.valid).toBe(false);
    if (!bad.valid) expect(bad.reason).toContain("nonce");
  });

  it("rejects swapped nonce (tamper)", () => {
    const a = makeAuthority();
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
      nonce: "orig",
    });
    const tampered = { ...w, nonce: "attack" };
    expect(verifyTimeWitness(tampered).valid).toBe(false);
  });

  it("rejects stale witness beyond maxAge", () => {
    const a = makeAuthority();
    const fake = new FakeTimeSource(1000);
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
      time: fake,
    });
    const result = verifyTimeWitness(w, { maxAgeMs: 100, now: 2000 });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("stale");
  });

  it("accepts fresh witness within maxAge", () => {
    const a = makeAuthority();
    const fake = new FakeTimeSource(1000);
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
      time: fake,
    });
    const result = verifyTimeWitness(w, { maxAgeMs: 500, now: 1200 });
    expect(result.valid).toBe(true);
  });

  it("rejects witness from too far future", () => {
    const a = makeAuthority();
    const fake = new FakeTimeSource(10000);
    const w = issueTimeWitness({
      authoritySecretKey: a.secretKey,
      authorityPublicKey: a.publicKey,
      time: fake,
    });
    const result = verifyTimeWitness(w, { maxSkewMs: 100, now: 1000 });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("future");
  });

  it("enforces trustedAuthorities allowlist", () => {
    const trusted = makeAuthority();
    const rogue = makeAuthority();
    const wTrusted = issueTimeWitness({
      authoritySecretKey: trusted.secretKey,
      authorityPublicKey: trusted.publicKey,
    });
    const wRogue = issueTimeWitness({
      authoritySecretKey: rogue.secretKey,
      authorityPublicKey: rogue.publicKey,
    });
    expect(
      verifyTimeWitness(wTrusted, { trustedAuthorities: [trusted.did] }).valid,
    ).toBe(true);
    expect(
      verifyTimeWitness(wRogue, { trustedAuthorities: [trusted.did] }).valid,
    ).toBe(false);
  });
});

describe("verifyWitnessQuorum", () => {
  function witnessAt(authority: ReturnType<typeof makeAuthority>, t: number, nonce?: string) {
    return issueTimeWitness({
      authoritySecretKey: authority.secretKey,
      authorityPublicKey: authority.publicKey,
      nonce,
      time: new FakeTimeSource(t),
    });
  }

  it("accepts M-of-N with 3 valid witnesses, threshold=2", () => {
    const a = makeAuthority();
    const b = makeAuthority();
    const c = makeAuthority();
    const ws: TimeWitness[] = [
      witnessAt(a, 1000),
      witnessAt(b, 1005),
      witnessAt(c, 1010),
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 2,
      trustedAuthorities: [a.did, b.did, c.did],
      now: 1100,
      maxAgeMs: 500,
    });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.acceptedAuthorities.length).toBe(3);
      expect(result.medianTime).toBe(1005);
    }
  });

  it("rejects when fewer than threshold witnesses pass", () => {
    const a = makeAuthority();
    const b = makeAuthority();
    // b's witness is stale; only a counts
    const ws: TimeWitness[] = [
      witnessAt(a, 1000),
      witnessAt(b, 100), // way too old
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 2,
      trustedAuthorities: [a.did, b.did],
      now: 1100,
      maxAgeMs: 500,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("insufficient");
  });

  it("counts duplicate authority DIDs only once", () => {
    const a = makeAuthority();
    const ws: TimeWitness[] = [
      witnessAt(a, 1000),
      witnessAt(a, 1001), // same authority, different witness
      witnessAt(a, 1002),
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 2,
      trustedAuthorities: [a.did],
      now: 1100,
      maxAgeMs: 500,
    });
    // Only 1 distinct authority accepted, need 2
    expect(result.valid).toBe(false);
  });

  it("rejects when drift exceeds maxDrift", () => {
    const a = makeAuthority();
    const b = makeAuthority();
    const c = makeAuthority();
    const ws: TimeWitness[] = [
      witnessAt(a, 1000),
      witnessAt(b, 1100),
      witnessAt(c, 5000), // huge drift
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 3,
      trustedAuthorities: [a.did, b.did, c.did],
      now: 5100,
      maxAgeMs: 10000,
      maxDriftMs: 500,
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("drift");
  });

  it("accepts within maxDrift", () => {
    const a = makeAuthority();
    const b = makeAuthority();
    const ws: TimeWitness[] = [
      witnessAt(a, 1000),
      witnessAt(b, 1020),
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 2,
      trustedAuthorities: [a.did, b.did],
      now: 1100,
      maxAgeMs: 500,
      maxDriftMs: 100,
    });
    expect(result.valid).toBe(true);
  });

  it("requires nonce to match across quorum", () => {
    const a = makeAuthority();
    const b = makeAuthority();
    const ws: TimeWitness[] = [
      witnessAt(a, 1000, "challenge-X"),
      witnessAt(b, 1005, "challenge-Y"), // wrong nonce
    ];
    const result = verifyWitnessQuorum(ws, {
      threshold: 2,
      trustedAuthorities: [a.did, b.did],
      expectedNonce: "challenge-X",
      now: 1100,
      maxAgeMs: 500,
    });
    expect(result.valid).toBe(false); // only a passes
  });
});
