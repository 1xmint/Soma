import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  evaluateVrf,
  verifyVrf,
  outputToInt,
  combineBeacon,
  type VrfOutput,
} from "../../src/heart/vrf.js";

const crypto = getCryptoProvider();

function makeParty() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function evalAt(party: ReturnType<typeof makeParty>, input: Uint8Array) {
  return evaluateVrf({
    input,
    signingKey: party.kp.secretKey,
    publicKey: party.kp.publicKey,
  });
}

describe("VRF: basic evaluate + verify", () => {
  it("evaluates and verifies", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("epoch-42");
    const out = evalAt(alice, input);
    const r = verifyVrf(input, out);
    expect(r.valid).toBe(true);
    if (r.valid) expect(r.output).toHaveLength(32);
  });

  it("output is 32 bytes (SHA-256)", () => {
    const alice = makeParty();
    const out = evalAt(alice, new TextEncoder().encode("x"));
    expect(crypto.encoding.decodeBase64(out.outputB64)).toHaveLength(32);
  });

  it("proof is 64 bytes (Ed25519)", () => {
    const alice = makeParty();
    const out = evalAt(alice, new TextEncoder().encode("x"));
    expect(crypto.encoding.decodeBase64(out.proofB64)).toHaveLength(64);
  });

  it("includes evaluator's DID", () => {
    const alice = makeParty();
    const out = evalAt(alice, new TextEncoder().encode("x"));
    expect(out.evaluatorDid).toBe(alice.did);
  });
});

describe("VRF: determinism", () => {
  it("same (sk, input) → same output", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("epoch-42");
    const out1 = evalAt(alice, input);
    const out2 = evalAt(alice, input);
    expect(out1.outputB64).toBe(out2.outputB64);
    expect(out1.proofB64).toBe(out2.proofB64);
  });

  it("different input → different output", () => {
    const alice = makeParty();
    const out1 = evalAt(alice, new TextEncoder().encode("epoch-1"));
    const out2 = evalAt(alice, new TextEncoder().encode("epoch-2"));
    expect(out1.outputB64).not.toBe(out2.outputB64);
  });

  it("different sk → different output (same input)", () => {
    const alice = makeParty();
    const bob = makeParty();
    const input = new TextEncoder().encode("same-input");
    const outA = evalAt(alice, input);
    const outB = evalAt(bob, input);
    expect(outA.outputB64).not.toBe(outB.outputB64);
  });
});

describe("VRF: verification failures", () => {
  it("rejects wrong input", () => {
    const alice = makeParty();
    const out = evalAt(alice, new TextEncoder().encode("x"));
    const r = verifyVrf(new TextEncoder().encode("y"), out);
    expect(r.valid).toBe(false);
  });

  it("rejects tampered output", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("x");
    const out = evalAt(alice, input);
    const bad: VrfOutput = {
      ...out,
      outputB64: crypto.encoding.encodeBase64(crypto.random.randomBytes(32)),
    };
    const r = verifyVrf(input, bad);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/output/);
  });

  it("rejects tampered proof", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("x");
    const out = evalAt(alice, input);
    const bad: VrfOutput = {
      ...out,
      proofB64: crypto.encoding.encodeBase64(crypto.random.randomBytes(64)),
    };
    const r = verifyVrf(input, bad);
    expect(r.valid).toBe(false);
  });

  it("rejects proof from wrong key", () => {
    const alice = makeParty();
    const bob = makeParty();
    const input = new TextEncoder().encode("x");
    const outA = evalAt(alice, input);
    // Claim it's bob's by swapping identities but keep alice's proof.
    const forged: VrfOutput = {
      ...outA,
      evaluatorDid: bob.did,
      evaluatorPublicKey: bob.publicKey,
    };
    const r = verifyVrf(input, forged);
    expect(r.valid).toBe(false);
  });

  it("rejects DID/key mismatch", () => {
    const alice = makeParty();
    const bob = makeParty();
    const input = new TextEncoder().encode("x");
    const out = evalAt(alice, input);
    const forged: VrfOutput = { ...out, evaluatorDid: bob.did };
    const r = verifyVrf(input, forged);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/evaluatorDid/);
  });

  it("rejects malformed base64", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("x");
    const out = evalAt(alice, input);
    const bad: VrfOutput = { ...out, outputB64: "!!!not-base64!!!" };
    const r = verifyVrf(input, bad);
    expect(r.valid).toBe(false);
  });
});

describe("VRF: outputToInt (rejection sampling)", () => {
  it("produces integers in range [0, bound)", () => {
    const alice = makeParty();
    for (let i = 0; i < 10; i++) {
      const out = evalAt(alice, new TextEncoder().encode(`test-${i}`));
      const bytes = crypto.encoding.decodeBase64(out.outputB64);
      const n = outputToInt(bytes, 100);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThan(100);
    }
  });

  it("deterministic for same bytes", () => {
    const alice = makeParty();
    const out = evalAt(alice, new TextEncoder().encode("test"));
    const bytes = crypto.encoding.decodeBase64(out.outputB64);
    const n1 = outputToInt(bytes, 1000);
    const n2 = outputToInt(bytes, 1000);
    expect(n1).toBe(n2);
  });

  it("rejects invalid bounds", () => {
    const bytes = new Uint8Array(32).fill(1);
    expect(() => outputToInt(bytes, 0)).toThrow();
    expect(() => outputToInt(bytes, -1)).toThrow();
    expect(() => outputToInt(bytes, 2 ** 32 + 1)).toThrow();
  });

  it("distribution is roughly uniform over 200 samples", () => {
    const alice = makeParty();
    const buckets = new Array(5).fill(0);
    for (let i = 0; i < 200; i++) {
      const out = evalAt(alice, new TextEncoder().encode(`sample-${i}`));
      const bytes = crypto.encoding.decodeBase64(out.outputB64);
      const n = outputToInt(bytes, 5);
      buckets[n]!++;
    }
    // Each bucket should have roughly 40, allow 20..60 for noise.
    for (const count of buckets) {
      expect(count).toBeGreaterThan(20);
      expect(count).toBeLessThan(60);
    }
  });
});

describe("VRF: leader election pattern", () => {
  it("lowest VRF output picks a unique winner", () => {
    const parties = [makeParty(), makeParty(), makeParty()];
    const input = new TextEncoder().encode("epoch-1-leader-election");
    const outputs = parties.map((p) => ({
      party: p,
      vrf: evalAt(p, input),
    }));
    // All outputs verify
    for (const o of outputs) {
      expect(verifyVrf(input, o.vrf).valid).toBe(true);
    }
    // Pick winner: lowest outputB64 (deterministic)
    outputs.sort((a, b) =>
      a.vrf.outputB64 < b.vrf.outputB64
        ? -1
        : a.vrf.outputB64 > b.vrf.outputB64
          ? 1
          : 0,
    );
    // Winner is stable across independent evaluations
    const outputs2 = parties.map((p) => ({
      party: p,
      vrf: evalAt(p, input),
    }));
    outputs2.sort((a, b) =>
      a.vrf.outputB64 < b.vrf.outputB64
        ? -1
        : a.vrf.outputB64 > b.vrf.outputB64
          ? 1
          : 0,
    );
    expect(outputs[0]!.party.did).toBe(outputs2[0]!.party.did);
  });
});

describe("VRF: beacon combination", () => {
  it("combines outputs into a single beacon hash", () => {
    const parties = [makeParty(), makeParty(), makeParty()];
    const input = new TextEncoder().encode("round-1");
    const vrfs = parties.map((p) => evalAt(p, input));
    const beacon = combineBeacon(vrfs);
    expect(beacon).toMatch(/^[0-9a-f]{64}$/);
  });

  it("beacon is order-independent", () => {
    const parties = [makeParty(), makeParty(), makeParty()];
    const input = new TextEncoder().encode("round-1");
    const vrfs = parties.map((p) => evalAt(p, input));
    const b1 = combineBeacon(vrfs);
    const b2 = combineBeacon([...vrfs].reverse());
    const b3 = combineBeacon([vrfs[1]!, vrfs[0]!, vrfs[2]!]);
    expect(b1).toBe(b2);
    expect(b1).toBe(b3);
  });

  it("different participants → different beacon", () => {
    const set1 = [makeParty(), makeParty()];
    const set2 = [makeParty(), makeParty()];
    const input = new TextEncoder().encode("round-1");
    const v1 = set1.map((p) => evalAt(p, input));
    const v2 = set2.map((p) => evalAt(p, input));
    expect(combineBeacon(v1)).not.toBe(combineBeacon(v2));
  });

  it("throws on empty set", () => {
    expect(() => combineBeacon([])).toThrow(/at least one/);
  });
});

describe("VRF: domain separation", () => {
  it("VRF proof is not usable as a standalone signature on the raw input", () => {
    const alice = makeParty();
    const input = new TextEncoder().encode("my-input");
    const vrf = evalAt(alice, input);
    // The proof was over "soma-vrf-input:v1:" || input — verifying against
    // the raw input (without the prefix) should fail.
    const proofBytes = crypto.encoding.decodeBase64(vrf.proofB64);
    const pubKeyBytes = crypto.encoding.decodeBase64(alice.publicKey);
    expect(
      crypto.signing.verify(input, proofBytes, pubKeyBytes),
    ).toBe(false);
  });
});
