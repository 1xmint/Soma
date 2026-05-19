import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import type { SigningProvider } from "../../src/core/crypto-provider.js";
import {
  AlgorithmRegistry,
  generateHybridKeyPair,
  hybridSign,
  verifyHybridSignature,
  hybridPublicKeys,
  hybridFingerprint,
  type HybridSignature,
} from "../../src/heart/hybrid-signing.js";

const crypto = getCryptoProvider();

function msg(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/**
 * Mock "PQ" signing provider — NOT real post-quantum crypto. Uses
 * Ed25519 under the hood but advertises a different algorithmId so
 * tests exercise the composite envelope format. When a real ML-DSA
 * provider ships, these tests continue to apply unchanged.
 */
function mockPqProvider(algorithmId: string): SigningProvider {
  const ed = crypto.signing;
  return {
    algorithmId,
    multicodecPrefix: new Uint8Array([0x00, 0x00]),
    generateKeyPair: () => ed.generateKeyPair(),
    sign: (m, sk) => ed.sign(m, sk),
    verify: (m, s, pk) => ed.verify(m, s, pk),
  };
}

function buildRegistry(): AlgorithmRegistry {
  const reg = new AlgorithmRegistry();
  reg.register(crypto.signing);
  reg.register(mockPqProvider("ml-dsa-65-mock"));
  return reg;
}

// ─── AlgorithmRegistry ──────────────────────────────────────────────────────

describe("AlgorithmRegistry", () => {
  it("registers and retrieves providers by id", () => {
    const reg = new AlgorithmRegistry();
    reg.register(crypto.signing);
    expect(reg.has("ed25519")).toBe(true);
    expect(reg.get("ed25519").algorithmId).toBe("ed25519");
    expect(reg.size()).toBe(1);
  });

  it("rejects duplicate registration", () => {
    const reg = new AlgorithmRegistry();
    reg.register(crypto.signing);
    expect(() => reg.register(crypto.signing)).toThrow(/already registered/);
  });

  it("throws on unknown algorithm", () => {
    const reg = new AlgorithmRegistry();
    expect(() => reg.get("ghost")).toThrow(/no provider/);
  });

  it("lists algorithms sorted", () => {
    const reg = buildRegistry();
    expect(reg.list()).toEqual(["ed25519", "ml-dsa-65-mock"]);
  });
});

// ─── generateHybridKeyPair ──────────────────────────────────────────────────

describe("generateHybridKeyPair", () => {
  it("produces one key pair per algorithm, in order", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    expect(kp.algorithms).toHaveLength(2);
    expect(kp.algorithms[0].algorithmId).toBe("ed25519");
    expect(kp.algorithms[1].algorithmId).toBe("ml-dsa-65-mock");
    expect(kp.algorithms[0].publicKey).toHaveLength(32);
    expect(kp.algorithms[0].secretKey).toHaveLength(64);
  });

  it("rejects empty algorithm list", () => {
    const reg = buildRegistry();
    expect(() => generateHybridKeyPair([], reg)).toThrow(/at least one/);
  });

  it("rejects duplicate algorithms", () => {
    const reg = buildRegistry();
    expect(() =>
      generateHybridKeyPair(["ed25519", "ed25519"], reg),
    ).toThrow(/duplicate/);
  });

  it("throws if algorithm not registered", () => {
    const reg = new AlgorithmRegistry();
    reg.register(crypto.signing);
    expect(() =>
      generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg),
    ).toThrow(/no provider/);
  });
});

// ─── hybridSign / verifyHybridSignature ─────────────────────────────────────

describe("hybridSign + verifyHybridSignature", () => {
  it("round-trips under require-all", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, { type: "require-all" });
    expect(v.ok).toBe(true);
    expect(v.verifiedAlgorithms.sort()).toEqual(["ed25519", "ml-dsa-65-mock"]);
    expect(v.failedAlgorithms).toEqual([]);
  });

  it("round-trips under require-any", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, { type: "require-any" });
    expect(v.ok).toBe(true);
    expect(v.verifiedAlgorithms).toEqual(["ed25519"]);
  });

  it("envelope carries both public keys in canonical order", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    expect(sig.algorithms).toEqual(["ed25519", "ml-dsa-65-mock"]);
    expect(sig.publicKeysB64).toHaveLength(2);
    expect(sig.signatures).toHaveLength(2);
  });

  it("rejects signing with empty key pair", () => {
    const reg = buildRegistry();
    expect(() =>
      hybridSign({ algorithms: [] }, msg("m"), reg),
    ).toThrow(/empty/);
  });

  it("fails when message is different at verify time", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("original"), reg);
    const v = verifyHybridSignature(sig, msg("tampered"), reg, {
      type: "require-all",
    });
    expect(v.ok).toBe(false);
    expect(v.verifiedAlgorithms).toEqual([]);
    expect(v.failedAlgorithms.sort()).toEqual(["ed25519", "ml-dsa-65-mock"]);
  });

  it("fails when a single signature is tampered", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const tampered: HybridSignature = {
      ...sig,
      signatures: [
        { ...sig.signatures[0], signatureB64: sig.signatures[1].signatureB64 },
        sig.signatures[1],
      ],
    };
    const v = verifyHybridSignature(tampered, msg("m"), reg, {
      type: "require-all",
    });
    expect(v.ok).toBe(false);
    // Second algorithm still verifies, only first fails.
    expect(v.failedAlgorithms).toContain(sig.signatures[0].algorithmId);
  });
});

// ─── Cross-algorithm key substitution ──────────────────────────────────────

describe("binding protects against key substitution", () => {
  it("substituted public key breaks all signatures", () => {
    const reg = buildRegistry();
    const victim = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const attackerKp = generateHybridKeyPair(["ml-dsa-65-mock"], reg);
    const sig = hybridSign(victim, msg("m"), reg);
    // Attacker swaps victim's PQ public key for their own.
    const attackerPqPkB64 = crypto.encoding.encodeBase64(
      attackerKp.algorithms[0].publicKey,
    );
    const tampered: HybridSignature = {
      ...sig,
      publicKeysB64: [sig.publicKeysB64[0], attackerPqPkB64],
    };
    const v = verifyHybridSignature(tampered, msg("m"), reg, {
      type: "require-any",
    });
    // Both sigs signed over a binding with the ORIGINAL pk set. Changing
    // the pk breaks the binding, so neither sig verifies.
    expect(v.ok).toBe(false);
  });
});

// ─── Verification policies ──────────────────────────────────────────────────

describe("verification policies", () => {
  it("require-all fails if any sig is bad", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const tampered: HybridSignature = {
      ...sig,
      signatures: [
        sig.signatures[0],
        {
          algorithmId: sig.signatures[1].algorithmId,
          signatureB64: crypto.encoding.encodeBase64(new Uint8Array(64)),
        },
      ],
    };
    const v = verifyHybridSignature(tampered, msg("m"), reg, {
      type: "require-all",
    });
    expect(v.ok).toBe(false);
  });

  it("require-any succeeds if at least one sig is good", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const tampered: HybridSignature = {
      ...sig,
      signatures: [
        sig.signatures[0], // still valid
        {
          algorithmId: sig.signatures[1].algorithmId,
          signatureB64: crypto.encoding.encodeBase64(new Uint8Array(64)),
        },
      ],
    };
    const v = verifyHybridSignature(tampered, msg("m"), reg, {
      type: "require-any",
    });
    expect(v.ok).toBe(true);
    expect(v.verifiedAlgorithms).toEqual(["ed25519"]);
  });

  it("require-algorithms enforces named set", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "require-algorithms",
      algorithms: ["ml-dsa-65-mock"],
    });
    expect(v.ok).toBe(true);
  });

  it("require-algorithms fails if a required algo is absent", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "require-algorithms",
      algorithms: ["ml-dsa-65-mock"],
    });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/missing required/);
  });

  it("require-algorithms with empty list fails closed", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "require-algorithms",
      algorithms: [],
    });
    expect(v.ok).toBe(false);
  });

  it("prefer-pq enforces minimum PQ count", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "prefer-pq",
      pqAlgorithms: ["ml-dsa-65-mock", "slh-dsa-mock"],
      minPq: 1,
    });
    expect(v.ok).toBe(true);
  });

  it("prefer-pq fails if not enough PQ sigs present", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "prefer-pq",
      pqAlgorithms: ["ml-dsa-65-mock"],
      minPq: 1,
    });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/need 1 PQ/);
  });

  it("prefer-pq with minPq=2 fails when only 1 PQ algo registered", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const v = verifyHybridSignature(sig, msg("m"), reg, {
      type: "prefer-pq",
      pqAlgorithms: ["ml-dsa-65-mock", "slh-dsa-mock"],
      minPq: 2,
    });
    expect(v.ok).toBe(false);
  });
});

// ─── Forward compat: unknown algorithms ─────────────────────────────────────

describe("forward compatibility", () => {
  it("unknown algorithm in envelope counts as failure, not crash", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    // Verifier registry only knows ed25519.
    const limited = new AlgorithmRegistry();
    limited.register(crypto.signing);
    const v = verifyHybridSignature(sig, msg("m"), limited, {
      type: "require-any",
    });
    // ed25519 still verifies; unknown ml-dsa-65-mock counts as failed.
    expect(v.ok).toBe(true);
    expect(v.verifiedAlgorithms).toEqual(["ed25519"]);
    expect(v.failedAlgorithms).toEqual(["ml-dsa-65-mock"]);
  });

  it("require-all fails when verifier lacks a provider for an advertised algo", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const limited = new AlgorithmRegistry();
    limited.register(crypto.signing);
    const v = verifyHybridSignature(sig, msg("m"), limited, {
      type: "require-all",
    });
    expect(v.ok).toBe(false);
    expect(v.failedAlgorithms).toEqual(["ml-dsa-65-mock"]);
  });

  it("unsupported version fails closed", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const bad = { ...sig, version: 99 as unknown as 1 };
    const v = verifyHybridSignature(bad, msg("m"), reg, { type: "require-any" });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/unsupported/);
  });

  it("length mismatch fails closed", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const bad: HybridSignature = {
      ...sig,
      publicKeysB64: [sig.publicKeysB64[0]],
    };
    const v = verifyHybridSignature(bad, msg("m"), reg, { type: "require-any" });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/length mismatch/);
  });

  it("duplicate algorithm in envelope fails closed", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    const bad: HybridSignature = {
      ...sig,
      algorithms: ["ed25519", "ed25519"],
      publicKeysB64: [sig.publicKeysB64[0], sig.publicKeysB64[0]],
    };
    const v = verifyHybridSignature(bad, msg("m"), reg, { type: "require-any" });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/duplicate algorithm/);
  });

  it("missing signature for advertised algo is treated as failure", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const sig = hybridSign(kp, msg("m"), reg);
    // Drop the PQ signature while keeping it advertised.
    const stripped: HybridSignature = {
      ...sig,
      signatures: [sig.signatures[0]],
    };
    const v = verifyHybridSignature(stripped, msg("m"), reg, {
      type: "require-all",
    });
    expect(v.ok).toBe(false);
    expect(v.failedAlgorithms).toContain("ml-dsa-65-mock");
  });
});

// ─── Helpers ────────────────────────────────────────────────────────────────

describe("hybridPublicKeys", () => {
  it("returns public keys without secret material", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const pks = hybridPublicKeys(kp);
    expect(pks).toHaveLength(2);
    expect(pks[0]).toHaveProperty("publicKey");
    expect(pks[0]).not.toHaveProperty("secretKey");
  });
});

describe("hybridFingerprint", () => {
  it("is stable for same key set", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const pks = hybridPublicKeys(kp);
    const f1 = hybridFingerprint(pks);
    const f2 = hybridFingerprint(pks);
    expect(f1).toBe(f2);
    expect(f1).toMatch(/^soma-hybrid-fp:v1:[0-9a-f]{64}$/);
  });

  it("differs when any public key changes", () => {
    const reg = buildRegistry();
    const kp1 = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const kp2 = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    expect(hybridFingerprint(hybridPublicKeys(kp1))).not.toBe(
      hybridFingerprint(hybridPublicKeys(kp2)),
    );
  });

  it("differs when algorithm set changes", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const full = hybridFingerprint(hybridPublicKeys(kp));
    const ed25519Only = hybridFingerprint([hybridPublicKeys(kp)[0]]);
    expect(full).not.toBe(ed25519Only);
  });

  it("order-dependent — same keys different order produce different fingerprints", () => {
    const reg = buildRegistry();
    const kp = generateHybridKeyPair(["ed25519", "ml-dsa-65-mock"], reg);
    const pks = hybridPublicKeys(kp);
    const reversed = [...pks].reverse();
    expect(hybridFingerprint(pks)).not.toBe(hybridFingerprint(reversed));
  });
});
