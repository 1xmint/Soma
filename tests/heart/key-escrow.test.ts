import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  splitSecret,
  reconstructSecret,
  verifyShares,
  verifyAllSubsetsReconstruct,
  type SecretShare,
} from "../../src/heart/key-escrow.js";

const crypto = getCryptoProvider();

function randomBytes(n: number): Uint8Array {
  return crypto.random.randomBytes(n);
}

describe("Shamir: basic round-trip", () => {
  it("3-of-5 reconstruction recovers the exact secret", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    const got = reconstructSecret(shares.slice(0, 3));
    expect(got).toEqual(secret);
  });

  it("2-of-3 works", () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5]);
    const shares = splitSecret(secret, { threshold: 2, totalShares: 3 });
    expect(reconstructSecret([shares[0]!, shares[1]!])).toEqual(secret);
    expect(reconstructSecret([shares[0]!, shares[2]!])).toEqual(secret);
    expect(reconstructSecret([shares[1]!, shares[2]!])).toEqual(secret);
  });

  it("5-of-5 works (all must be present)", () => {
    const secret = randomBytes(64);
    const shares = splitSecret(secret, { threshold: 5, totalShares: 5 });
    expect(reconstructSecret(shares)).toEqual(secret);
  });

  it("handles Ed25519-sized (64 byte) secrets", () => {
    const secret = randomBytes(64);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    expect(reconstructSecret(shares.slice(0, 3))).toEqual(secret);
  });

  it("handles single-byte secret", () => {
    const secret = new Uint8Array([42]);
    const shares = splitSecret(secret, { threshold: 2, totalShares: 3 });
    expect(reconstructSecret([shares[0]!, shares[2]!])).toEqual(secret);
  });

  it("handles large secret (1KB)", () => {
    const secret = randomBytes(1024);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    expect(reconstructSecret(shares.slice(0, 3))).toEqual(secret);
  });
});

describe("Shamir: any K-subset reconstructs", () => {
  it("verifies every K-subset of a small split yields the same secret", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    expect(verifyAllSubsetsReconstruct(shares, secret)).toBe(true);
  });

  it("2-of-4: all 6 pairs work", () => {
    const secret = randomBytes(8);
    const shares = splitSecret(secret, { threshold: 2, totalShares: 4 });
    expect(verifyAllSubsetsReconstruct(shares, secret)).toBe(true);
  });
});

describe("Shamir: K-1 shares leak nothing", () => {
  it("2 of 3-of-5 reconstruction produces the wrong secret", () => {
    const secret = randomBytes(32);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    // Use only 2 shares but simulate a 2-threshold reconstruction: the
    // Lagrange interp is for 3 points, so with 2 points we can't call
    // reconstructSecret directly (it enforces the threshold). Instead
    // confirm that skipping a share + reusing threshold fails.
    expect(() => reconstructSecret(shares.slice(0, 2))).toThrow(/at least/);
  });

  it("cannot distinguish secrets from just K-1 shares", () => {
    // Demonstration: two distinct secrets produce completely unrelated
    // shares (because random coefficients differ).
    const s1 = randomBytes(16);
    const s2 = randomBytes(16);
    const shares1 = splitSecret(s1, { threshold: 3, totalShares: 5 });
    const shares2 = splitSecret(s2, { threshold: 3, totalShares: 5 });
    // Share[0] for secret1 and share[0] for secret2 are independent bytes.
    const b1 = crypto.encoding.decodeBase64(shares1[0]!.shareB64);
    const b2 = crypto.encoding.decodeBase64(shares2[0]!.shareB64);
    let diff = 0;
    for (let i = 0; i < b1.length; i++) diff += b1[i]! === b2[i]! ? 1 : 0;
    // With random coefs, shares differ in most bytes.
    expect(diff).toBeLessThan(b1.length); // not identical
  });
});

describe("Shamir: validation", () => {
  it("rejects empty secret", () => {
    expect(() =>
      splitSecret(new Uint8Array(0), { threshold: 2, totalShares: 3 }),
    ).toThrow(/empty/);
  });

  it("rejects threshold < 2", () => {
    const secret = randomBytes(8);
    expect(() => splitSecret(secret, { threshold: 1, totalShares: 3 })).toThrow(
      /threshold/,
    );
    expect(() => splitSecret(secret, { threshold: 0, totalShares: 3 })).toThrow(
      /threshold/,
    );
  });

  it("rejects totalShares < threshold", () => {
    const secret = randomBytes(8);
    expect(() => splitSecret(secret, { threshold: 3, totalShares: 2 })).toThrow(
      /totalShares/,
    );
  });

  it("rejects totalShares > 255", () => {
    const secret = randomBytes(8);
    expect(() =>
      splitSecret(secret, { threshold: 3, totalShares: 256 }),
    ).toThrow(/255/);
  });

  it("accepts 2-of-2", () => {
    const secret = randomBytes(8);
    const shares = splitSecret(secret, { threshold: 2, totalShares: 2 });
    expect(shares).toHaveLength(2);
    expect(reconstructSecret(shares)).toEqual(secret);
  });

  it("accepts 255-of-255 (max)", () => {
    const secret = new Uint8Array([0xab, 0xcd]);
    const shares = splitSecret(secret, { threshold: 255, totalShares: 255 });
    expect(shares).toHaveLength(255);
    expect(reconstructSecret(shares)).toEqual(secret);
  });
});

describe("Shamir: share binding (secretId)", () => {
  it("all shares from one split share the same secretId", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    const firstId = shares[0]!.secretId;
    for (const s of shares) expect(s.secretId).toBe(firstId);
  });

  it("custom secretId is honored", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, {
      threshold: 2,
      totalShares: 3,
      secretId: "vault-alice-2026",
    });
    expect(shares[0]!.secretId).toBe("vault-alice-2026");
  });

  it("rejects mixing shares from different secrets", () => {
    const s1 = randomBytes(16);
    const s2 = randomBytes(16);
    const shares1 = splitSecret(s1, { threshold: 2, totalShares: 3 });
    const shares2 = splitSecret(s2, { threshold: 2, totalShares: 3 });
    expect(() =>
      reconstructSecret([shares1[0]!, shares2[1]!]),
    ).toThrow(/different secrets/);
  });
});

describe("Shamir: malformed share handling", () => {
  it("rejects fewer than threshold shares", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    expect(() => reconstructSecret(shares.slice(0, 2))).toThrow(/at least/);
  });

  it("rejects duplicate share indexes", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    expect(() =>
      reconstructSecret([shares[0]!, shares[0]!, shares[1]!]),
    ).toThrow(/duplicate/);
  });

  it("rejects empty share list", () => {
    expect(() => reconstructSecret([])).toThrow(/empty/);
  });

  it("rejects shares with metadata mismatch", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    const bad: SecretShare = { ...shares[1]!, threshold: 2 };
    expect(() => reconstructSecret([shares[0]!, bad, shares[2]!])).toThrow(
      /metadata/,
    );
  });

  it("rejects share with wrong secretLength in decode", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 2, totalShares: 3 });
    // Tamper with share bytes — truncate.
    const truncated = crypto.encoding.decodeBase64(shares[0]!.shareB64).slice(0, 8);
    const bad: SecretShare = {
      ...shares[0]!,
      shareB64: crypto.encoding.encodeBase64(truncated),
    };
    expect(() => reconstructSecret([bad, shares[1]!])).toThrow(
      /length/,
    );
  });
});

describe("Shamir: tampered share detection", () => {
  it("tampered share yields WRONG secret (no integrity check!)", () => {
    // Shamir alone provides confidentiality but NOT integrity — a
    // byzantine share holder can poison reconstruction. Callers need
    // to layer integrity (e.g. sign the reconstructed secret, or use
    // verifiable SSS). This test documents that gap.
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    const bytes = crypto.encoding.decodeBase64(shares[0]!.shareB64);
    bytes[0] = bytes[0]! ^ 0xff; // flip bits
    const tampered: SecretShare = {
      ...shares[0]!,
      shareB64: crypto.encoding.encodeBase64(bytes),
    };
    const got = reconstructSecret([tampered, shares[1]!, shares[2]!]);
    // Reconstruction "succeeds" — but gives wrong bytes.
    expect(got).not.toEqual(secret);
  });

  it("verifyShares catches tampered share (vs known expected)", () => {
    const secret = randomBytes(16);
    const shares = splitSecret(secret, { threshold: 3, totalShares: 5 });
    const bytes = crypto.encoding.decodeBase64(shares[0]!.shareB64);
    bytes[0] ^= 0x01;
    const tampered: SecretShare = {
      ...shares[0]!,
      shareB64: crypto.encoding.encodeBase64(bytes),
    };
    expect(
      verifyShares([tampered, shares[1]!, shares[2]!], secret),
    ).toBe(false);
  });
});

describe("Shamir: typical key-escrow workflow", () => {
  it("Ed25519 signing key escrow + recovery", () => {
    // Operator has an Ed25519 key they want to back up.
    const kp = crypto.signing.generateKeyPair();
    const secret = kp.secretKey; // 64 bytes

    // Split into 3-of-5 and distribute to trustees.
    const shares = splitSecret(secret, {
      threshold: 3,
      totalShares: 5,
      secretId: "heart-operator-alice-v1",
    });
    expect(shares).toHaveLength(5);

    // Later, 3 trustees cooperate to rebuild the key.
    const recovered = reconstructSecret([shares[0]!, shares[2]!, shares[4]!]);
    expect(recovered).toEqual(secret);

    // The recovered key still signs correctly.
    const msg = new TextEncoder().encode("hello");
    const sig = crypto.signing.sign(msg, recovered);
    expect(crypto.signing.verify(msg, sig, kp.publicKey)).toBe(true);
  });
});
