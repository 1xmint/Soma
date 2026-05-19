import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import type { SecretShare } from "../../src/heart/key-escrow.js";
import {
  generateThresholdKeyPair,
  shareExistingKey,
  thresholdSign,
  verifyThresholdSignature,
  SigningCeremony,
} from "../../src/heart/threshold-signing.js";

const crypto = getCryptoProvider();

function msg(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ─── generateThresholdKeyPair ───────────────────────────────────────────────

describe("generateThresholdKeyPair", () => {
  it("produces a public key and N shares", () => {
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "test-v1",
    });
    expect(tk.publicKey).toHaveLength(32);
    expect(tk.shares).toHaveLength(5);
    expect(tk.threshold).toBe(3);
    expect(tk.totalShares).toBe(5);
    expect(tk.keyId).toBe("test-v1");
  });

  it("binds all shares to the same keyId", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "alice-root",
    });
    for (const share of tk.shares) {
      expect(share.secretId).toBe("alice-root");
    }
  });

  it("shares have unique indices", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 5,
      keyId: "k",
    });
    const indices = tk.shares.map((s) => s.index);
    expect(new Set(indices).size).toBe(5);
  });

  it("rejects threshold < 2", () => {
    expect(() =>
      generateThresholdKeyPair({ threshold: 1, totalShares: 3, keyId: "k" }),
    ).toThrow(/threshold must be/);
  });

  it("rejects totalShares < threshold", () => {
    expect(() =>
      generateThresholdKeyPair({ threshold: 5, totalShares: 3, keyId: "k" }),
    ).toThrow(/totalShares/);
  });

  it("rejects empty keyId", () => {
    expect(() =>
      generateThresholdKeyPair({ threshold: 2, totalShares: 3, keyId: "" }),
    ).toThrow(/keyId/);
  });
});

// ─── shareExistingKey ───────────────────────────────────────────────────────

describe("shareExistingKey", () => {
  it("shards an existing Ed25519 keypair", () => {
    const kp = crypto.signing.generateKeyPair();
    const tk = shareExistingKey({
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      threshold: 2,
      totalShares: 3,
      keyId: "imported-v1",
    });
    expect(tk.publicKey).toEqual(kp.publicKey);
    expect(tk.shares).toHaveLength(3);
  });

  it("signature from sharded key verifies against original publicKey", () => {
    const kp = crypto.signing.generateKeyPair();
    const tk = shareExistingKey({
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      threshold: 2,
      totalShares: 3,
      keyId: "imported",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("hi"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "imported",
    });
    expect(crypto.signing.verify(msg("hi"), sig.signature, kp.publicKey)).toBe(
      true,
    );
  });

  it("rejects wrong public key length", () => {
    const kp = crypto.signing.generateKeyPair();
    expect(() =>
      shareExistingKey({
        publicKey: new Uint8Array(16),
        secretKey: kp.secretKey,
        threshold: 2,
        totalShares: 3,
        keyId: "k",
      }),
    ).toThrow(/32-byte/);
  });

  it("rejects wrong secret key length", () => {
    const kp = crypto.signing.generateKeyPair();
    expect(() =>
      shareExistingKey({
        publicKey: kp.publicKey,
        secretKey: new Uint8Array(32),
        threshold: 2,
        totalShares: 3,
        keyId: "k",
      }),
    ).toThrow(/64-byte/);
  });
});

// ─── thresholdSign happy path ───────────────────────────────────────────────

describe("thresholdSign (happy path)", () => {
  it("signs with exactly threshold shares (2-of-3)", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("hello"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(sig.signature).toHaveLength(64);
    expect(sig.contributingShareIds).toHaveLength(2);
    expect(sig.keyId).toBe("k");
  });

  it("signs with more than threshold shares (3 of 2-of-5)", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 5,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 3), msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(sig.contributingShareIds).toHaveLength(3);
  });

  it("signs with 3-of-5", () => {
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "k",
    });
    const sig = thresholdSign(
      [tk.shares[0], tk.shares[2], tk.shares[4]],
      msg("hello"),
      {
        publicKey: tk.publicKey,
        threshold: 3,
        keyId: "k",
      },
    );
    expect(
      crypto.signing.verify(msg("hello"), sig.signature, tk.publicKey),
    ).toBe(true);
  });

  it("signature verifies with standard Ed25519 verify", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("xyz"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    // ANY Ed25519 verifier — including existing soma code — accepts this.
    expect(crypto.signing.verify(msg("xyz"), sig.signature, tk.publicKey)).toBe(
      true,
    );
  });

  it("contributing share ids are sorted ascending", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 5,
      keyId: "k",
    });
    // Pass shares out of order
    const sig = thresholdSign(
      [tk.shares[3], tk.shares[0], tk.shares[2]],
      msg("m"),
      { publicKey: tk.publicKey, threshold: 2, keyId: "k" },
    );
    const ids = sig.contributingShareIds;
    for (let i = 1; i < ids.length; i++) {
      expect(ids[i]).toBeGreaterThan(ids[i - 1]);
    }
  });
});

// ─── thresholdSign failure modes ────────────────────────────────────────────

describe("thresholdSign (failure modes)", () => {
  it("throws when below threshold", () => {
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "k",
    });
    expect(() =>
      thresholdSign(tk.shares.slice(0, 2), msg("m"), {
        publicKey: tk.publicKey,
        threshold: 3,
        keyId: "k",
      }),
    ).toThrow(/at least 3/);
  });

  it("throws when shares belong to different key", () => {
    const tk1 = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "key-1",
    });
    const tk2 = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "key-2",
    });
    expect(() =>
      thresholdSign([tk1.shares[0], tk2.shares[0]], msg("m"), {
        publicKey: tk1.publicKey,
        threshold: 2,
        keyId: "key-1",
      }),
    ).toThrow(/does not match keyId/);
  });

  it("throws on duplicate share indices", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    expect(() =>
      thresholdSign([tk.shares[0], tk.shares[0]], msg("m"), {
        publicKey: tk.publicKey,
        threshold: 2,
        keyId: "k",
      }),
    ).toThrow(/duplicate/);
  });

  it("throws when reconstructed key does not match expected publicKey", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const otherKp = crypto.signing.generateKeyPair();
    expect(() =>
      thresholdSign(tk.shares.slice(0, 2), msg("m"), {
        publicKey: otherKp.publicKey, // WRONG expected pk
        threshold: 2,
        keyId: "k",
      }),
    ).toThrow(/did not produce a valid signature/);
  });
});

// ─── verifyThresholdSignature ───────────────────────────────────────────────

describe("verifyThresholdSignature", () => {
  it("accepts a valid threshold signature", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(verifyThresholdSignature(msg("m"), sig, tk.publicKey)).toBe(true);
  });

  it("accepts raw Uint8Array signature", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(
      verifyThresholdSignature(msg("m"), sig.signature, tk.publicKey),
    ).toBe(true);
  });

  it("rejects on message tampering", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const sig = thresholdSign(tk.shares.slice(0, 2), msg("original"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(verifyThresholdSignature(msg("tampered"), sig, tk.publicKey)).toBe(
      false,
    );
  });
});

// ─── SigningCeremony ────────────────────────────────────────────────────────

describe("SigningCeremony", () => {
  it("collects shares and emits signature when threshold reached", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(ceremony.ready).toBe(false);
    expect(ceremony.contribute(tk.shares[0])).toBe(false);
    expect(ceremony.ready).toBe(false);
    expect(ceremony.contribute(tk.shares[1])).toBe(true);
    expect(ceremony.ready).toBe(true);
    const sig = ceremony.sign();
    expect(crypto.signing.verify(msg("m"), sig.signature, tk.publicKey)).toBe(
      true,
    );
  });

  it("tracks contributed share ids", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 5,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    ceremony.contribute(tk.shares[2]);
    ceremony.contribute(tk.shares[4]);
    expect(ceremony.contributedCount).toBe(2);
    expect(ceremony.contributingShareIds()).toEqual([
      tk.shares[2].index,
      tk.shares[4].index,
    ]);
  });

  it("rejects duplicate share contributions", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    ceremony.contribute(tk.shares[0]);
    expect(() => ceremony.contribute(tk.shares[0])).toThrow(/already contributed/);
  });

  it("rejects shares from different key", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "key-a",
    });
    const tk2 = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "key-b",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "key-a",
    });
    expect(() => ceremony.contribute(tk2.shares[0])).toThrow(/does not match/);
  });

  it("sign throws below threshold", () => {
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 3,
      keyId: "k",
    });
    ceremony.contribute(tk.shares[0]);
    ceremony.contribute(tk.shares[1]);
    expect(() => ceremony.sign()).toThrow(/below threshold/);
  });

  it("cannot sign twice", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    ceremony.contribute(tk.shares[0]);
    ceremony.contribute(tk.shares[1]);
    ceremony.sign();
    expect(() => ceremony.sign()).toThrow(/already signed/);
  });

  it("abort prevents further contributions", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const ceremony = new SigningCeremony(msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    ceremony.contribute(tk.shares[0]);
    ceremony.abort();
    expect(() => ceremony.contribute(tk.shares[1])).toThrow(/already signed/);
  });

  it("rejects threshold < 2 in ceremony", () => {
    const kp = crypto.signing.generateKeyPair();
    expect(
      () =>
        new SigningCeremony(msg("m"), {
          publicKey: kp.publicKey,
          threshold: 1,
          keyId: "k",
        }),
    ).toThrow(/threshold must be/);
  });
});

// ─── Interop with existing soma Ed25519 verifiers ───────────────────────────

describe("threshold signatures are standard Ed25519", () => {
  it("signature verifies via the default signing provider unchanged", () => {
    // This is the whole point: threshold-signed messages are
    // indistinguishable from single-signer Ed25519 signatures. Existing
    // verification code doesn't need to know the difference.
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "interop",
    });
    const sig = thresholdSign(
      [tk.shares[0], tk.shares[1], tk.shares[2]],
      msg("any standard consumer verifies this"),
      { publicKey: tk.publicKey, threshold: 3, keyId: "interop" },
    );
    // Standard Ed25519 verify via the signing provider.
    expect(
      crypto.signing.verify(
        msg("any standard consumer verifies this"),
        sig.signature,
        tk.publicKey,
      ),
    ).toBe(true);
  });

  it("different M-subsets of the same shares produce equal signatures (deterministic Ed25519)", () => {
    const tk = generateThresholdKeyPair({
      threshold: 3,
      totalShares: 5,
      keyId: "det",
    });
    const sig1 = thresholdSign(tk.shares.slice(0, 3), msg("m"), {
      publicKey: tk.publicKey,
      threshold: 3,
      keyId: "det",
    });
    const sig2 = thresholdSign(tk.shares.slice(2, 5), msg("m"), {
      publicKey: tk.publicKey,
      threshold: 3,
      keyId: "det",
    });
    // Both reconstructions yield the same secret, Ed25519 is deterministic.
    expect(sig1.signature).toEqual(sig2.signature);
  });
});

// ─── Share serialization (round-trip) ───────────────────────────────────────

describe("shares are serializable", () => {
  it("share JSON round-trips and still signs", () => {
    const tk = generateThresholdKeyPair({
      threshold: 2,
      totalShares: 3,
      keyId: "k",
    });
    const jsonShares = tk.shares.map((s) => JSON.parse(JSON.stringify(s)));
    const sig = thresholdSign(jsonShares.slice(0, 2) as SecretShare[], msg("m"), {
      publicKey: tk.publicKey,
      threshold: 2,
      keyId: "k",
    });
    expect(crypto.signing.verify(msg("m"), sig.signature, tk.publicKey)).toBe(
      true,
    );
  });
});
