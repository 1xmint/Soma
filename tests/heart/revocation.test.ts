import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createRevocation,
  verifyRevocation,
  RevocationRegistry,
} from "../../src/heart/revocation.js";

const crypto = getCryptoProvider();

function makeIdentity() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

describe("Revocation events", () => {
  it("creates and verifies a revocation", () => {
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-abc123",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
      reason: "compromised",
    });
    expect(verifyRevocation(rev).valid).toBe(true);
    expect(rev.reason).toBe("compromised");
  });

  it("rejects tampered revocation", () => {
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-abc123",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    const tampered = { ...rev, targetId: "dg-different" };
    expect(verifyRevocation(tampered).valid).toBe(false);
  });
});

describe("RevocationRegistry", () => {
  it("accepts valid revocations", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    expect(reg.add(rev)).toBe(true);
    expect(reg.isRevoked("dg-1")).toBe(true);
    expect(reg.isRevoked("dg-999")).toBe(false);
    expect(reg.size).toBe(1);
  });

  it("rejects tampered revocations", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    const tampered = { ...rev, targetId: "dg-2" };
    expect(reg.add(tampered)).toBe(false);
    expect(reg.isRevoked("dg-2")).toBe(false);
  });

  it("deduplicates same-target revocations", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    expect(reg.add(rev)).toBe(true);
    expect(reg.add(rev)).toBe(false); // already present
    expect(reg.size).toBe(1);
  });

  it("exports and imports", () => {
    const src = new RevocationRegistry();
    const issuer = makeIdentity();
    for (let i = 0; i < 3; i++) {
      src.add(
        createRevocation({
          targetId: `dg-${i}`,
          targetKind: "delegation",
          issuerDid: issuer.did,
          issuerPublicKey: issuer.publicKey,
          issuerSigningKey: issuer.kp.secretKey,
        }),
      );
    }
    const exported = src.export();
    const dst = new RevocationRegistry();
    expect(dst.import(exported)).toBe(3);
    expect(dst.size).toBe(3);
  });
});
