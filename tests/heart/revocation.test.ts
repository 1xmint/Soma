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
    reg.registerAuthority("dg-1", issuer.did);
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    expect(reg.add(rev).accepted).toBe(true);
    expect(reg.isRevoked("dg-1")).toBe(true);
    expect(reg.isRevoked("dg-999")).toBe(false);
    expect(reg.size).toBe(1);
  });

  it("rejects tampered revocations", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    reg.registerAuthority("dg-1", issuer.did);
    reg.registerAuthority("dg-2", issuer.did);
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    const tampered = { ...rev, targetId: "dg-2" };
    const result = reg.add(tampered);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/invalid/);
    expect(reg.isRevoked("dg-2")).toBe(false);
  });

  it("deduplicates same-target revocations", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    reg.registerAuthority("dg-1", issuer.did);
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    expect(reg.add(rev).accepted).toBe(true);
    expect(reg.add(rev).accepted).toBe(false); // already present
    expect(reg.size).toBe(1);
  });

  it("exports and imports", () => {
    const src = new RevocationRegistry();
    const issuer = makeIdentity();
    for (let i = 0; i < 3; i++) {
      src.registerAuthority(`dg-${i}`, issuer.did);
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
    for (let i = 0; i < 3; i++) {
      dst.registerAuthority(`dg-${i}`, issuer.did);
    }
    expect(dst.import(exported)).toBe(3);
    expect(dst.size).toBe(3);
  });

  it("rejects revocations with unknown authority (fail-closed)", () => {
    const reg = new RevocationRegistry();
    const issuer = makeIdentity();
    const rev = createRevocation({
      targetId: "dg-orphan",
      targetKind: "delegation",
      issuerDid: issuer.did,
      issuerPublicKey: issuer.publicKey,
      issuerSigningKey: issuer.kp.secretKey,
    });
    const result = reg.add(rev);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/unknown authority/);
  });

  it("rejects revocations from an unauthorized issuer", () => {
    const reg = new RevocationRegistry();
    const alice = makeIdentity();
    const eve = makeIdentity();
    reg.registerAuthority("dg-1", alice.did);
    const rev = createRevocation({
      targetId: "dg-1",
      targetKind: "delegation",
      issuerDid: eve.did,
      issuerPublicKey: eve.publicKey,
      issuerSigningKey: eve.kp.secretKey,
    });
    const result = reg.add(rev);
    expect(result.accepted).toBe(false);
    expect(result.reason).toMatch(/not authorized/);
  });
});
