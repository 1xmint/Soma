import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  DidKeyMethod,
  DidPkhMethod,
  DidMethodRegistry,
  verifyDidBinding,
  createDefaultDidRegistry,
  type DidVerificationKey,
  type PkhIdentifier,
} from "../../src/core/did-method.js";
import { publicKeyToDid } from "../../src/core/genome.js";

const crypto = getCryptoProvider();

// ─── Default fallback (no registry) ─────────────────────────────────────────

describe("verifyDidBinding — fallback path (no registry)", () => {
  it("accepts a did:key bound to its own public key", () => {
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const result = verifyDidBinding(did, kp.publicKey);
    expect(result.bound).toBe(true);
    if (result.bound) expect(result.via).toBe("did-key-fallback");
  });

  it("rejects a did:key with a mismatched public key", () => {
    const a = crypto.signing.generateKeyPair();
    const b = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(a.publicKey);
    const result = verifyDidBinding(did, b.publicKey);
    expect(result.bound).toBe(false);
  });

  it("rejects a non-did:key DID with no registry", () => {
    const kp = crypto.signing.generateKeyPair();
    const result = verifyDidBinding(
      "did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678",
      kp.publicKey,
    );
    expect(result.bound).toBe(false);
  });
});

// ─── Registry path: did:key ─────────────────────────────────────────────────

describe("verifyDidBinding — registry path (did:key)", () => {
  it("resolves via registry when did:key is registered", () => {
    const registry = createDefaultDidRegistry();
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const result = verifyDidBinding(did, kp.publicKey, registry);
    expect(result.bound).toBe(true);
    if (result.bound) expect(result.via).toBe("registry");
  });

  it("rejects via registry when key doesn't match", () => {
    const registry = createDefaultDidRegistry();
    const a = crypto.signing.generateKeyPair();
    const b = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(a.publicKey);
    const result = verifyDidBinding(did, b.publicKey, registry);
    expect(result.bound).toBe(false);
  });
});

// ─── Registry path: did:pkh ─────────────────────────────────────────────────

describe("verifyDidBinding — registry path (did:pkh)", () => {
  it("accepts a did:pkh whose keyBinder returns the matching key", () => {
    const kp = crypto.signing.generateKeyPair();
    const account = "0x1234567890abcdef1234567890abcdef12345678";
    const keyBinder = (pkh: PkhIdentifier): DidVerificationKey[] => {
      if (pkh.account === account) {
        return [{ publicKey: kp.publicKey, algorithmId: "ed25519" }];
      }
      return [];
    };
    const registry = new DidMethodRegistry();
    registry.register(new DidPkhMethod(keyBinder));
    const did = `did:pkh:eip155:1:${account}`;
    const result = verifyDidBinding(did, kp.publicKey, registry);
    expect(result.bound).toBe(true);
    if (result.bound) expect(result.via).toBe("registry");
  });

  it("rejects a did:pkh when keyBinder returns empty", () => {
    const kp = crypto.signing.generateKeyPair();
    const registry = new DidMethodRegistry();
    registry.register(new DidPkhMethod(() => []));
    const did = "did:pkh:eip155:1:0xabc";
    const result = verifyDidBinding(did, kp.publicKey, registry);
    expect(result.bound).toBe(false);
  });

  it("rejects a did:pkh when keyBinder returns a different key", () => {
    const a = crypto.signing.generateKeyPair();
    const b = crypto.signing.generateKeyPair();
    const registry = new DidMethodRegistry();
    registry.register(
      new DidPkhMethod(() => [{ publicKey: a.publicKey, algorithmId: "ed25519" }]),
    );
    const did = "did:pkh:eip155:1:0xabc";
    const result = verifyDidBinding(did, b.publicKey, registry);
    expect(result.bound).toBe(false);
  });
});

// ─── Mixed registry (key + pkh) ─────────────────────────────────────────────

describe("verifyDidBinding — mixed registry", () => {
  it("dispatches correctly between did:key and did:pkh", () => {
    const keyKp = crypto.signing.generateKeyPair();
    const pkhKp = crypto.signing.generateKeyPair();
    const account = "0xdeadbeef1234567890deadbeef1234567890beef";

    const registry = createDefaultDidRegistry();
    registry.register(
      new DidPkhMethod((pkh) =>
        pkh.account === account
          ? [{ publicKey: pkhKp.publicKey, algorithmId: "ed25519" }]
          : [],
      ),
    );

    const keyDid = publicKeyToDid(keyKp.publicKey);
    const pkhDid = `did:pkh:eip155:1:${account}`;

    expect(verifyDidBinding(keyDid, keyKp.publicKey, registry).bound).toBe(true);
    expect(verifyDidBinding(pkhDid, pkhKp.publicKey, registry).bound).toBe(true);
    // Cross-wired: key for pkh identity, pkh for key identity.
    expect(verifyDidBinding(keyDid, pkhKp.publicKey, registry).bound).toBe(false);
    expect(verifyDidBinding(pkhDid, keyKp.publicKey, registry).bound).toBe(false);
  });
});
