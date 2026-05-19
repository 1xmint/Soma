/**
 * Cross-method delegation retrofit — issuer uses did:pkh via registry.
 *
 * Without a registry, verifyDelegation falls back to did:key and rejects
 * any delegation whose issuerDid isn't did:key (the pre-retrofit behavior).
 * With a registry registered for did:pkh, a keyBinder resolves the DID to
 * the real Ed25519 key and the delegation verifies.
 */

import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  DidMethodRegistry,
  DidKeyMethod,
  DidPkhMethod,
  type PkhIdentifier,
  type DidVerificationKey,
} from "../../src/core/did-method.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createDelegation,
  verifyDelegation,
  verifyDelegationSignature,
} from "../../src/heart/delegation.js";

const crypto = getCryptoProvider();

describe("delegation — cross-method DID binding (did:pkh issuer)", () => {
  const account = "0xa1b2c3d4e5f67890abcdef1234567890abcdef12";

  function setupPkhRegistry(
    issuerPublicKey: Uint8Array,
  ): DidMethodRegistry {
    const keyBinder = (pkh: PkhIdentifier): DidVerificationKey[] => {
      if (pkh.account === account) {
        return [{ publicKey: issuerPublicKey, algorithmId: "ed25519" }];
      }
      return [];
    };
    const registry = new DidMethodRegistry();
    registry.register(new DidKeyMethod());
    registry.register(new DidPkhMethod(keyBinder));
    return registry;
  }

  it("rejects a did:pkh delegation without a registry (did:key-only fallback)", () => {
    const issuerKp = crypto.signing.generateKeyPair();
    const subjectKp = crypto.signing.generateKeyPair();
    const pkhDid = `did:pkh:eip155:1:${account}`;

    const del = createDelegation({
      issuerDid: pkhDid,
      issuerPublicKey: crypto.encoding.encodeBase64(issuerKp.publicKey),
      issuerSigningKey: issuerKp.secretKey,
      subjectDid: publicKeyToDid(subjectKp.publicKey),
      capabilities: ["api:read"],
    });

    // No registry → falls back to did:key semantics, which expects the DID
    // to encode the public key. did:pkh doesn't, so binding fails.
    const sigResult = verifyDelegationSignature(del);
    expect(sigResult.valid).toBe(false);
    if (!sigResult.valid) {
      expect(sigResult.reason).toContain("does not match");
    }
  });

  it("accepts a did:pkh delegation with a registry supplying the keyBinder", () => {
    const issuerKp = crypto.signing.generateKeyPair();
    const subjectKp = crypto.signing.generateKeyPair();
    const pkhDid = `did:pkh:eip155:1:${account}`;
    const registry = setupPkhRegistry(issuerKp.publicKey);

    const del = createDelegation({
      issuerDid: pkhDid,
      issuerPublicKey: crypto.encoding.encodeBase64(issuerKp.publicKey),
      issuerSigningKey: issuerKp.secretKey,
      subjectDid: publicKeyToDid(subjectKp.publicKey),
      capabilities: ["api:read"],
    });

    const sigResult = verifyDelegationSignature(del, undefined, registry);
    expect(sigResult.valid).toBe(true);

    const fullResult = verifyDelegation(
      del,
      {
        invokerDid: publicKeyToDid(subjectKp.publicKey),
        capability: "api:read",
      },
      undefined,
      registry,
    );
    expect(fullResult.valid).toBe(true);
  });

  it("rejects a did:pkh delegation with a registry whose keyBinder returns wrong key", () => {
    const issuerKp = crypto.signing.generateKeyPair();
    const decoyKp = crypto.signing.generateKeyPair();
    const subjectKp = crypto.signing.generateKeyPair();
    const pkhDid = `did:pkh:eip155:1:${account}`;
    const registry = setupPkhRegistry(decoyKp.publicKey); // wrong mapping!

    const del = createDelegation({
      issuerDid: pkhDid,
      issuerPublicKey: crypto.encoding.encodeBase64(issuerKp.publicKey),
      issuerSigningKey: issuerKp.secretKey,
      subjectDid: publicKeyToDid(subjectKp.publicKey),
      capabilities: ["api:read"],
    });

    const sigResult = verifyDelegationSignature(del, undefined, registry);
    expect(sigResult.valid).toBe(false);
    if (!sigResult.valid) {
      expect(sigResult.reason).toContain("does not match");
    }
  });

  it("still accepts a did:key delegation when registry is supplied", () => {
    // Backwards compat: supplying a registry must not break did:key flows.
    const issuerKp = crypto.signing.generateKeyPair();
    const subjectKp = crypto.signing.generateKeyPair();
    const registry = setupPkhRegistry(issuerKp.publicKey);

    const del = createDelegation({
      issuerDid: publicKeyToDid(issuerKp.publicKey),
      issuerPublicKey: crypto.encoding.encodeBase64(issuerKp.publicKey),
      issuerSigningKey: issuerKp.secretKey,
      subjectDid: publicKeyToDid(subjectKp.publicKey),
      capabilities: ["api:read"],
    });

    const result = verifyDelegation(
      del,
      {
        invokerDid: publicKeyToDid(subjectKp.publicKey),
        capability: "api:read",
      },
      undefined,
      registry,
    );
    expect(result.valid).toBe(true);
  });
});
