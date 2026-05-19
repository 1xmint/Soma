/**
 * Attack #5 — Cross-algorithm key substitution in a hybrid signature.
 *
 * Scenario:
 *   Alice publishes a hybrid identity (ed-pk, pq-pk) and signs `msg` with
 *   both keys, producing envelope E = {algos: [ed, pq], pks: [ed-pk, pq-pk],
 *   sigs: [sig_ed, sig_pq]}. Eve wants to impersonate Alice under a
 *   `require-all` policy using only her own PQ keypair (eve-pq-sk, eve-pq-pk)
 *   — say, once PQ algorithms become breakable via quantum advantage.
 *
 *   Eve tries: keep Alice's legitimate `sig_ed` (she doesn't have it? no, she
 *   CAPTURED it from the wire), swap (pq-pk → eve-pq-pk) and (sig_pq →
 *   eve-forged-pq-sig). If the Ed25519 signature weren't bound to the pk set,
 *   Alice's sig_ed would still verify against ed-pk, and Eve's forged sig_pq
 *   would verify against eve-pq-pk. Policy = "require-all" passes. Identity
 *   compromised.
 *
 * Defense: the binding payload includes ALL public keys. Alice's sig_ed was
 * computed over (protocol, binding=[ed, ed-pk + pq, pq-pk], message). If Eve
 * substitutes eve-pq-pk, the binding payload differs → Alice's ORIGINAL sig_ed
 * no longer verifies under the new envelope. Substitution breaks the Ed25519
 * signature, not the PQ one.
 *
 * Primitives composed:
 *   hybrid-signing · binding payload · AlgorithmRegistry
 */

import { describe, it, expect } from "vitest";
import {
  AlgorithmRegistry,
  generateHybridKeyPair,
  hybridSign,
  verifyHybridSignature,
} from "../../src/heart/hybrid-signing.js";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { canonicalJson } from "../../src/core/canonicalize.js";
import { bytes } from "./_harness.js";

const crypto = getCryptoProvider();

/**
 * Build an AlgorithmRegistry with ed25519 registered as "ed25519" and a
 * SECOND provider under the alias "pq-mock" (same underlying Ed25519
 * implementation — we're testing the envelope, not a real PQ algo).
 */
function buildRegistry(): AlgorithmRegistry {
  const registry = new AlgorithmRegistry();
  const real = crypto.signing;
  registry.register(real);
  // Register a "pq-mock" provider backed by the same Ed25519 implementation
  // but advertised under a different algorithmId. This lets us exercise
  // multi-algo envelopes without shipping a PQ library.
  registry.register({
    algorithmId: "pq-mock",
    multicodecPrefix: real.multicodecPrefix,
    generateKeyPair: () => real.generateKeyPair(),
    sign: (msg, sk) => real.sign(msg, sk),
    verify: (msg, sig, pk) => real.verify(msg, sig, pk),
  });
  return registry;
}

describe("Attack #5: hybrid cross-algorithm key substitution", () => {
  it("substituting a public key invalidates the sibling signature", () => {
    const registry = buildRegistry();
    const alice = generateHybridKeyPair(["ed25519", "pq-mock"], registry);
    const eve = generateHybridKeyPair(["pq-mock"], registry);

    const msg = bytes("transfer 1000 credits to eve");
    const legitEnvelope = hybridSign(alice, msg, registry);

    // Sanity: legit envelope passes require-all.
    expect(
      verifyHybridSignature(legitEnvelope, msg, registry, { type: "require-all" }).ok,
    ).toBe(true);

    // Eve replaces the pq slot's public key with her own AND produces a
    // "forged" PQ signature that verifies against eve-pq-pk (in our mock,
    // that's just a genuine sign with eve's secret).
    const evePqPk = eve.algorithms.find((a) => a.algorithmId === "pq-mock")!;
    const tamperedPks = [...legitEnvelope.publicKeysB64];
    const pqIdx = legitEnvelope.algorithms.indexOf("pq-mock");
    tamperedPks[pqIdx] = crypto.encoding.encodeBase64(evePqPk.publicKey);

    // At this point, Eve needs to re-sign the PQ slot OVER THE NEW BINDING
    // (which includes her eve-pq-pk). She CAN do that because she controls
    // that key — so that one signature will pass by itself. But Alice's
    // legitimate Ed25519 signature was computed over the OLD binding (with
    // alice's pq-pk), so it won't verify against the new binding.
    //
    // Simulate Eve's best-effort forgery:
    // 1. Keep Alice's ed sig (captured).
    // 2. Forge a new pq sig against the new binding using her pq-sk.
    const newBindingPayload = buildBindingPayloadLocal(
      legitEnvelope.algorithms,
      tamperedPks,
      msg,
    );
    const forgedPqSig = crypto.signing.sign(
      newBindingPayload,
      evePqPk.secretKey,
    );

    const eveEnvelope = {
      version: 1 as const,
      algorithms: legitEnvelope.algorithms,
      publicKeysB64: tamperedPks,
      signatures: legitEnvelope.signatures.map((s) =>
        s.algorithmId === "pq-mock"
          ? {
              algorithmId: "pq-mock",
              signatureB64: crypto.encoding.encodeBase64(forgedPqSig),
            }
          : s,
      ),
    };

    // require-all MUST reject: ed sig is over old binding, new binding differs.
    const eveResult = verifyHybridSignature(eveEnvelope, msg, registry, {
      type: "require-all",
    });
    expect(eveResult.ok).toBe(false);
    expect(eveResult.verifiedAlgorithms).toEqual(["pq-mock"]);
    expect(eveResult.failedAlgorithms).toContain("ed25519");
  });

  it("keeping the full envelope BUT flipping one pk fails both sigs", () => {
    const registry = buildRegistry();
    const alice = generateHybridKeyPair(["ed25519", "pq-mock"], registry);
    const mallory = generateHybridKeyPair(["ed25519"], registry);

    const msg = bytes("delegate admin");
    const envelope = hybridSign(alice, msg, registry);

    // Mallory swaps the ed pk out but keeps Alice's original ed signature.
    const edIdx = envelope.algorithms.indexOf("ed25519");
    const tamperedPks = [...envelope.publicKeysB64];
    tamperedPks[edIdx] = crypto.encoding.encodeBase64(
      mallory.algorithms[0].publicKey,
    );
    const tamperedEnvelope = { ...envelope, publicKeysB64: tamperedPks };

    const result = verifyHybridSignature(
      tamperedEnvelope,
      msg,
      registry,
      { type: "require-all" },
    );
    expect(result.ok).toBe(false);
    // Alice's ed sig was over the old binding — won't match new pk position.
    // Alice's pq sig was also over the old binding, which included the old
    // ed pk — so flipping ed pk invalidates BOTH sigs.
    expect(result.verifiedAlgorithms).toEqual([]);
  });

  it("require-any still rejects if ALL swaps break the bindings", () => {
    const registry = buildRegistry();
    const alice = generateHybridKeyPair(["ed25519", "pq-mock"], registry);
    const mallory = generateHybridKeyPair(["ed25519", "pq-mock"], registry);

    const msg = bytes("important message");
    const envelope = hybridSign(alice, msg, registry);

    // Mallory swaps BOTH public keys to her own. Alice's sigs are over the
    // old binding (alice's pks), new binding has mallory's pks. Both fail.
    const tamperedPks = [
      crypto.encoding.encodeBase64(mallory.algorithms[0].publicKey),
      crypto.encoding.encodeBase64(mallory.algorithms[1].publicKey),
    ];
    const tamperedEnvelope = { ...envelope, publicKeysB64: tamperedPks };

    const result = verifyHybridSignature(
      tamperedEnvelope,
      msg,
      registry,
      { type: "require-any" },
    );
    expect(result.ok).toBe(false);
  });
});

// ─── Helper: mirror buildBindingPayload for the forgery simulation ─────────

function buildBindingPayloadLocal(
  algorithms: readonly string[],
  publicKeysB64: readonly string[],
  message: Uint8Array,
): Uint8Array {
  const payload = {
    protocol: "soma-hybrid-sig/1",
    binding: algorithms.map((algorithmId, i) => ({
      algorithmId,
      publicKeyB64: publicKeysB64[i],
    })),
    messageB64: crypto.encoding.encodeBase64(message),
  };
  return new TextEncoder().encode(canonicalJson(payload));
}
