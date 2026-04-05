/**
 * Attack #7 — Stolen current key tries to seize an identity.
 *
 * Scenario:
 *   Alice has a KeyHistory with inception K0 → pre-commits to digest(K1).
 *   She rotates to K1, pre-committing to digest(K2). At this point she is
 *   signing with K1, and K0 is retired.
 *
 *   Eve compromises K1. Her goal: produce a rotation event that seizes
 *   Alice's identity by registering Eve's own key K_eve as the current key
 *   and pre-committing to Eve's own next key.
 *
 * Defense: each rotation's `currentPublicKey` must match the PRIOR event's
 * `nextKeyDigest`. Alice committed digest(K2) during her last rotation; the
 * attacker would need a key whose digest equals digest(K2) to move the chain
 * forward. That's a pre-image break on SHA-256 — infeasible. Eve CAN sign
 * messages with K1 (since she stole it), but she cannot produce a valid
 * NEXT rotation event because she doesn't have K2.
 *
 * Primitives composed:
 *   key-rotation · KeyHistory · pre-rotation commitment
 */

import { describe, it, expect } from "vitest";
import { KeyHistory } from "../../src/heart/key-rotation.js";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";

const crypto = getCryptoProvider();

describe("Attack #7: stolen-key rotation takeover", () => {
  it("attacker with K1 cannot rotate to a key whose digest doesn't match K2's pre-commit", () => {
    const k0 = crypto.signing.generateKeyPair();
    const k1 = crypto.signing.generateKeyPair();
    const k2 = crypto.signing.generateKeyPair();
    const kEve = crypto.signing.generateKeyPair();

    // Alice establishes inception committing to K1's digest.
    const { history } = KeyHistory.incept({
      inceptionSecretKey: k0.secretKey,
      inceptionPublicKey: k0.publicKey,
      nextPublicKey: k1.publicKey,
    });

    // Alice performs the first rotation from K0 to K1, committing to K2.
    history.rotate({
      currentSecretKey: k1.secretKey,
      currentPublicKey: k1.publicKey,
      nextPublicKey: k2.publicKey,
    });

    // Eve has stolen K1 (current signing key). She tries to register
    // Eve's own key (kEve) as the "next" current — but the chain's last
    // event committed to digest(K2), not digest(kEve).
    //
    // The rotate() call signs with the CURRENT key (K1, which Eve has) and
    // passes CURRENT=kEve (the new holder), but the validation is that
    // currentPublicKey must match prior.nextKeyDigest — digest(kEve) ≠
    // digest(K2), so rotate() rejects.
    expect(() =>
      history.rotate({
        currentSecretKey: k1.secretKey,
        currentPublicKey: kEve.publicKey, // Eve's key
        nextPublicKey: kEve.publicKey, // attacker's "next" key
      }),
    ).toThrow(/does not match prior event nextKeyDigest/);
  });

  it("attacker cannot stealth-forge an inception event for Alice's existing identity", () => {
    // Goal: Eve rebuilds a fake KeyHistory for Alice's DID using her own
    // keys. Should not be accepted because inception's currentPublicKey must
    // derive the claimed identity DID.
    const k0 = crypto.signing.generateKeyPair();
    const k1 = crypto.signing.generateKeyPair();
    const kEve = crypto.signing.generateKeyPair();

    const { history } = KeyHistory.incept({
      inceptionSecretKey: k0.secretKey,
      inceptionPublicKey: k0.publicKey,
      nextPublicKey: k1.publicKey,
    });
    const aliceIdentity = history.identity;

    // Eve tries to construct a new history claiming Alice's identity while
    // her inception event is signed by kEve.
    const { history: eveHistory } = KeyHistory.incept({
      inceptionSecretKey: kEve.secretKey,
      inceptionPublicKey: kEve.publicKey,
      nextPublicKey: kEve.publicKey,
    });
    // Eve's KeyHistory has a DIFFERENT identity (derives from kEve), not
    // Alice's.
    expect(eveHistory.identity).not.toBe(aliceIdentity);

    // If Eve tries to verify her chain UNDER Alice's identity DID, the
    // chain verification fails because event 0's identity field is wrong.
    const result = KeyHistory.verifyChain(
      eveHistory.getEvents(),
      aliceIdentity, // expectedIdentity (Alice's), not Eve's
    );
    expect(result.valid).toBe(false);
  });

  it("attacker who steals BOTH K1 and K2 can rotate — this is the limit of pre-rotation", () => {
    // Pre-rotation defends against single-key compromise, not against an
    // attacker who compromises the "held in escrow" next key too. We test
    // this as a known-limit acknowledgement, not a successful defense.
    const k0 = crypto.signing.generateKeyPair();
    const k1 = crypto.signing.generateKeyPair();
    const k2 = crypto.signing.generateKeyPair();
    const k3 = crypto.signing.generateKeyPair();

    const { history } = KeyHistory.incept({
      inceptionSecretKey: k0.secretKey,
      inceptionPublicKey: k0.publicKey,
      nextPublicKey: k1.publicKey,
    });
    history.rotate({
      currentSecretKey: k1.secretKey,
      currentPublicKey: k1.publicKey,
      nextPublicKey: k2.publicKey,
    });
    // Attacker has K2 (the pre-committed next key) AND K1 (the current
    // signing key). They CAN perform a rotation.
    const rotation = history.rotate({
      currentSecretKey: k2.secretKey,
      currentPublicKey: k2.publicKey,
      nextPublicKey: k3.publicKey,
    });
    expect(rotation.sequence).toBe(2);
    expect(history.verify().valid).toBe(true);
    // This confirms the operator must protect BOTH keys — limit acknowledged.
  });

  it("tampering with a rotation event's signature breaks chain verification", () => {
    const k0 = crypto.signing.generateKeyPair();
    const k1 = crypto.signing.generateKeyPair();
    const k2 = crypto.signing.generateKeyPair();

    const { history } = KeyHistory.incept({
      inceptionSecretKey: k0.secretKey,
      inceptionPublicKey: k0.publicKey,
      nextPublicKey: k1.publicKey,
    });
    history.rotate({
      currentSecretKey: k1.secretKey,
      currentPublicKey: k1.publicKey,
      nextPublicKey: k2.publicKey,
    });
    const events = [...history.getEvents()];
    // Eve mutates the signature on the inception event.
    events[0] = {
      ...events[0],
      signature: crypto.encoding.encodeBase64(new Uint8Array(64)),
    };
    const result = KeyHistory.verifyChain(events, history.identity);
    expect(result.valid).toBe(false);
  });
});
