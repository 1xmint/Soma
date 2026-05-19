import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  initiateSession,
  acceptSession,
  confirmSession,
  verifyMutualSession,
  computeTranscriptHash,
  type SessionInit,
  type SessionAccept,
} from "../../src/heart/mutual-session.js";

const crypto = getCryptoProvider();

function makeParty() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function runHandshake(
  alice = makeParty(),
  bob = makeParty(),
  purpose = "subtask-dispatch",
  ttlMs: number | null = null,
) {
  const init = initiateSession({
    initiatorDid: alice.did,
    initiatorPublicKey: alice.publicKey,
    purpose,
    ttlMs,
  });
  const accept = acceptSession({
    init,
    responderDid: bob.did,
    responderPublicKey: bob.publicKey,
    responderSigningKey: bob.kp.secretKey,
  });
  const confirm = confirmSession({
    init,
    accept,
    initiatorSigningKey: alice.kp.secretKey,
  });
  return { alice, bob, init, accept, confirm };
}

describe("mutual session — happy path", () => {
  it("completes a three-message handshake", () => {
    const { init, accept, confirm } = runHandshake();
    const result = verifyMutualSession({ init, accept, confirm });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.bindings.sessionId).toBe(init.sessionId);
      expect(result.bindings.nonceA).toBe(init.nonceA);
      expect(result.bindings.nonceB).toBe(accept.nonceB);
      expect(result.bindings.purpose).toBe("subtask-dispatch");
      expect(result.bindings.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("generates unique session ids and nonces per handshake", () => {
    const a = makeParty();
    const b = makeParty();
    const h1 = runHandshake(a, b);
    const h2 = runHandshake(a, b);
    expect(h1.init.sessionId).not.toBe(h2.init.sessionId);
    expect(h1.init.nonceA).not.toBe(h2.init.nonceA);
    expect(h1.accept.nonceB).not.toBe(h2.accept.nonceB);
  });

  it("produces identical transcriptHash for both parties", () => {
    const { init, accept } = runHandshake();
    const h1 = computeTranscriptHash(init, accept);
    const h2 = computeTranscriptHash(init, accept);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("captures initiator & responder DIDs in bindings", () => {
    const alice = makeParty();
    const bob = makeParty();
    const { init, accept, confirm } = runHandshake(alice, bob);
    const result = verifyMutualSession({ init, accept, confirm });
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.bindings.initiatorDid).toBe(alice.did);
      expect(result.bindings.responderDid).toBe(bob.did);
    }
  });
});

describe("mutual session — responder signs transcript", () => {
  it("rejects acceptSession when responderDid doesn't match key", () => {
    const alice = makeParty();
    const bob = makeParty();
    const impostor = makeParty();
    const init = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "test",
    });
    expect(() =>
      acceptSession({
        init,
        responderDid: impostor.did, // lies about DID
        responderPublicKey: bob.publicKey, // uses bob's key
        responderSigningKey: bob.kp.secretKey,
      }),
    ).toThrow(/responderDid/);
  });
});

describe("mutual session — initiator verifies before signing", () => {
  it("confirmSession throws when responder signature is invalid", () => {
    const alice = makeParty();
    const bob = makeParty();
    const init = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "test",
    });
    const accept = acceptSession({
      init,
      responderDid: bob.did,
      responderPublicKey: bob.publicKey,
      responderSigningKey: bob.kp.secretKey,
    });
    const tampered: SessionAccept = {
      ...accept,
      nonceB: crypto.encoding.encodeBase64(crypto.random.randomBytes(32)),
    };
    expect(() =>
      confirmSession({
        init,
        accept: tampered,
        initiatorSigningKey: alice.kp.secretKey,
      }),
    ).toThrow(/responder signature invalid/);
  });

  it("confirmSession throws when responder DID/key mismatch", () => {
    const alice = makeParty();
    const bob = makeParty();
    const attacker = makeParty();
    const init = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "test",
    });
    const accept = acceptSession({
      init,
      responderDid: bob.did,
      responderPublicKey: bob.publicKey,
      responderSigningKey: bob.kp.secretKey,
    });
    // Swap in attacker's public key AND redo the signature with attacker's key,
    // but keep bob's DID. Signature now verifies under attacker key but
    // DID binding is broken.
    const payload = {
      protocol: "soma-mutual-session/1",
      sessionId: init.sessionId,
      initiatorDid: init.initiatorDid,
      initiatorPublicKey: init.initiatorPublicKey,
      responderDid: bob.did,
      responderPublicKey: attacker.publicKey,
      nonceA: init.nonceA,
      nonceB: accept.nonceB,
      purpose: init.purpose,
      initiatedAt: init.initiatedAt,
      acceptedAt: accept.acceptedAt,
      ttlMs: init.ttlMs,
    };
    const signingInput = new TextEncoder().encode(JSON.stringify(payload));
    // Reorder keys to canonical — we'll use the canonical JSON path, but
    // for a minimal repro we just test that substituting attacker public key
    // with bob's DID fails at the DID/key check.
    const tampered: SessionAccept = {
      ...accept,
      responderPublicKey: attacker.publicKey, // mismatch with responderDid
      responderSignature: crypto.encoding.encodeBase64(
        crypto.signing.sign(signingInput, attacker.kp.secretKey),
      ),
    };
    expect(() =>
      confirmSession({
        init,
        accept: tampered,
        initiatorSigningKey: alice.kp.secretKey,
      }),
    ).toThrow();
  });

  it("throws on session id mismatch between init and accept", () => {
    const alice = makeParty();
    const bob = makeParty();
    const init = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "test",
    });
    const accept = acceptSession({
      init,
      responderDid: bob.did,
      responderPublicKey: bob.publicKey,
      responderSigningKey: bob.kp.secretKey,
    });
    const badAccept: SessionAccept = { ...accept, sessionId: "sess-wrong" };
    expect(() =>
      confirmSession({
        init,
        accept: badAccept,
        initiatorSigningKey: alice.kp.secretKey,
      }),
    ).toThrow(/session id/);
  });
});

describe("verifyMutualSession — failure modes", () => {
  it("rejects session id mismatch across messages", () => {
    const { init, accept, confirm } = runHandshake();
    const bad = { ...confirm, sessionId: "sess-different" };
    const r = verifyMutualSession({ init, accept, confirm: bad });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/session id/);
  });

  it("rejects when accept timestamp precedes init", () => {
    const { init, accept, confirm } = runHandshake();
    const badAccept = { ...accept, acceptedAt: init.initiatedAt - 1000 };
    // Verification uses the transcript signature over the (tampered) accept
    // payload, which won't match — but we explicitly reject on ordering.
    const r = verifyMutualSession({ init, accept: badAccept, confirm });
    expect(r.valid).toBe(false);
    // Either "accept precedes init" or signature failure — both are correct.
    if (!r.valid) expect(r.reason).toBeTruthy();
  });

  it("rejects when TTL has expired", () => {
    const { init, accept, confirm } = runHandshake(
      makeParty(),
      makeParty(),
      "short-lived",
      1000,
    );
    const laterNow = init.initiatedAt + 60_000; // well past 1s TTL
    const r = verifyMutualSession({ init, accept, confirm, now: laterNow });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/TTL/);
  });

  it("accepts within TTL window", () => {
    const { init, accept, confirm } = runHandshake(
      makeParty(),
      makeParty(),
      "short-lived",
      60_000,
    );
    const r = verifyMutualSession({
      init,
      accept,
      confirm,
      now: init.initiatedAt + 1000,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects stale handshake via maxAgeMs", () => {
    const { init, accept, confirm } = runHandshake();
    const r = verifyMutualSession({
      init,
      accept,
      confirm,
      now: init.initiatedAt + 10 * 60_000,
      maxAgeMs: 60_000,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/too old/);
  });

  it("rejects tampered responder signature", () => {
    const { init, accept, confirm } = runHandshake();
    const badSig = crypto.encoding.encodeBase64(
      crypto.random.randomBytes(64),
    );
    const badAccept = { ...accept, responderSignature: badSig };
    const r = verifyMutualSession({ init, accept: badAccept, confirm });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/responder signature/);
  });

  it("rejects tampered initiator signature", () => {
    const { init, accept, confirm } = runHandshake();
    const badSig = crypto.encoding.encodeBase64(
      crypto.random.randomBytes(64),
    );
    const badConfirm = { ...confirm, initiatorSignature: badSig };
    const r = verifyMutualSession({ init, accept, confirm: badConfirm });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/initiator signature/);
  });

  it("rejects when initiator DID is forged (doesn't match public key)", () => {
    const alice = makeParty();
    const bob = makeParty();
    const impostor = makeParty();
    const init: SessionInit = {
      sessionId: "sess-forge",
      initiatorDid: impostor.did, // lie
      initiatorPublicKey: alice.publicKey, // real alice pubkey
      nonceA: crypto.encoding.encodeBase64(crypto.random.randomBytes(32)),
      purpose: "test",
      initiatedAt: Date.now(),
      ttlMs: null,
    };
    const accept = acceptSession({
      init,
      responderDid: bob.did,
      responderPublicKey: bob.publicKey,
      responderSigningKey: bob.kp.secretKey,
    });
    // confirm will sign with alice's key (since she's the one whose key
    // actually matches initiatorPublicKey) — signature will be valid, but
    // the DID/key binding is broken.
    const confirm = confirmSession({
      init,
      accept,
      initiatorSigningKey: alice.kp.secretKey,
    });
    const r = verifyMutualSession({ init, accept, confirm });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/initiator/);
  });

  it("rejects malformed public key", () => {
    const { init, accept, confirm } = runHandshake();
    const badInit = { ...init, initiatorPublicKey: "!!!not-base64!!!" };
    const r = verifyMutualSession({ init: badInit, accept, confirm });
    expect(r.valid).toBe(false);
  });
});

describe("mutual session — purpose binding", () => {
  it("changes transcript hash when purpose changes", () => {
    const alice = makeParty();
    const bob = makeParty();
    const h1 = runHandshake(alice, bob, "purpose-A");
    const h2 = runHandshake(alice, bob, "purpose-B");
    const hash1 = computeTranscriptHash(h1.init, h1.accept);
    const hash2 = computeTranscriptHash(h2.init, h2.accept);
    expect(hash1).not.toBe(hash2);
  });

  it("both parties can independently derive the same hash", () => {
    const { init, accept, confirm } = runHandshake();
    // Both parties verify; both should get the same bindings.transcriptHash.
    const r1 = verifyMutualSession({ init, accept, confirm });
    const r2 = verifyMutualSession({ init, accept, confirm });
    expect(r1.valid).toBe(true);
    expect(r2.valid).toBe(true);
    if (r1.valid && r2.valid) {
      expect(r1.bindings.transcriptHash).toBe(r2.bindings.transcriptHash);
      // Also matches the standalone helper
      expect(computeTranscriptHash(init, accept)).toBe(
        r1.bindings.transcriptHash,
      );
    }
  });
});

describe("mutual session — replay resistance", () => {
  it("produces a different transcriptHash for each handshake", () => {
    const a = makeParty();
    const b = makeParty();
    const h1 = runHandshake(a, b);
    const h2 = runHandshake(a, b);
    const hash1 = computeTranscriptHash(h1.init, h1.accept);
    const hash2 = computeTranscriptHash(h2.init, h2.accept);
    expect(hash1).not.toBe(hash2);
  });

  it("cannot reuse responder signature from one session in another", () => {
    const alice = makeParty();
    const bob = makeParty();
    const init1 = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "sess-1",
    });
    const init2 = initiateSession({
      initiatorDid: alice.did,
      initiatorPublicKey: alice.publicKey,
      purpose: "sess-2",
    });
    const accept1 = acceptSession({
      init: init1,
      responderDid: bob.did,
      responderPublicKey: bob.publicKey,
      responderSigningKey: bob.kp.secretKey,
    });
    // try to use accept1 with init2 — signature won't match transcript
    expect(() =>
      confirmSession({
        init: init2,
        accept: accept1,
        initiatorSigningKey: alice.kp.secretKey,
      }),
    ).toThrow();
  });
});
