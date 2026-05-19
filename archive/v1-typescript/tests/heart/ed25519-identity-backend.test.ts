/**
 * Ed25519IdentityBackend — end-to-end tests against CredentialRotationController.
 *
 * Verifies that the real backend plus the controller agree on:
 *  - pre-rotation (both layers enforce it),
 *  - KeyHistory chain integrity after controller-driven rotations,
 *  - verify-before-revoke semantics (old credentials stay verifiable during grace),
 *  - secret-key zeroization on revoke (best-effort — the byte buffer is cleared).
 */

import { describe, it, expect } from "vitest";
import {
  CredentialRotationController,
  Ed25519IdentityBackend,
  DEFAULT_POLICY,
  type ControllerPolicy,
} from "../../src/heart/credential-rotation/index.js";
import { KeyHistory } from "../../src/heart/key-rotation.js";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";

const crypto = getCryptoProvider();

function makeController(): {
  controller: CredentialRotationController;
  backend: Ed25519IdentityBackend;
  clockRef: { t: number };
} {
  const clockRef = { t: 1_700_000_000_000 };
  const policy: ControllerPolicy = {
    ...DEFAULT_POLICY,
    backendAllowlist: ["ed25519-identity"],
  };
  const controller = new CredentialRotationController({
    policy,
    clock: () => clockRef.t,
  });
  const backend = new Ed25519IdentityBackend({ backendId: "ed25519-identity" });
  controller.registerBackend(backend);
  return { controller, backend, clockRef };
}

async function inceptAndEffect(
  controller: CredentialRotationController,
  identityId: string,
) {
  const { event, credential } = await controller.incept({
    identityId,
    backendId: "ed25519-identity",
  });
  controller.anchorEvent(identityId, event.hash, "pulse-root-0");
  controller.witnessEvent(identityId, event.hash);
  return { event, credential };
}

async function rotateAndEffect(
  controller: CredentialRotationController,
  identityId: string,
  rootLabel: string,
) {
  const { event, credential } = await controller.rotate(identityId);
  controller.anchorEvent(identityId, event.hash, rootLabel);
  controller.witnessEvent(identityId, event.hash);
  return { event, credential };
}

describe("Ed25519IdentityBackend — inception", () => {
  it("mints an inception credential and starts a KeyHistory", async () => {
    const { controller, backend } = makeController();
    const { credential } = await inceptAndEffect(controller, "alice");

    expect(credential.algorithmSuite).toBe("ed25519");
    expect(credential.class).toBe("A");
    expect(credential.publicKey.length).toBe(32);

    const events = backend.getKeyHistoryEvents("alice");
    expect(events.length).toBe(1);
    expect(events[0]!.eventType).toBe("inception");
    expect(events[0]!.sequence).toBe(0);

    // KeyHistory verifies standalone.
    const ident = events[0]!.identity;
    expect(KeyHistory.verifyChain([...events], ident).valid).toBe(true);
  });

  it("refuses to incept the same identity twice at the backend level", async () => {
    const { backend } = makeController();
    await backend.issueCredential({
      identityId: "alice",
      issuedAt: Date.now(),
      ttlMs: 10 * 60 * 1000,
    });
    await expect(
      backend.issueCredential({
        identityId: "alice",
        issuedAt: Date.now(),
        ttlMs: 10 * 60 * 1000,
      }),
    ).rejects.toThrowError(/already inceptioned/);
  });
});

describe("Ed25519IdentityBackend — rotation", () => {
  it("round-trips a controller rotation and extends the KeyHistory chain", async () => {
    const { controller, backend, clockRef } = makeController();
    await inceptAndEffect(controller, "alice");

    clockRef.t += 60_000;
    const { credential: c1 } = await rotateAndEffect(controller, "alice", "pulse-root-1");

    clockRef.t += 60_000;
    const { credential: c2 } = await rotateAndEffect(controller, "alice", "pulse-root-2");

    expect(c1.credentialId).not.toBe(c2.credentialId);

    const events = backend.getKeyHistoryEvents("alice");
    expect(events.length).toBe(3); // inception + 2 rotations
    expect(events[1]!.eventType).toBe("rotation");
    expect(events[2]!.eventType).toBe("rotation");

    // Full KeyHistory chain verifies — pre-rotation digests match all the way.
    const identity = events[0]!.identity;
    const check = KeyHistory.verifyChain([...events], identity);
    expect(check.valid).toBe(true);
  });

  it("signs with the current credential and the signature verifies through the backend", async () => {
    const { controller, backend } = makeController();
    const { credential } = await inceptAndEffect(controller, "alice");

    const msg = new TextEncoder().encode("hello-from-alice");
    const sig = await controller.sign("alice", msg);
    expect(await controller.verify("alice", msg, sig)).toBe(true);

    // Direct backend verify should also pass.
    expect(
      await backend.verifyWithCredential(credential.credentialId, msg, sig),
    ).toBe(true);
  });

  it("zeroizes the secret key buffer on revoke (best-effort)", async () => {
    const { controller, backend, clockRef } = makeController();
    const { credential: c0 } = await inceptAndEffect(controller, "alice");

    // Capture a reference to the underlying secret key bytes.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stored = (backend as any).secrets.get(c0.credentialId);
    expect(stored).toBeTruthy();
    const secretRef: Uint8Array = stored.keyPair.secretKey;
    // At this point the first byte is almost certainly non-zero; if it is
    // zero by coincidence, check the first non-zero byte instead.
    const nonZeroBefore = secretRef.some(b => b !== 0);
    expect(nonZeroBefore).toBe(true);

    clockRef.t += 60_000;
    const { event: r1 } = await controller.rotate("alice");
    controller.anchorEvent("alice", r1.hash, "r1");
    controller.witnessEvent("alice", r1.hash);
    await controller.ackPropagation("alice", c0.credentialId);

    // After revoke, the bytes should all be zero.
    expect(secretRef.every(b => b === 0)).toBe(true);
  });

  it("verify-before-revoke: old credential still verifies during grace period", async () => {
    const { controller, clockRef } = makeController();
    const { credential: c0 } = await inceptAndEffect(controller, "alice");

    const msg = new TextEncoder().encode("signed-before-rotation");
    const sig = await controller.sign("alice", msg);

    clockRef.t += 60_000;
    const { event: r1 } = await controller.rotate("alice");
    controller.anchorEvent("alice", r1.hash, "r1");
    controller.witnessEvent("alice", r1.hash);

    // Old sig still verifies — c0 is in the accepted pool.
    expect(await controller.verify("alice", msg, sig)).toBe(true);

    // After ack, c0 is revoked in the backend and no longer verifies.
    await controller.ackPropagation("alice", c0.credentialId);
    expect(await controller.verify("alice", msg, sig)).toBe(false);
  });
});

describe("Ed25519IdentityBackend — KeyHistory-level pre-rotation integrity", () => {
  it("KeyHistory chain remains valid across many controller rotations", async () => {
    const { controller, backend, clockRef } = makeController();
    await inceptAndEffect(controller, "alice");

    for (let i = 1; i <= 5; i++) {
      clockRef.t += 60_000;
      await rotateAndEffect(controller, "alice", `pulse-root-${i}`);
    }

    const events = backend.getKeyHistoryEvents("alice");
    expect(events.length).toBe(6); // inception + 5 rotations
    const identity = events[0]!.identity;
    expect(KeyHistory.verifyChain([...events], identity).valid).toBe(true);

    // Every event after inception is a rotation; sequence is monotonic.
    for (let i = 0; i < events.length; i++) {
      expect(events[i]!.sequence).toBe(i);
    }
  });
});

describe("Ed25519IdentityBackend — isolation", () => {
  it("two identities in the same backend have independent KeyHistories", async () => {
    const { controller, backend, clockRef } = makeController();
    await inceptAndEffect(controller, "alice");
    await inceptAndEffect(controller, "bob");

    clockRef.t += 60_000;
    await rotateAndEffect(controller, "alice", "alice-r1");

    const aliceEvents = backend.getKeyHistoryEvents("alice");
    const bobEvents = backend.getKeyHistoryEvents("bob");
    expect(aliceEvents.length).toBe(2);
    expect(bobEvents.length).toBe(1);
    expect(aliceEvents[0]!.identity).not.toBe(bobEvents[0]!.identity);
  });
});
