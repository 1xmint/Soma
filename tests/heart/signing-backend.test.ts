import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  InProcessBackend,
  DelegatedBackend,
  BackendRegistry,
  handleToDid,
  type SigningKeyHandle,
} from "../../src/heart/signing-backend.js";

const crypto = getCryptoProvider();

function msg(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("InProcessBackend", () => {
  it("generates and signs with a fresh key", async () => {
    const backend = new InProcessBackend();
    const handle = backend.generateKey();
    expect(handle.backendId).toBe("in-process");
    expect(handle.publicKey).toHaveLength(32);

    const sig = await backend.sign(handle, msg("hello"));
    expect(sig).toHaveLength(64);
    expect(backend.verify(msg("hello"), sig, handle.publicKey)).toBe(true);
  });

  it("imports an existing key pair", async () => {
    const backend = new InProcessBackend();
    const kp = crypto.signing.generateKeyPair();
    const handle = backend.importKey("alice-v1", kp.publicKey, kp.secretKey);
    expect(handle.keyId).toBe("alice-v1");

    const sig = await backend.sign(handle, msg("x"));
    expect(crypto.signing.verify(msg("x"), sig, kp.publicKey)).toBe(true);
  });

  it("rejects handles from another backend", async () => {
    const backend = new InProcessBackend();
    const handle: SigningKeyHandle = {
      publicKey: new Uint8Array(32),
      backendId: "other-backend",
      keyId: "alien",
    };
    await expect(async () => backend.sign(handle, msg("x"))).rejects.toThrow(
      /belongs to/,
    );
  });

  it("throws on unknown keyId", async () => {
    const backend = new InProcessBackend();
    const handle: SigningKeyHandle = {
      publicKey: new Uint8Array(32),
      backendId: "in-process",
      keyId: "ghost",
    };
    await expect(async () => backend.sign(handle, msg("x"))).rejects.toThrow(
      /unknown keyId/,
    );
  });

  it("lists handles", () => {
    const backend = new InProcessBackend();
    backend.generateKey({ keyId: "a" });
    backend.generateKey({ keyId: "b" });
    const list = backend.listHandles();
    expect(list).toHaveLength(2);
    expect(list.map((h) => h.keyId).sort()).toEqual(["a", "b"]);
  });

  it("deleteKey removes a key", () => {
    const backend = new InProcessBackend();
    backend.generateKey({ keyId: "temp" });
    expect(backend.listHandles()).toHaveLength(1);
    expect(backend.deleteKey("temp")).toBe(true);
    expect(backend.listHandles()).toHaveLength(0);
    expect(backend.deleteKey("temp")).toBe(false);
  });

  it("exportSecretKey returns a copy", () => {
    const backend = new InProcessBackend();
    const handle = backend.generateKey({ keyId: "export-me" });
    const exported = backend.exportSecretKey(handle);
    expect(exported).toHaveLength(64);
    // Mutating export should not affect the stored key.
    exported[0] = 0xff;
    const exported2 = backend.exportSecretKey(handle);
    expect(exported2[0]).not.toBe(0xff);
  });

  it("signs deterministically (Ed25519)", async () => {
    const backend = new InProcessBackend();
    const handle = backend.generateKey();
    const s1 = await backend.sign(handle, msg("same"));
    const s2 = await backend.sign(handle, msg("same"));
    expect(s1).toEqual(s2);
  });
});

describe("DelegatedBackend", () => {
  it("signs by invoking the delegate", async () => {
    const kp = crypto.signing.generateKeyPair();
    const handle: SigningKeyHandle = {
      publicKey: kp.publicKey,
      backendId: "mock-hsm",
      keyId: "slot-0",
    };
    let called = 0;
    const backend = new DelegatedBackend({
      backendId: "mock-hsm",
      sign: async (h, m) => {
        called++;
        expect(h.keyId).toBe("slot-0");
        return crypto.signing.sign(m, kp.secretKey);
      },
      handles: [handle],
    });
    const sig = await backend.sign(handle, msg("hello"));
    expect(called).toBe(1);
    expect(backend.verify(msg("hello"), sig, kp.publicKey)).toBe(true);
  });

  it("rejects delegate that returns a bad signature", async () => {
    const kp = crypto.signing.generateKeyPair();
    const handle: SigningKeyHandle = {
      publicKey: kp.publicKey,
      backendId: "bad-hsm",
      keyId: "slot-0",
    };
    const backend = new DelegatedBackend({
      backendId: "bad-hsm",
      sign: async () => crypto.random.randomBytes(64), // junk sig
    });
    await expect(async () => backend.sign(handle, msg("x"))).rejects.toThrow(
      /does not verify/,
    );
  });

  it("rejects handles from other backends", async () => {
    const backend = new DelegatedBackend({
      backendId: "hsm-a",
      sign: async () => new Uint8Array(64),
    });
    const handle: SigningKeyHandle = {
      publicKey: new Uint8Array(32),
      backendId: "hsm-b",
      keyId: "x",
    };
    await expect(async () => backend.sign(handle, msg("x"))).rejects.toThrow(
      /belongs to/,
    );
  });

  it("registerHandle adds handles post-construction", () => {
    const backend = new DelegatedBackend({
      backendId: "hsm",
      sign: async () => new Uint8Array(64),
    });
    expect(backend.listHandles()).toHaveLength(0);
    backend.registerHandle({
      publicKey: new Uint8Array(32),
      backendId: "hsm",
      keyId: "late-arrival",
    });
    expect(backend.listHandles()).toHaveLength(1);
  });

  it("registerHandle rejects mismatched backendId", () => {
    const backend = new DelegatedBackend({
      backendId: "hsm",
      sign: async () => new Uint8Array(64),
    });
    expect(() =>
      backend.registerHandle({
        publicKey: new Uint8Array(32),
        backendId: "other",
        keyId: "x",
      }),
    ).toThrow(/does not match/);
  });

  it("constructor rejects mismatched initial handles", () => {
    expect(
      () =>
        new DelegatedBackend({
          backendId: "hsm",
          sign: async () => new Uint8Array(64),
          handles: [
            { publicKey: new Uint8Array(32), backendId: "other", keyId: "x" },
          ],
        }),
    ).toThrow(/does not match/);
  });
});

describe("BackendRegistry", () => {
  it("routes signing to the correct backend", async () => {
    const inproc = new InProcessBackend();
    const handle = inproc.generateKey({ keyId: "k1" });
    const registry = new BackendRegistry();
    registry.register(inproc);
    const sig = await registry.sign(handle, msg("routed"));
    expect(inproc.verify(msg("routed"), sig, handle.publicKey)).toBe(true);
  });

  it("handles multiple backends concurrently", async () => {
    const inproc = new InProcessBackend();
    const kp = crypto.signing.generateKeyPair();
    const hsmHandle: SigningKeyHandle = {
      publicKey: kp.publicKey,
      backendId: "ledger",
      keyId: "path/0",
    };
    const ledger = new DelegatedBackend({
      backendId: "ledger",
      sign: async (_h, m) => crypto.signing.sign(m, kp.secretKey),
      handles: [hsmHandle],
    });
    const registry = new BackendRegistry();
    registry.register(inproc);
    registry.register(ledger);

    const softHandle = inproc.generateKey({ keyId: "soft-1" });
    const s1 = await registry.sign(softHandle, msg("m1"));
    const s2 = await registry.sign(hsmHandle, msg("m2"));
    expect(
      crypto.signing.verify(msg("m1"), s1, softHandle.publicKey),
    ).toBe(true);
    expect(crypto.signing.verify(msg("m2"), s2, kp.publicKey)).toBe(true);
  });

  it("rejects duplicate registration", () => {
    const registry = new BackendRegistry();
    registry.register(new InProcessBackend());
    expect(() => registry.register(new InProcessBackend())).toThrow(
      /already registered/,
    );
  });

  it("throws when backend missing", async () => {
    const registry = new BackendRegistry();
    const handle: SigningKeyHandle = {
      publicKey: new Uint8Array(32),
      backendId: "ghost",
      keyId: "x",
    };
    await expect(async () =>
      registry.sign(handle, msg("x")),
    ).rejects.toThrow(/no backend/);
  });

  it("reports has / size correctly", () => {
    const registry = new BackendRegistry();
    expect(registry.has("in-process")).toBe(false);
    expect(registry.size()).toBe(0);
    registry.register(new InProcessBackend());
    expect(registry.has("in-process")).toBe(true);
    expect(registry.size()).toBe(1);
  });

  it("verify falls back to default provider when empty", () => {
    const registry = new BackendRegistry();
    const kp = crypto.signing.generateKeyPair();
    const sig = crypto.signing.sign(msg("x"), kp.secretKey);
    expect(registry.verify(msg("x"), sig, kp.publicKey)).toBe(true);
  });
});

describe("handleToDid", () => {
  it("returns stable DID for a handle", () => {
    const backend = new InProcessBackend();
    const handle = backend.generateKey();
    expect(handleToDid(handle)).toBe(publicKeyToDid(handle.publicKey));
  });
});

describe("backend interop with existing code paths", () => {
  it("signatures produced by backend verify with raw crypto provider", async () => {
    // Key takeaway: a signature produced by any backend is STILL a standard
    // Ed25519 signature — existing verifyRevocation/verifyAttestation etc.
    // will all accept it without modification.
    const backend = new InProcessBackend();
    const handle = backend.generateKey();
    const message = msg("any standard Ed25519 signature");
    const sig = await backend.sign(handle, message);
    expect(crypto.signing.verify(message, sig, handle.publicKey)).toBe(true);
  });
});
