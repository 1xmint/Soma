import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import {
  DidKeyMethod,
  DidWebMethod,
  DidPkhMethod,
  DidMethodRegistry,
  createDefaultDidRegistry,
  verifySignatureViaDid,
  type DidWebFetcher,
  type DidWebDocumentJson,
  type DidVerificationKey,
} from "../../src/core/did-method.js";
import { publicKeyToDid } from "../../src/core/genome.js";

const crypto = getCryptoProvider();

function msg(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ─── DidKeyMethod ───────────────────────────────────────────────────────────

describe("DidKeyMethod", () => {
  it("identifies a public key as did:key", () => {
    const method = new DidKeyMethod();
    const kp = crypto.signing.generateKeyPair();
    const did = method.identify(kp.publicKey);
    expect(did).toMatch(/^did:key:z/);
    expect(did).toBe(publicKeyToDid(kp.publicKey));
  });

  it("matches did:key prefix", () => {
    const method = new DidKeyMethod();
    expect(method.matches("did:key:z6MkabcXYZ")).toBe(true);
    expect(method.matches("did:web:example.com")).toBe(false);
    expect(method.matches("did:pkh:eip155:1:0xabc")).toBe(false);
  });

  it("resolves back to the same public key", async () => {
    const method = new DidKeyMethod();
    const kp = crypto.signing.generateKeyPair();
    const did = method.identify(kp.publicKey);
    const doc = await method.resolve(did);
    expect(doc.did).toBe(did);
    expect(doc.verificationKeys).toHaveLength(1);
    expect(doc.verificationKeys[0].publicKey).toEqual(kp.publicKey);
    expect(doc.verificationKeys[0].algorithmId).toBe("ed25519");
    expect(doc.verificationKeys[0].purpose).toBe("authentication");
  });

  it("resolve throws on malformed did:key", async () => {
    const method = new DidKeyMethod();
    await expect(method.resolve("did:key:garbage-not-base64!")).rejects.toThrow();
  });
});

// ─── DidWebMethod ───────────────────────────────────────────────────────────

describe("DidWebMethod", () => {
  it("matches did:web prefix", () => {
    const method = new DidWebMethod(async () => ({}));
    expect(method.matches("did:web:example.com")).toBe(true);
    expect(method.matches("did:key:z6MkabcXYZ")).toBe(false);
  });

  it("converts did:web:example.com to well-known URL", () => {
    expect(DidWebMethod.didToUrl("did:web:example.com")).toBe(
      "https://example.com/.well-known/did.json",
    );
  });

  it("converts did:web with path to nested URL", () => {
    expect(DidWebMethod.didToUrl("did:web:example.com:users:alice")).toBe(
      "https://example.com/users/alice/did.json",
    );
  });

  it("rejects non-did:web in didToUrl", () => {
    expect(() => DidWebMethod.didToUrl("did:key:z6Mk")).toThrow(/not a did:web/);
  });

  it("rejects empty domain", () => {
    expect(() => DidWebMethod.didToUrl("did:web:")).toThrow(/missing domain/);
  });

  it("resolves a did document returned by the fetcher", async () => {
    const kp = crypto.signing.generateKeyPair();
    const fetcher: DidWebFetcher = async (url) => {
      expect(url).toBe("https://example.com/.well-known/did.json");
      return {
        id: "did:web:example.com",
        verificationMethod: [
          {
            id: "did:web:example.com#key-1",
            type: "ed25519",
            publicKeyBase64: crypto.encoding.encodeBase64(kp.publicKey),
          },
        ],
      };
    };
    const method = new DidWebMethod(fetcher);
    const doc = await method.resolve("did:web:example.com");
    expect(doc.did).toBe("did:web:example.com");
    expect(doc.verificationKeys).toHaveLength(1);
    expect(doc.verificationKeys[0].publicKey).toEqual(kp.publicKey);
    expect(doc.verificationKeys[0].keyId).toBe("did:web:example.com#key-1");
  });

  it("rejects document with mismatched id", async () => {
    const fetcher: DidWebFetcher = async () => ({
      id: "did:web:evil.com",
      verificationMethod: [],
    });
    const method = new DidWebMethod(fetcher);
    await expect(method.resolve("did:web:example.com")).rejects.toThrow(
      /id mismatch/,
    );
  });

  it("allows missing id field (spec-compliant for some issuers)", async () => {
    const kp = crypto.signing.generateKeyPair();
    const fetcher: DidWebFetcher = async () => ({
      verificationMethod: [
        {
          type: "ed25519",
          publicKeyBase64: crypto.encoding.encodeBase64(kp.publicKey),
        },
      ],
    });
    const method = new DidWebMethod(fetcher);
    const doc = await method.resolve("did:web:example.com");
    expect(doc.verificationKeys).toHaveLength(1);
  });

  it("skips keys without publicKeyBase64", async () => {
    const fetcher: DidWebFetcher = async () => ({
      verificationMethod: [
        { type: "ed25519", publicKeyMultibase: "z6MkabcXYZ" },
        { type: "ed25519", publicKeyBase58: "abc" },
      ],
    });
    const method = new DidWebMethod(fetcher);
    const doc = await method.resolve("did:web:example.com");
    expect(doc.verificationKeys).toEqual([]);
  });

  it("returns empty array for document with no verification methods", async () => {
    const fetcher: DidWebFetcher = async () => ({ id: "did:web:example.com" });
    const method = new DidWebMethod(fetcher);
    const doc = await method.resolve("did:web:example.com");
    expect(doc.verificationKeys).toEqual([]);
  });

  it("propagates fetcher errors", async () => {
    const fetcher: DidWebFetcher = async () => {
      throw new Error("network boom");
    };
    const method = new DidWebMethod(fetcher);
    await expect(method.resolve("did:web:example.com")).rejects.toThrow(
      /network boom/,
    );
  });

  it("rejects resolve for non-did:web input", async () => {
    const method = new DidWebMethod(async () => ({}));
    await expect(method.resolve("did:key:abc")).rejects.toThrow(/not a did:web/);
  });
});

// ─── DidPkhMethod ───────────────────────────────────────────────────────────

describe("DidPkhMethod", () => {
  it("matches did:pkh prefix", () => {
    const method = new DidPkhMethod();
    expect(method.matches("did:pkh:eip155:1:0xabc")).toBe(true);
    expect(method.matches("did:key:z6Mk")).toBe(false);
  });

  it("parses caip-10 format", () => {
    const id = DidPkhMethod.parse("did:pkh:eip155:1:0xAbCd1234");
    expect(id.chainNamespace).toBe("eip155");
    expect(id.chainReference).toBe("1");
    expect(id.account).toBe("0xAbCd1234");
  });

  it("parses solana did:pkh", () => {
    const id = DidPkhMethod.parse(
      "did:pkh:solana:mainnet:5FHwkrdxntdK24hgQU8qgBjn35Y1zwhz1GZwCkP2UJnM",
    );
    expect(id.chainNamespace).toBe("solana");
    expect(id.account).toBe("5FHwkrdxntdK24hgQU8qgBjn35Y1zwhz1GZwCkP2UJnM");
  });

  it("formats from identifier object", () => {
    const did = DidPkhMethod.format({
      chainNamespace: "eip155",
      chainReference: "1",
      account: "0xabc",
    });
    expect(did).toBe("did:pkh:eip155:1:0xabc");
  });

  it("rejects wrong segment count", () => {
    expect(() => DidPkhMethod.parse("did:pkh:eip155:1")).toThrow(/segments/);
    expect(() =>
      DidPkhMethod.parse("did:pkh:eip155:1:0xabc:extra"),
    ).toThrow(/segments/);
  });

  it("rejects empty segments", () => {
    expect(() => DidPkhMethod.parse("did:pkh:eip155::0xabc")).toThrow(/empty/);
  });

  it("rejects non-did:pkh input", () => {
    expect(() => DidPkhMethod.parse("did:key:z6Mk")).toThrow(/not a did:pkh/);
  });

  it("resolves without keys if no keyBinder", async () => {
    const method = new DidPkhMethod();
    const doc = await method.resolve("did:pkh:eip155:1:0xabc");
    expect(doc.verificationKeys).toEqual([]);
    expect(doc.metadata?.chainNamespace).toBe("eip155");
    expect(doc.metadata?.account).toBe("0xabc");
  });

  it("resolves with keys via keyBinder callback", async () => {
    const kp = crypto.signing.generateKeyPair();
    const method = new DidPkhMethod((pkh) => {
      expect(pkh.account).toBe("0xabc");
      return [
        {
          publicKey: kp.publicKey,
          algorithmId: "ed25519",
          purpose: "authentication",
        },
      ];
    });
    const doc = await method.resolve("did:pkh:eip155:1:0xabc");
    expect(doc.verificationKeys).toHaveLength(1);
    expect(doc.verificationKeys[0].publicKey).toEqual(kp.publicKey);
  });
});

// ─── DidMethodRegistry ──────────────────────────────────────────────────────

describe("DidMethodRegistry", () => {
  it("registers and retrieves methods", () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidKeyMethod());
    expect(reg.has("key")).toBe(true);
    expect(reg.get("key").methodName).toBe("key");
    expect(reg.size()).toBe(1);
  });

  it("rejects duplicate method registration", () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidKeyMethod());
    expect(() => reg.register(new DidKeyMethod())).toThrow(/already/);
  });

  it("get throws for unknown method", () => {
    const reg = new DidMethodRegistry();
    expect(() => reg.get("ghost")).toThrow(/no DID method/);
  });

  it("forDid routes by prefix", async () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidKeyMethod());
    reg.register(new DidPkhMethod());
    const kp = crypto.signing.generateKeyPair();
    const didKey = publicKeyToDid(kp.publicKey);
    expect(reg.forDid(didKey).methodName).toBe("key");
    expect(reg.forDid("did:pkh:eip155:1:0xabc").methodName).toBe("pkh");
  });

  it("forDid throws if no method matches", () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidKeyMethod());
    expect(() => reg.forDid("did:web:example.com")).toThrow(/no registered/);
  });

  it("resolve dispatches through forDid", async () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidKeyMethod());
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const doc = await reg.resolve(did);
    expect(doc.verificationKeys[0].publicKey).toEqual(kp.publicKey);
  });

  it("lists registered methods sorted", () => {
    const reg = new DidMethodRegistry();
    reg.register(new DidPkhMethod());
    reg.register(new DidKeyMethod());
    expect(reg.list()).toEqual(["key", "pkh"]);
  });
});

// ─── createDefaultDidRegistry ───────────────────────────────────────────────

describe("createDefaultDidRegistry", () => {
  it("pre-populates with DidKeyMethod", () => {
    const reg = createDefaultDidRegistry();
    expect(reg.has("key")).toBe(true);
    expect(reg.has("web")).toBe(false);
    expect(reg.has("pkh")).toBe(false);
  });
});

// ─── verifySignatureViaDid ──────────────────────────────────────────────────

describe("verifySignatureViaDid", () => {
  it("verifies a signature via did:key resolution", async () => {
    const reg = createDefaultDidRegistry();
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const m = msg("hello did");
    const sig = crypto.signing.sign(m, kp.secretKey);
    const match = await verifySignatureViaDid(did, m, sig, reg);
    expect(match).not.toBeNull();
    expect(match?.publicKey).toEqual(kp.publicKey);
  });

  it("returns null when signature is invalid", async () => {
    const reg = createDefaultDidRegistry();
    const kp = crypto.signing.generateKeyPair();
    const did = publicKeyToDid(kp.publicKey);
    const m = msg("hello");
    const badSig = new Uint8Array(64);
    const match = await verifySignatureViaDid(did, m, badSig, reg);
    expect(match).toBeNull();
  });

  it("tries all keys in the document", async () => {
    // Simulate a method returning two keys — only the second matches.
    const kpGood = crypto.signing.generateKeyPair();
    const kpBad = crypto.signing.generateKeyPair();
    const customMethod = {
      methodName: "custom",
      matches: (d: string) => d.startsWith("did:custom:"),
      resolve: async (did: string) => ({
        did,
        verificationKeys: [
          {
            publicKey: kpBad.publicKey,
            algorithmId: "ed25519",
          } as DidVerificationKey,
          {
            publicKey: kpGood.publicKey,
            algorithmId: "ed25519",
          } as DidVerificationKey,
        ],
      }),
    };
    const reg = new DidMethodRegistry();
    reg.register(customMethod);
    const m = msg("hello");
    const sig = crypto.signing.sign(m, kpGood.secretKey);
    const match = await verifySignatureViaDid(
      "did:custom:abc",
      m,
      sig,
      reg,
    );
    expect(match).not.toBeNull();
    expect(match?.publicKey).toEqual(kpGood.publicKey);
  });

  it("works via did:web through a stub fetcher", async () => {
    const kp = crypto.signing.generateKeyPair();
    const fetcher: DidWebFetcher = async (): Promise<DidWebDocumentJson> => ({
      id: "did:web:alice.test",
      verificationMethod: [
        {
          id: "did:web:alice.test#key-1",
          type: "ed25519",
          publicKeyBase64: crypto.encoding.encodeBase64(kp.publicKey),
        },
      ],
    });
    const reg = new DidMethodRegistry();
    reg.register(new DidWebMethod(fetcher));
    const m = msg("via did:web");
    const sig = crypto.signing.sign(m, kp.secretKey);
    const match = await verifySignatureViaDid(
      "did:web:alice.test",
      m,
      sig,
      reg,
    );
    expect(match).not.toBeNull();
    expect(match?.publicKey).toEqual(kp.publicKey);
  });
});
