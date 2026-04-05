import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createAttestationDocument,
  verifyAttestationDocument,
  NoopVerifier,
  MockTeeVerifier,
  type AttestationDocument,
  type MeasurementPolicy,
  type RemoteAttestationVerifier,
} from "../../src/heart/remote-attestation.js";

const crypto = getCryptoProvider();

function makeHeart() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function makeVendor() {
  return crypto.signing.generateKeyPair();
}

function makeAttestation(
  heart: ReturnType<typeof makeHeart>,
  vendor: ReturnType<typeof makeVendor>,
  measurements: Record<string, string>,
  nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16)),
) {
  const quote = MockTeeVerifier.issueQuote(vendor.secretKey, {
    nonce,
    publicKey: heart.publicKey,
    measurements,
  });
  const doc = createAttestationDocument({
    platform: "custom",
    platformDetail: "mock-sgx-v1",
    quote,
    measurements,
    heartDid: heart.did,
    heartPublicKey: heart.publicKey,
    heartSigningKey: heart.kp.secretKey,
    nonceB64: nonce,
  });
  const verifier = new MockTeeVerifier(vendor.publicKey, ["custom"]);
  return { heart, vendor, doc, verifier, nonce };
}

describe("createAttestationDocument", () => {
  it("creates a well-formed document", () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc } = makeAttestation(heart, vendor, {
      mrenclave: "abcd1234",
      mrsigner: "ffee9988",
    });
    expect(doc.id).toMatch(/^att-/);
    expect(doc.platform).toBe("custom");
    expect(doc.heartDid).toBe(heart.did);
    expect(doc.signature).toBeTruthy();
    expect(doc.measurements).toEqual({
      mrenclave: "abcd1234",
      mrsigner: "ffee9988",
    });
  });
});

describe("verifyAttestationDocument — happy path", () => {
  it("accepts valid attestation with mock verifier", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, {
      mrenclave: "abc123",
    });
    const r = await verifyAttestationDocument(doc, { verifiers: [verifier] });
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(r.heartDid).toBe(heart.did);
      expect(r.measurements.mrenclave).toBe("abc123");
    }
  });

  it("honors expectedNonce", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier, nonce } = makeAttestation(heart, vendor, {
      m: "1",
    });
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      expectedNonce: nonce,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects wrong expected nonce", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, { m: "1" });
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      expectedNonce: "wrong-nonce",
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/nonce/);
  });
});

describe("verifyAttestationDocument — envelope integrity", () => {
  it("rejects tampered heart signature", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, { m: "1" });
    const bad: AttestationDocument = {
      ...doc,
      signature: crypto.encoding.encodeBase64(crypto.random.randomBytes(64)),
    };
    const r = await verifyAttestationDocument(bad, { verifiers: [verifier] });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/heart signature/);
  });

  it("rejects tampered measurements", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, {
      mrenclave: "original",
    });
    const tampered: AttestationDocument = {
      ...doc,
      measurements: { mrenclave: "modified" },
    };
    const r = await verifyAttestationDocument(tampered, {
      verifiers: [verifier],
    });
    expect(r.valid).toBe(false);
  });

  it("rejects DID/key mismatch", async () => {
    const heart = makeHeart();
    const other = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, { m: "1" });
    const tampered: AttestationDocument = { ...doc, heartDid: other.did };
    const r = await verifyAttestationDocument(tampered, {
      verifiers: [verifier],
    });
    expect(r.valid).toBe(false);
  });
});

describe("verifyAttestationDocument — quote verification", () => {
  it("rejects quote signed by wrong vendor key", async () => {
    const heart = makeHeart();
    const realVendor = makeVendor();
    const attackerVendor = makeVendor();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    const badQuote = MockTeeVerifier.issueQuote(attackerVendor.secretKey, {
      nonce,
      publicKey: heart.publicKey,
      measurements: { m: "1" },
    });
    const doc = createAttestationDocument({
      platform: "custom",
      quote: badQuote,
      measurements: { m: "1" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
    });
    const verifier = new MockTeeVerifier(realVendor.publicKey, ["custom"]);
    const r = await verifyAttestationDocument(doc, { verifiers: [verifier] });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/vendor signature/);
  });

  it("rejects quote for wrong public key", async () => {
    const heart = makeHeart();
    const attacker = makeHeart();
    const vendor = makeVendor();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    // vendor issues quote for attacker's key, but doc claims heart's key
    const quote = MockTeeVerifier.issueQuote(vendor.secretKey, {
      nonce,
      publicKey: attacker.publicKey,
      measurements: { m: "1" },
    });
    const doc = createAttestationDocument({
      platform: "custom",
      quote,
      measurements: { m: "1" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
    });
    const verifier = new MockTeeVerifier(vendor.publicKey, ["custom"]);
    const r = await verifyAttestationDocument(doc, { verifiers: [verifier] });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/public key/);
  });

  it("rejects when no verifier for platform", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc } = makeAttestation(heart, vendor, { m: "1" });
    const wrongVerifier = new MockTeeVerifier(vendor.publicKey, ["aws-nitro"]);
    const r = await verifyAttestationDocument(doc, {
      verifiers: [wrongVerifier],
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/no verifier/);
  });

  it("selects correct verifier from a list", async () => {
    const heart = makeHeart();
    const sgxVendor = makeVendor();
    const nitroVendor = makeVendor();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    const quote = MockTeeVerifier.issueQuote(sgxVendor.secretKey, {
      nonce,
      publicKey: heart.publicKey,
      measurements: { m: "sgx" },
    });
    const doc = createAttestationDocument({
      platform: "intel-sgx",
      quote,
      measurements: { m: "sgx" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
    });
    const verifiers: RemoteAttestationVerifier[] = [
      new MockTeeVerifier(nitroVendor.publicKey, ["aws-nitro"]),
      new MockTeeVerifier(sgxVendor.publicKey, ["intel-sgx"]),
    ];
    const r = await verifyAttestationDocument(doc, { verifiers });
    expect(r.valid).toBe(true);
    if (r.valid) expect(r.platform).toBe("intel-sgx");
  });
});

describe("verifyAttestationDocument — expiry", () => {
  it("rejects expired documents", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    const quote = MockTeeVerifier.issueQuote(vendor.secretKey, {
      nonce,
      publicKey: heart.publicKey,
      measurements: { m: "1" },
    });
    const doc = createAttestationDocument({
      platform: "custom",
      quote,
      measurements: { m: "1" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
      expiresAt: Date.now() - 1000,
    });
    const verifier = new MockTeeVerifier(vendor.publicKey, ["custom"]);
    const r = await verifyAttestationDocument(doc, { verifiers: [verifier] });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/expired/);
  });

  it("accepts non-expired documents", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    const quote = MockTeeVerifier.issueQuote(vendor.secretKey, {
      nonce,
      publicKey: heart.publicKey,
      measurements: { m: "1" },
    });
    const doc = createAttestationDocument({
      platform: "custom",
      quote,
      measurements: { m: "1" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
      expiresAt: Date.now() + 3600_000,
    });
    const verifier = new MockTeeVerifier(vendor.publicKey, ["custom"]);
    const r = await verifyAttestationDocument(doc, { verifiers: [verifier] });
    expect(r.valid).toBe(true);
  });
});

describe("verifyAttestationDocument — measurement policy", () => {
  it("accepts when measurements match policy allowlist", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, {
      mrenclave: "aaaa",
      mrsigner: "bbbb",
    });
    const policies: MeasurementPolicy[] = [
      {
        platform: "custom",
        allow: {
          mrenclave: ["aaaa", "cccc"],
          mrsigner: ["bbbb"],
        },
      },
    ];
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      policies,
    });
    expect(r.valid).toBe(true);
  });

  it("rejects when measurement is not allowed", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, {
      mrenclave: "malicious-build",
    });
    const policies: MeasurementPolicy[] = [
      {
        platform: "custom",
        allow: { mrenclave: ["good-build-1", "good-build-2"] },
      },
    ];
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      policies,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/allowlist/);
  });

  it("rejects when required measurement is missing", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, {
      mrenclave: "aaaa",
    });
    const policies: MeasurementPolicy[] = [
      {
        platform: "custom",
        allow: { mrenclave: ["aaaa"], mrsigner: ["required-sig"] },
      },
    ];
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      policies,
    });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/missing/);
  });

  it("ignores policies for other platforms", async () => {
    const heart = makeHeart();
    const vendor = makeVendor();
    const { doc, verifier } = makeAttestation(heart, vendor, { m: "x" });
    const policies: MeasurementPolicy[] = [
      { platform: "intel-sgx", allow: { m: ["y"] } }, // irrelevant
    ];
    const r = await verifyAttestationDocument(doc, {
      verifiers: [verifier],
      policies,
    });
    expect(r.valid).toBe(true);
  });
});

describe("NoopVerifier", () => {
  it("accepts any quote in dev mode", async () => {
    const heart = makeHeart();
    const nonce = crypto.encoding.encodeBase64(crypto.random.randomBytes(16));
    const doc = createAttestationDocument({
      platform: "custom",
      quote: new Uint8Array([1, 2, 3]),
      measurements: { dev: "true" },
      heartDid: heart.did,
      heartPublicKey: heart.publicKey,
      heartSigningKey: heart.kp.secretKey,
      nonceB64: nonce,
    });
    const noop = new NoopVerifier(heart.publicKey, { dev: "true" });
    const r = await verifyAttestationDocument(doc, { verifiers: [noop] });
    expect(r.valid).toBe(true);
  });
});
