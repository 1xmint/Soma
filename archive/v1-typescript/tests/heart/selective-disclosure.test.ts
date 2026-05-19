import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createDisclosableDocument,
  verifyDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
  type DisclosableDocument,
  type DisclosureProof,
} from "../../src/heart/selective-disclosure.js";

const crypto = getCryptoProvider();

function makeParty() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
  };
}

function issueKycDocument(
  issuer = makeParty(),
  subject = makeParty(),
  overrides: Partial<{ claims: Record<string, unknown>; expiresAt: number | null }> = {},
) {
  const claims = overrides.claims ?? {
    name: "Alice Liddell",
    dob: "1990-01-01",
    country: "US",
    tier: 3,
    kycVerified: true,
  };
  const doc = createDisclosableDocument({
    issuerDid: issuer.did,
    issuerPublicKey: issuer.publicKey,
    issuerSigningKey: issuer.kp.secretKey,
    subjectDid: subject.did,
    claims,
    expiresAt: overrides.expiresAt ?? null,
  });
  return { issuer, subject, doc };
}

describe("createDisclosableDocument", () => {
  it("issues a document with all fields committed", () => {
    const { doc } = issueKycDocument();
    expect(doc.id).toMatch(/^doc-/);
    expect(Object.keys(doc.salts)).toEqual(
      expect.arrayContaining(["name", "dob", "country", "tier", "kycVerified"]),
    );
    expect(doc.commitmentRoot).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.signature).toBeTruthy();
  });

  it("generates unique salts per field", () => {
    const { doc } = issueKycDocument();
    const salts = Object.values(doc.salts);
    const uniqueSalts = new Set(salts);
    expect(uniqueSalts.size).toBe(salts.length);
  });

  it("produces different roots for different claim sets", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const { doc: d1 } = issueKycDocument(issuer, subject, {
      claims: { tier: 2 },
    });
    const { doc: d2 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    expect(d1.commitmentRoot).not.toBe(d2.commitmentRoot);
  });

  it("produces different roots for same claims with different salts", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const { doc: d1 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    const { doc: d2 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    // Same claims, but fresh salts → different roots + different sigs.
    expect(d1.commitmentRoot).not.toBe(d2.commitmentRoot);
    expect(d1.signature).not.toBe(d2.signature);
  });

  it("rejects empty claim set", () => {
    const issuer = makeParty();
    const subject = makeParty();
    expect(() =>
      createDisclosableDocument({
        issuerDid: issuer.did,
        issuerPublicKey: issuer.publicKey,
        issuerSigningKey: issuer.kp.secretKey,
        subjectDid: subject.did,
        claims: {},
      }),
    ).toThrow(/claims/);
  });
});

describe("verifyDisclosableDocument (issuer-facing self-check)", () => {
  it("accepts a well-formed document", () => {
    const { doc } = issueKycDocument();
    expect(verifyDisclosableDocument(doc).valid).toBe(true);
  });

  it("rejects document with tampered claim value", () => {
    const { doc } = issueKycDocument();
    const tampered: DisclosableDocument = {
      ...doc,
      claims: { ...doc.claims, tier: 99 },
    };
    expect(verifyDisclosableDocument(tampered).valid).toBe(false);
  });

  it("rejects document with tampered salt", () => {
    const { doc } = issueKycDocument();
    const tampered: DisclosableDocument = {
      ...doc,
      salts: {
        ...doc.salts,
        tier: crypto.encoding.encodeBase64(crypto.random.randomBytes(32)),
      },
    };
    expect(verifyDisclosableDocument(tampered).valid).toBe(false);
  });

  it("rejects document with tampered signature", () => {
    const { doc } = issueKycDocument();
    const tampered: DisclosableDocument = {
      ...doc,
      signature: crypto.encoding.encodeBase64(crypto.random.randomBytes(64)),
    };
    expect(verifyDisclosableDocument(tampered).valid).toBe(false);
  });

  it("rejects document with DID/key mismatch", () => {
    const { doc } = issueKycDocument();
    const other = makeParty();
    const tampered: DisclosableDocument = {
      ...doc,
      issuerDid: other.did,
    };
    expect(verifyDisclosableDocument(tampered).valid).toBe(false);
  });
});

describe("createDisclosureProof + verifyDisclosureProof", () => {
  it("reveals only selected fields", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier", "kycVerified"]);
    expect(Object.keys(proof.disclosed)).toEqual(
      expect.arrayContaining(["tier", "kycVerified"]),
    );
    expect(Object.keys(proof.disclosed)).toHaveLength(2);
    expect(Object.keys(proof.undisclosedCommitments)).toHaveLength(3);
    expect("name" in proof.disclosed).toBe(false);
    expect("dob" in proof.disclosed).toBe(false);
  });

  it("verifier accepts partial disclosure", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier", "kycVerified"]);
    const r = verifyDisclosureProof(proof);
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(r.disclosed["tier"]).toBe(3);
      expect(r.disclosed["kycVerified"]).toBe(true);
      expect("name" in r.disclosed).toBe(false);
    }
  });

  it("verifier accepts full disclosure", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, Object.keys(doc.claims));
    const r = verifyDisclosureProof(proof);
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(Object.keys(r.disclosed)).toHaveLength(5);
    }
  });

  it("verifier accepts empty disclosure (just issuer signature + subject)", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, []);
    const r = verifyDisclosureProof(proof);
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(Object.keys(r.disclosed)).toHaveLength(0);
    }
  });

  it("throws when holder asks to reveal a field that doesn't exist", () => {
    const { doc } = issueKycDocument();
    expect(() => createDisclosureProof(doc, ["nonexistent"])).toThrow();
  });

  it("rejects proof with forged disclosed value (different from original)", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    const forged: DisclosureProof = {
      ...proof,
      disclosed: {
        tier: { value: 99, salt: proof.disclosed["tier"]!.salt },
      },
    };
    const r = verifyDisclosureProof(forged);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/commitment root/);
  });

  it("rejects proof with swapped field name", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    // Rename the field — hash prefix includes field name, so this breaks.
    const { tier, ...rest } = proof.disclosed;
    const forged: DisclosureProof = {
      ...proof,
      disclosed: { ...rest, level: tier! },
    };
    const r = verifyDisclosureProof(forged);
    expect(r.valid).toBe(false);
  });

  it("rejects proof with tampered issuer signature", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    const forged: DisclosureProof = {
      ...proof,
      signature: crypto.encoding.encodeBase64(crypto.random.randomBytes(64)),
    };
    expect(verifyDisclosureProof(forged).valid).toBe(false);
  });

  it("rejects proof with DID/key mismatch", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    const other = makeParty();
    const forged: DisclosureProof = { ...proof, issuerDid: other.did };
    const r = verifyDisclosureProof(forged);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/DID/);
  });

  it("rejects proof where same field is both disclosed and undisclosed", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    const forged: DisclosureProof = {
      ...proof,
      undisclosedCommitments: {
        ...proof.undisclosedCommitments,
        tier: "dup",
      },
    };
    const r = verifyDisclosureProof(forged);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/both/);
  });
});

describe("expiry and required fields", () => {
  it("rejects expired documents", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const past = Date.now() - 1000;
    const { doc } = issueKycDocument(issuer, subject, { expiresAt: past });
    const proof = createDisclosureProof(doc, ["tier"]);
    const r = verifyDisclosureProof(proof);
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/expired/);
  });

  it("accepts non-expired documents", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const future = Date.now() + 3600_000;
    const { doc } = issueKycDocument(issuer, subject, { expiresAt: future });
    const proof = createDisclosureProof(doc, ["tier"]);
    expect(verifyDisclosureProof(proof).valid).toBe(true);
  });

  it("enforces requiredFields on verifier side", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier"]);
    const r = verifyDisclosureProof(proof, { requiredFields: ["tier", "kycVerified"] });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toMatch(/required field/);
  });

  it("accepts when required fields are disclosed", () => {
    const { doc } = issueKycDocument();
    const proof = createDisclosureProof(doc, ["tier", "kycVerified"]);
    const r = verifyDisclosureProof(proof, {
      requiredFields: ["tier", "kycVerified"],
    });
    expect(r.valid).toBe(true);
  });
});

describe("unlinkability (salt independence)", () => {
  it("same claim value produces different commitments in different documents", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const { doc: d1 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    const { doc: d2 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    // Same field + same value, but different salts → different commitments.
    const proof1 = createDisclosureProof(d1, []);
    const proof2 = createDisclosureProof(d2, []);
    const c1 = proof1.undisclosedCommitments["tier"];
    const c2 = proof2.undisclosedCommitments["tier"];
    expect(c1).not.toBe(c2);
  });

  it("commitment hash reveals nothing about the value", () => {
    // Smoke test: two different values produce unrelated hashes that
    // can't be distinguished without the salts.
    const issuer = makeParty();
    const subject = makeParty();
    const { doc: d1 } = issueKycDocument(issuer, subject, {
      claims: { tier: 1 },
    });
    const { doc: d2 } = issueKycDocument(issuer, subject, {
      claims: { tier: 3 },
    });
    const proof1 = createDisclosureProof(d1, []);
    const proof2 = createDisclosureProof(d2, []);
    // Hashes look like random 64-char hex strings, no visible pattern.
    expect(proof1.undisclosedCommitments["tier"]).toMatch(/^[0-9a-f]{64}$/);
    expect(proof2.undisclosedCommitments["tier"]).toMatch(/^[0-9a-f]{64}$/);
    expect(proof1.undisclosedCommitments["tier"]).not.toBe(
      proof2.undisclosedCommitments["tier"],
    );
  });
});

describe("complex claim types", () => {
  it("handles numbers, booleans, strings, objects, arrays", () => {
    const issuer = makeParty();
    const subject = makeParty();
    const { doc } = issueKycDocument(issuer, subject, {
      claims: {
        age: 34,
        adult: true,
        name: "Alice",
        address: { city: "NYC", zip: "10001" },
        hobbies: ["chess", "climbing"],
      },
    });
    expect(verifyDisclosableDocument(doc).valid).toBe(true);
    const proof = createDisclosureProof(doc, ["adult", "age"]);
    const r = verifyDisclosureProof(proof);
    expect(r.valid).toBe(true);
    if (r.valid) {
      expect(r.disclosed["age"]).toBe(34);
      expect(r.disclosed["adult"]).toBe(true);
    }
  });
});
