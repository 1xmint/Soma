import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";

const crypto = getCryptoProvider();
import {
  createBirthCertificate,
  createUnsignedBirthCertificate,
  createDataProvenance,
  signDataProvenance,
  verifyDataProvenance,
  verifyBirthCertificate,
  verifySourceSignature,
  verifyDataIntegrity,
  verifyBirthCertificateChain,
  birthCertificateFingerprint,
  type BirthCertificate,
  type DataSource,
} from "../../src/heart/birth-certificate.js";

describe("BirthCertificate", () => {
  function makeKeyPair() {
    return crypto.signing.generateKeyPair();
  }

  function makeDid(keyPair: { publicKey: Uint8Array }): string {
    return publicKeyToDid(keyPair.publicKey);
  }

  const apiSource: DataSource = {
    type: "api",
    identifier: "https://api.example.com/data",
    heartVerified: false,
  };

  const agentSource: DataSource = {
    type: "agent",
    identifier: "did:key:z123",
    heartVerified: true,
  };

  describe("createBirthCertificate()", () => {
    it("creates a certificate with correct fields", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate(
        "Hello world",
        apiSource,
        did,
        "session-1",
        keyPair
      );

      expect(cert.dataHash).toBeTruthy();
      expect(cert.source).toEqual(apiSource);
      expect(cert.bornAt).toBeGreaterThan(0);
      expect(cert.bornThrough).toBe(did);
      expect(cert.bornInSession).toBe("session-1");
      expect(cert.parentCertificates).toEqual([]);
      expect(cert.receiverSignature).toBeTruthy();
      expect(cert.sourceSignature).toBeNull();
      expect(cert.trustTier).toBe("single-signed");
    });

    it("creates different hashes for different data", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert1 = createBirthCertificate("data A", apiSource, did, "s1", keyPair);
      const cert2 = createBirthCertificate("data B", apiSource, did, "s1", keyPair);
      expect(cert1.dataHash).not.toBe(cert2.dataHash);
    });

    it("includes parent certificate references", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const parents = ["parent-hash-1", "parent-hash-2"];
      const cert = createBirthCertificate(
        "derived data",
        agentSource,
        did,
        "s1",
        keyPair,
        parents
      );
      expect(cert.parentCertificates).toEqual(parents);
    });
  });

  describe("verifyBirthCertificate()", () => {
    it("verifies a valid certificate", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate(
        "test data",
        apiSource,
        did,
        "session-1",
        keyPair
      );
      expect(verifyBirthCertificate(cert, keyPair.publicKey)).toBe(true);
    });

    it("rejects certificate signed with wrong key", () => {
      const keyPair1 = makeKeyPair();
      const keyPair2 = makeKeyPair();
      const did = makeDid(keyPair1);
      const cert = createBirthCertificate(
        "test data",
        apiSource,
        did,
        "session-1",
        keyPair1
      );
      expect(verifyBirthCertificate(cert, keyPair2.publicKey)).toBe(false);
    });

    it("rejects certificate with tampered data hash", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate(
        "test data",
        apiSource,
        did,
        "session-1",
        keyPair
      );
      const tampered = { ...cert, dataHash: "tampered-hash" };
      expect(verifyBirthCertificate(tampered, keyPair.publicKey)).toBe(false);
    });

    it("rejects certificate with tampered source", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate(
        "test data",
        apiSource,
        did,
        "session-1",
        keyPair
      );
      const tampered = {
        ...cert,
        source: { ...cert.source, identifier: "https://evil.com" },
      };
      expect(verifyBirthCertificate(tampered, keyPair.publicKey)).toBe(false);
    });

    it("rejects certificate with tampered session", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate(
        "test data",
        apiSource,
        did,
        "session-1",
        keyPair
      );
      const tampered = { ...cert, bornInSession: "session-fake" };
      expect(verifyBirthCertificate(tampered, keyPair.publicKey)).toBe(false);
    });

    it("rejects unsigned certificates", () => {
      const keyPair = makeKeyPair();
      const cert = createUnsignedBirthCertificate(
        "data",
        apiSource,
        "session-1"
      );
      expect(verifyBirthCertificate(cert, keyPair.publicKey)).toBe(false);
    });
  });

  describe("co-signing protocol", () => {
    it("creates and verifies data provenance", () => {
      const sourceKp = makeKeyPair();
      const sourceDid = makeDid(sourceKp);
      const receiverDid = "did:key:receiver";

      const provenance = createDataProvenance("data", sourceDid, receiverDid);
      expect(provenance.dataHash).toBeTruthy();
      expect(provenance.sourceDid).toBe(sourceDid);
      expect(provenance.receiverDid).toBe(receiverDid);

      const sig = signDataProvenance(provenance, sourceKp);
      expect(verifyDataProvenance(provenance, sig, sourceKp.publicKey)).toBe(true);
    });

    it("rejects forged data provenance", () => {
      const realKp = makeKeyPair();
      const fakeKp = makeKeyPair();
      const provenance = createDataProvenance("data", makeDid(realKp), "recv");
      const fakeSig = signDataProvenance(provenance, fakeKp);
      expect(verifyDataProvenance(provenance, fakeSig, realKp.publicKey)).toBe(false);
    });

    it("creates dual-signed certificate", () => {
      const sourceKp = makeKeyPair();
      const receiverKp = makeKeyPair();
      const sourceDid = makeDid(sourceKp);
      const receiverDid = makeDid(receiverKp);

      const provenance = createDataProvenance("data", sourceDid, receiverDid);
      const sourceSig = signDataProvenance(provenance, sourceKp);

      const cert = createBirthCertificate(
        "data",
        { type: "agent", identifier: sourceDid, heartVerified: true },
        receiverDid,
        "session-1",
        receiverKp,
        [],
        undefined,
        sourceSig
      );

      expect(cert.trustTier).toBe("dual-signed");
      expect(cert.sourceSignature).toBe(sourceSig);
    });

    it("verifies both signatures on dual-signed cert", () => {
      const sourceKp = makeKeyPair();
      const receiverKp = makeKeyPair();
      const sourceDid = makeDid(sourceKp);
      const receiverDid = makeDid(receiverKp);

      const provenance = createDataProvenance("data", sourceDid, receiverDid);
      const sourceSig = signDataProvenance(provenance, sourceKp);

      const cert = createBirthCertificate(
        "data",
        { type: "agent", identifier: sourceDid, heartVerified: true },
        receiverDid,
        "s1",
        receiverKp,
        [],
        undefined,
        sourceSig,
        provenance.timestamp // Sync timestamp with provenance
      );

      expect(verifyBirthCertificate(cert, receiverKp.publicKey)).toBe(true);
      expect(verifySourceSignature(cert, sourceKp.publicKey)).toBe(true);
    });

    it("rejects forged source co-signature", () => {
      const sourceKp = makeKeyPair();
      const fakeKp = makeKeyPair();
      const receiverKp = makeKeyPair();
      const sourceDid = makeDid(sourceKp);
      const receiverDid = makeDid(receiverKp);

      const provenance = createDataProvenance("data", sourceDid, receiverDid);
      const fakeSig = signDataProvenance(provenance, fakeKp);

      const cert = createBirthCertificate(
        "data",
        { type: "agent", identifier: sourceDid, heartVerified: true },
        receiverDid,
        "s1",
        receiverKp,
        [],
        undefined,
        fakeSig,
        provenance.timestamp
      );

      expect(verifyBirthCertificate(cert, receiverKp.publicKey)).toBe(true);
      expect(verifySourceSignature(cert, sourceKp.publicKey)).toBe(false);
    });

    it("verifySourceSignature returns false for single-signed certs", () => {
      const receiverKp = makeKeyPair();
      const cert = createBirthCertificate(
        "data",
        apiSource,
        makeDid(receiverKp),
        "s1",
        receiverKp
      );
      expect(verifySourceSignature(cert, receiverKp.publicKey)).toBe(false);
    });
  });

  describe("trust tiers", () => {
    it("dual-signed when hearted source provides co-signature", () => {
      const sourceKp = makeKeyPair();
      const receiverKp = makeKeyPair();
      const provenance = createDataProvenance("d", makeDid(sourceKp), makeDid(receiverKp));
      const sig = signDataProvenance(provenance, sourceKp);

      const cert = createBirthCertificate(
        "d",
        { type: "agent", identifier: makeDid(sourceKp), heartVerified: true },
        makeDid(receiverKp),
        "s1",
        receiverKp,
        [],
        undefined,
        sig
      );
      expect(cert.trustTier).toBe("dual-signed");
    });

    it("single-signed when source is unhearted", () => {
      const kp = makeKeyPair();
      const cert = createBirthCertificate(
        "data",
        { type: "api", identifier: "url", heartVerified: false },
        makeDid(kp),
        "s1",
        kp
      );
      expect(cert.trustTier).toBe("single-signed");
    });

    it("unsigned from createUnsignedBirthCertificate", () => {
      const cert = createUnsignedBirthCertificate(
        "data",
        { type: "api", identifier: "url", heartVerified: false },
        "s1"
      );
      expect(cert.trustTier).toBe("unsigned");
    });
  });

  describe("verifyDataIntegrity()", () => {
    it("confirms matching data", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const data = "original data content";
      const cert = createBirthCertificate(data, apiSource, did, "s1", keyPair);
      expect(verifyDataIntegrity(data, cert)).toBe(true);
    });

    it("detects tampered data", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate("original data", apiSource, did, "s1", keyPair);
      expect(verifyDataIntegrity("modified data", cert)).toBe(false);
    });

    it("detects even single-character change", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate("abcdef", apiSource, did, "s1", keyPair);
      expect(verifyDataIntegrity("abcdeg", cert)).toBe(false);
    });
  });

  describe("verifyBirthCertificateChain()", () => {
    it("verifies an empty chain", () => {
      const result = verifyBirthCertificateChain([], new Map());
      expect(result.valid).toBe(true);
      expect(result.reason).toBe("Chain intact");
    });

    it("verifies a single-certificate chain", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate("data", apiSource, did, "s1", keyPair);
      const pubKeys = new Map([[did, keyPair.publicKey]]);
      const result = verifyBirthCertificateChain([cert], pubKeys);
      expect(result.valid).toBe(true);
    });

    it("verifies a multi-heart chain", () => {
      const heart1 = makeKeyPair();
      const heart2 = makeKeyPair();
      const did1 = makeDid(heart1);
      const did2 = makeDid(heart2);

      const cert1 = createBirthCertificate(
        "raw sensor data",
        { type: "sensor", identifier: "temp-001", heartVerified: false },
        did1,
        "s1",
        heart1
      );
      const cert2 = createBirthCertificate(
        "processed data",
        { type: "agent", identifier: did1, heartVerified: true },
        did2,
        "s2",
        heart2
      );

      const pubKeys = new Map([
        [did1, heart1.publicKey],
        [did2, heart2.publicKey],
      ]);
      const result = verifyBirthCertificateChain([cert1, cert2], pubKeys);
      expect(result.valid).toBe(true);
    });

    it("rejects chain with unknown heart DID", () => {
      const keyPair = makeKeyPair();
      const did = makeDid(keyPair);
      const cert = createBirthCertificate("data", apiSource, did, "s1", keyPair);
      const result = verifyBirthCertificateChain([cert], new Map());
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(0);
      expect(result.reason).toContain("Unknown heart DID");
    });

    it("rejects chain with invalid signature", () => {
      const keyPair1 = makeKeyPair();
      const keyPair2 = makeKeyPair();
      const did1 = makeDid(keyPair1);

      const cert = createBirthCertificate("data", apiSource, did1, "s1", keyPair1);
      const pubKeys = new Map([[did1, keyPair2.publicKey]]);
      const result = verifyBirthCertificateChain([cert], pubKeys);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Invalid receiver signature");
    });

    it("rejects chain with unsigned certificate", () => {
      const cert = createUnsignedBirthCertificate("data", apiSource, "s1");
      const result = verifyBirthCertificateChain([cert], new Map());
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Unsigned");
    });

    it("accepts parent references that use the full-cert fingerprint", () => {
      const heart1 = makeKeyPair();
      const heart2 = makeKeyPair();
      const did1 = makeDid(heart1);
      const did2 = makeDid(heart2);

      const parent = createBirthCertificate(
        "raw",
        { type: "sensor", identifier: "s-1", heartVerified: false },
        did1,
        "s1",
        heart1,
      );
      const parentFp = birthCertificateFingerprint(parent);

      const child = createBirthCertificate(
        "derived",
        { type: "agent", identifier: did1, heartVerified: true },
        did2,
        "s2",
        heart2,
        [parentFp],
      );

      const pubKeys = new Map([
        [did1, heart1.publicKey],
        [did2, heart2.publicKey],
      ]);
      const result = verifyBirthCertificateChain([parent, child], pubKeys);
      expect(result.valid).toBe(true);
    });

    it("rejects parent references that use the legacy signature-only hash", () => {
      const heart1 = makeKeyPair();
      const heart2 = makeKeyPair();
      const did1 = makeDid(heart1);
      const did2 = makeDid(heart2);

      const parent = createBirthCertificate(
        "raw",
        { type: "sensor", identifier: "s-1", heartVerified: false },
        did1,
        "s1",
        heart1,
      );
      // Legacy (pre-fingerprint) reference format — sha256 of receiverSignature only.
      const legacyRef = crypto.hashing.hash(parent.receiverSignature);

      const child = createBirthCertificate(
        "derived",
        { type: "agent", identifier: did1, heartVerified: true },
        did2,
        "s2",
        heart2,
        [legacyRef],
      );

      const pubKeys = new Map([
        [did1, heart1.publicKey],
        [did2, heart2.publicKey],
      ]);
      const result = verifyBirthCertificateChain([parent, child], pubKeys);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Missing parent");
    });

    it("detects parent-cert tampering via fingerprint binding", () => {
      const heart1 = makeKeyPair();
      const heart2 = makeKeyPair();
      const did1 = makeDid(heart1);
      const did2 = makeDid(heart2);

      const parent = createBirthCertificate(
        "raw",
        { type: "sensor", identifier: "s-1", heartVerified: false },
        did1,
        "s1",
        heart1,
      );
      const parentFp = birthCertificateFingerprint(parent);

      const child = createBirthCertificate(
        "derived",
        { type: "agent", identifier: did1, heartVerified: true },
        did2,
        "s2",
        heart2,
        [parentFp],
      );

      // Tamper with a non-signed field (bornInSession). The canonical body
      // changes, so the fingerprint no longer matches the child's reference —
      // even though the (now-invalid) receiver signature is untouched.
      const tamperedParent: BirthCertificate = {
        ...parent,
        bornInSession: "s1-tampered",
      };

      const pubKeys = new Map([
        [did1, heart1.publicKey],
        [did2, heart2.publicKey],
      ]);
      const result = verifyBirthCertificateChain([tamperedParent, child], pubKeys);
      expect(result.valid).toBe(false);
      // Either the parent's own receiver signature fails first, or the child's
      // parent reference no longer resolves — both are acceptable rejections.
      expect(
        result.reason.includes("Invalid receiver signature") ||
          result.reason.includes("Missing parent"),
      ).toBe(true);
    });
  });
});
