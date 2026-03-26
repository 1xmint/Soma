import { describe, it, expect } from "vitest";
import nacl from "tweetnacl";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createBirthCertificate,
  verifyBirthCertificate,
  verifyDataIntegrity,
  verifyBirthCertificateChain,
  type DataSource,
} from "../../src/heart/birth-certificate.js";

describe("BirthCertificate", () => {
  function makeKeyPair() {
    return nacl.sign.keyPair();
  }

  function makeDid(keyPair: nacl.SignKeyPair): string {
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
      expect(cert.signature).toBeTruthy();
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
      // Verify with wrong public key
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
      const cert = createBirthCertificate(
        "original data",
        apiSource,
        did,
        "s1",
        keyPair
      );
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
      const cert = createBirthCertificate(
        "data",
        apiSource,
        did,
        "s1",
        keyPair
      );

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

      // No parent reference needed for second cert in this test
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
      const cert = createBirthCertificate(
        "data",
        apiSource,
        did,
        "s1",
        keyPair
      );

      // Empty pub key map — DID is unknown
      const result = verifyBirthCertificateChain([cert], new Map());
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(0);
      expect(result.reason).toContain("Unknown heart DID");
    });

    it("rejects chain with invalid signature", () => {
      const keyPair1 = makeKeyPair();
      const keyPair2 = makeKeyPair();
      const did1 = makeDid(keyPair1);

      const cert = createBirthCertificate(
        "data",
        apiSource,
        did1,
        "s1",
        keyPair1
      );

      // Map DID to wrong public key
      const pubKeys = new Map([[did1, keyPair2.publicKey]]);
      const result = verifyBirthCertificateChain([cert], pubKeys);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Invalid signature");
    });
  });
});
