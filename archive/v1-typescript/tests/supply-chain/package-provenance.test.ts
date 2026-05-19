import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createBirthCertificate,
  verifyBirthCertificate,
  birthCertificateFingerprint,
  type DataSource,
} from "../../src/heart/birth-certificate.js";
import type { PackageProvenance } from "../../src/supply-chain/update-certificate.js";
import {
  validateProfile,
  validateClaimKind,
} from "../../src/heart/certificate/vocabulary.js";
import type { HeartbeatEventType } from "../../src/heart/heartbeat.js";

const crypto = getCryptoProvider();

function makeKeyPair() {
  return crypto.signing.generateKeyPair();
}

function makeDid(kp: { publicKey: Uint8Array }): string {
  return publicKeyToDid(kp.publicKey);
}

function hex64(c: string): string {
  return c.repeat(64).toLowerCase();
}

const apiSource: DataSource = {
  type: "api",
  identifier: "https://api.example.com",
  heartVerified: false,
};

const sampleProvenance: PackageProvenance = {
  package: "soma-heart",
  version: "0.6.0",
  tarballSha256: hex64("a"),
  releaseLogSequence: 0,
  updateCertificateHash: hex64("b"),
  ceremonyTier: "L1",
};

// ─── BirthCertificate packageProvenance ─────────────────────────────────────

describe("BirthCertificate with packageProvenance", () => {
  it("creates a certificate with packageProvenance", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      undefined,
      sampleProvenance,
    );
    expect(cert.packageProvenance).toEqual(sampleProvenance);
  });

  it("verifies a certificate with packageProvenance", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      undefined,
      sampleProvenance,
    );
    expect(verifyBirthCertificate(cert, kp.publicKey)).toBe(true);
  });

  it("rejects verification if packageProvenance was tampered", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      undefined,
      sampleProvenance,
    );
    const tampered = {
      ...cert,
      packageProvenance: { ...sampleProvenance, version: "999.0.0" },
    };
    expect(verifyBirthCertificate(tampered, kp.publicKey)).toBe(false);
  });

  it("rejects verification if packageProvenance was stripped from a cert that had it", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      undefined,
      sampleProvenance,
    );
    const stripped = { ...cert };
    delete stripped.packageProvenance;
    expect(verifyBirthCertificate(stripped, kp.publicKey)).toBe(false);
  });

  it("canonicalizes deterministically with packageProvenance", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const bornAt = 1700000000000;

    const cert1 = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      bornAt,
      sampleProvenance,
    );
    const cert2 = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      bornAt,
      sampleProvenance,
    );

    expect(cert1.receiverSignature).toBe(cert2.receiverSignature);
    expect(birthCertificateFingerprint(cert1)).toBe(
      birthCertificateFingerprint(cert2),
    );
  });

  it("produces different canonical form with vs without packageProvenance", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const bornAt = 1700000000000;

    const certWith = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      bornAt,
      sampleProvenance,
    );
    const certWithout = createBirthCertificate(
      "data",
      apiSource,
      did,
      "session-1",
      kp,
      [],
      undefined,
      null,
      bornAt,
    );

    expect(certWith.receiverSignature).not.toBe(certWithout.receiverSignature);
  });
});

// ─── Backward compatibility ─────────────────────────────────────────────────

describe("BirthCertificate backward compatibility (no packageProvenance)", () => {
  it("certificate without packageProvenance verifies as before", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate(
      "test data",
      apiSource,
      did,
      "session-1",
      kp,
    );
    expect(cert.packageProvenance).toBeUndefined();
    expect(verifyBirthCertificate(cert, kp.publicKey)).toBe(true);
  });

  it("fingerprint without packageProvenance is stable", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const bornAt = 1700000000000;

    const cert1 = createBirthCertificate(
      "data",
      apiSource,
      did,
      "s1",
      kp,
      [],
      undefined,
      null,
      bornAt,
    );
    const cert2 = createBirthCertificate(
      "data",
      apiSource,
      did,
      "s1",
      kp,
      [],
      undefined,
      null,
      bornAt,
    );

    expect(birthCertificateFingerprint(cert1)).toBe(
      birthCertificateFingerprint(cert2),
    );
  });

  it("cert without packageProvenance has no packageProvenance field", () => {
    const kp = makeKeyPair();
    const did = makeDid(kp);
    const cert = createBirthCertificate("data", apiSource, did, "s1", kp);
    expect("packageProvenance" in cert).toBe(false);
  });
});

// ─── Vocabulary validators ──────────────────────────────────────────────────

describe("vocabulary — update-certificate profile", () => {
  it("accepts 'update-certificate' profile", () => {
    const result = validateProfile("update-certificate");
    expect(result.valid).toBe(true);
    expect(result.disposition).toBe("accepted");
  });
});

describe("vocabulary — package_provenance claim", () => {
  it("accepts 'package_provenance' claim kind", () => {
    const result = validateClaimKind("package_provenance");
    expect(result.valid).toBe(true);
    expect(result.disposition).toBe("accepted");
  });
});

// ─── Heartbeat event type ───────────────────────────────────────────────────

describe("heartbeat — self_verification event type", () => {
  it("self_verification is a valid HeartbeatEventType", () => {
    const eventType: HeartbeatEventType = "self_verification";
    expect(eventType).toBe("self_verification");
  });
});
