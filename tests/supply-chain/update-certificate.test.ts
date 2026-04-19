import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  createUpdateCertificate,
  addAuthorization,
  verifyUpdateCertificate,
  computeUpdateCertificateSigningInput,
  computeUpdateCertificateHash,
  verifyPackageProvenance,
  type UpdateCertificate,
  type PackageProvenance,
} from "../../src/supply-chain/update-certificate.js";

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

function makeCert(opts?: {
  threshold?: number;
  ceremonyTier?: 'L0' | 'L1' | 'L2' | 'L3';
  expiresAt?: number | null;
}) {
  const maintainer = makeKeyPair();
  const cert = createUpdateCertificate({
    package: "soma-heart",
    targetVersion: "0.6.0",
    tarballSha256: hex64("a"),
    gitCommit: hex64("1"),
    releaseLogSequence: 0,
    releaseLogEntryHash: hex64("b"),
    threshold: opts?.threshold ?? 1,
    ceremonyTier: opts?.ceremonyTier ?? "L1",
    signingKey: maintainer.secretKey,
    publicKey: maintainer.publicKey,
    expiresAt: opts?.expiresAt,
  });
  return { cert, maintainer, maintainerDid: makeDid(maintainer) };
}

// ─── Creation ────────────────────────────────────────────────────────────────

describe("createUpdateCertificate", () => {
  it("creates a certificate with one authorization", () => {
    const { cert, maintainerDid } = makeCert();
    expect(cert.version).toBe("soma/update-certificate/v1");
    expect(cert.package).toBe("soma-heart");
    expect(cert.targetVersion).toBe("0.6.0");
    expect(cert.tarballSha256).toBe(hex64("a"));
    expect(cert.gitCommit).toBe(hex64("1"));
    expect(cert.releaseLogSequence).toBe(0);
    expect(cert.threshold).toBe(1);
    expect(cert.ceremonyTier).toBe("L1");
    expect(cert.authorizations).toHaveLength(1);
    expect(cert.authorizations[0].authorizerDid).toBe(maintainerDid);
    expect(cert.authorizations[0].role).toBe("maintainer");
    expect(cert.authorizations[0].authorizerCeremonyTier).toBe("L1");
    expect(cert.authorizations[0].delegationHash).toBeNull();
  });

  it("rejects invalid tarball hash", () => {
    const kp = makeKeyPair();
    expect(() =>
      createUpdateCertificate({
        package: "soma-heart",
        targetVersion: "0.6.0",
        tarballSha256: "not-a-sha256",
        gitCommit: hex64("1"),
        releaseLogSequence: 0,
        releaseLogEntryHash: hex64("b"),
        threshold: 1,
        ceremonyTier: "L1",
        signingKey: kp.secretKey,
        publicKey: kp.publicKey,
      }),
    ).toThrow("tarballSha256");
  });

  it("rejects threshold < 1", () => {
    const kp = makeKeyPair();
    expect(() =>
      createUpdateCertificate({
        package: "soma-heart",
        targetVersion: "0.6.0",
        tarballSha256: hex64("a"),
        gitCommit: hex64("1"),
        releaseLogSequence: 0,
        releaseLogEntryHash: hex64("b"),
        threshold: 0,
        ceremonyTier: "L1",
        signingKey: kp.secretKey,
        publicKey: kp.publicKey,
      }),
    ).toThrow("threshold");
  });

  it("accepts custom role and delegationHash", () => {
    const kp = makeKeyPair();
    const cert = createUpdateCertificate({
      package: "soma-heart",
      targetVersion: "0.6.0",
      tarballSha256: hex64("a"),
      gitCommit: hex64("1"),
      releaseLogSequence: 0,
      releaseLogEntryHash: hex64("b"),
      threshold: 1,
      ceremonyTier: "L2",
      signingKey: kp.secretKey,
      publicKey: kp.publicKey,
      role: "council-member",
      delegationHash: "delegation-hash-123",
    });
    expect(cert.authorizations[0].role).toBe("council-member");
    expect(cert.authorizations[0].delegationHash).toBe("delegation-hash-123");
  });
});

// ─── Co-signing ─────────────────────────────────────────────────────────────

describe("addAuthorization", () => {
  it("adds a co-signer with consumer-heart role", () => {
    const { cert } = makeCert({ threshold: 2 });
    const cosigner = makeKeyPair();
    const updated = addAuthorization(cert, cosigner.secretKey, cosigner.publicKey);

    expect(updated.authorizations).toHaveLength(2);
    expect(updated.authorizations[1].authorizerDid).toBe(makeDid(cosigner));
    expect(updated.authorizations[1].role).toBe("consumer-heart");
    expect(updated.authorizations[1].authorizerCeremonyTier).toBeNull();
    expect(updated.authorizations[1].delegationHash).toBeNull();
  });

  it("adds a co-signer with custom role and ceremony tier", () => {
    const { cert } = makeCert({ threshold: 2 });
    const cosigner = makeKeyPair();
    const updated = addAuthorization(cert, cosigner.secretKey, cosigner.publicKey, {
      role: "council-member",
      ceremonyTier: "L2",
      delegationHash: "some-hash",
    });

    expect(updated.authorizations[1].role).toBe("council-member");
    expect(updated.authorizations[1].authorizerCeremonyTier).toBe("L2");
    expect(updated.authorizations[1].delegationHash).toBe("some-hash");
  });

  it("rejects duplicate authorizer", () => {
    const { cert, maintainer } = makeCert();
    expect(() =>
      addAuthorization(cert, maintainer.secretKey, maintainer.publicKey),
    ).toThrow("already authorized");
  });

  it("does not mutate the original certificate", () => {
    const { cert } = makeCert({ threshold: 2 });
    const cosigner = makeKeyPair();
    const updated = addAuthorization(cert, cosigner.secretKey, cosigner.publicKey);
    expect(cert.authorizations).toHaveLength(1);
    expect(updated.authorizations).toHaveLength(2);
  });
});

// ─── Signing input ──────────────────────────────────────────────────────────

describe("computeUpdateCertificateSigningInput", () => {
  it("produces deterministic output", () => {
    const { cert } = makeCert();
    const { authorizations: _, ...body } = cert;
    const a = computeUpdateCertificateSigningInput(body);
    const b = computeUpdateCertificateSigningInput(body);
    expect(a).toEqual(b);
  });

  it("differs for different certificates", () => {
    const { cert: cert1 } = makeCert();
    const { cert: cert2 } = makeCert();
    const { authorizations: _1, ...body1 } = cert1;
    const { authorizations: _2, ...body2 } = cert2;
    const a = computeUpdateCertificateSigningInput(body1);
    const b = computeUpdateCertificateSigningInput(body2);
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });
});

// ─── Certificate hash ───────────────────────────────────────────────────────

describe("computeUpdateCertificateHash", () => {
  it("produces deterministic hash", () => {
    const { cert } = makeCert();
    const a = computeUpdateCertificateHash(cert);
    const b = computeUpdateCertificateHash(cert);
    expect(a).toBe(b);
  });

  it("changes when authorization is added", () => {
    const { cert } = makeCert({ threshold: 2 });
    const hashBefore = computeUpdateCertificateHash(cert);
    const cosigner = makeKeyPair();
    const updated = addAuthorization(cert, cosigner.secretKey, cosigner.publicKey);
    const hashAfter = computeUpdateCertificateHash(updated);
    expect(hashBefore).not.toBe(hashAfter);
  });
});

// ─── Verification ───────────────────────────────────────────────────────────

describe("verifyUpdateCertificate", () => {
  it("accepts a valid single-authorization certificate", () => {
    const { cert } = makeCert();
    const result = verifyUpdateCertificate(cert, Date.now());
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.ceremonyTier).toBe("L1");
  });

  it("accepts a valid multi-authorization certificate", () => {
    const { cert } = makeCert({ threshold: 2 });
    const cosigner = makeKeyPair();
    const updated = addAuthorization(cert, cosigner.secretKey, cosigner.publicKey);
    const result = verifyUpdateCertificate(updated, Date.now());
    expect(result.valid).toBe(true);
  });

  it("rejects wrong version tag", () => {
    const { cert } = makeCert();
    const tampered = { ...cert, version: "soma/wrong/v1" as any };
    const result = verifyUpdateCertificate(tampered, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("unknown version");
  });

  it("rejects tampered certificate body", () => {
    const { cert } = makeCert();
    const tampered = { ...cert, targetVersion: "999.0.0" };
    const result = verifyUpdateCertificate(tampered, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("invalid signature");
  });

  it("rejects tampered tarball hash", () => {
    const { cert } = makeCert();
    const tampered = { ...cert, tarballSha256: hex64("x") };
    const result = verifyUpdateCertificate(tampered, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("invalid signature");
  });

  it("rejects when threshold not met", () => {
    const { cert } = makeCert({ threshold: 2 });
    const result = verifyUpdateCertificate(cert, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("threshold not met");
  });

  it("rejects expired certificate", () => {
    const { cert } = makeCert({ expiresAt: Date.now() + 60_000 });
    const result = verifyUpdateCertificate(cert, Date.now() + 120_000);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("expired");
  });

  it("rejects ceremony tier below minimum", () => {
    const { cert } = makeCert({ ceremonyTier: "L0" });
    const result = verifyUpdateCertificate(cert, Date.now(), {
      minCeremonyTier: "L2",
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("ceremony tier");
  });

  it("accepts ceremony tier at minimum", () => {
    const { cert } = makeCert({ ceremonyTier: "L2" });
    const result = verifyUpdateCertificate(cert, Date.now(), {
      minCeremonyTier: "L2",
    });
    expect(result.valid).toBe(true);
  });

  it("rejects DID mismatch (tampered pubkey)", () => {
    const { cert } = makeCert();
    const fakeKey = makeKeyPair();
    const tampered: UpdateCertificate = {
      ...cert,
      authorizations: [
        {
          ...cert.authorizations[0],
          authorizerPublicKey: crypto.encoding.encodeBase64(fakeKey.publicKey),
        },
      ],
    };
    const result = verifyUpdateCertificate(tampered, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("DID does not match");
  });

  it("rejects duplicate authorizer DIDs", () => {
    const { cert, maintainer } = makeCert({ threshold: 2 });
    const tampered: UpdateCertificate = {
      ...cert,
      authorizations: [cert.authorizations[0], cert.authorizations[0]],
    };
    const result = verifyUpdateCertificate(tampered, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("duplicate");
  });

  it("uses trustedDids to filter valid authorizers", () => {
    const { cert } = makeCert({ threshold: 1 });
    const untrustedDid = "did:key:zunknown";
    const result = verifyUpdateCertificate(cert, Date.now(), {
      trustedDids: [untrustedDid],
    });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toContain("threshold not met");
  });

  it("accepts when trustedDids includes the authorizer", () => {
    const { cert, maintainerDid } = makeCert({ threshold: 1 });
    const result = verifyUpdateCertificate(cert, Date.now(), {
      trustedDids: [maintainerDid],
    });
    expect(result.valid).toBe(true);
  });
});

// ─── Full round-trip: create → sign → co-sign → verify ─────────────────────

describe("round-trip: create → co-sign → verify", () => {
  it("full 2-of-2 round-trip succeeds", () => {
    const maintainer = makeKeyPair();
    const consumer = makeKeyPair();

    const cert = createUpdateCertificate({
      package: "soma-heart",
      targetVersion: "0.7.0",
      tarballSha256: hex64("c"),
      gitCommit: hex64("3"),
      releaseLogSequence: 1,
      releaseLogEntryHash: hex64("d"),
      threshold: 2,
      ceremonyTier: "L2",
      signingKey: maintainer.secretKey,
      publicKey: maintainer.publicKey,
      delegationHash: "delegation-abc",
    });

    const cosigned = addAuthorization(
      cert,
      consumer.secretKey,
      consumer.publicKey,
      { role: "consumer-heart" },
    );

    expect(cosigned.authorizations).toHaveLength(2);

    const result = verifyUpdateCertificate(cosigned, Date.now());
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.ceremonyTier).toBe("L2");
  });

  it("3-of-5 round-trip with threshold met", () => {
    const signers = Array.from({ length: 5 }, () => makeKeyPair());

    let cert = createUpdateCertificate({
      package: "soma-heart",
      targetVersion: "1.0.0",
      tarballSha256: hex64("e"),
      gitCommit: hex64("5"),
      releaseLogSequence: 2,
      releaseLogEntryHash: hex64("f"),
      threshold: 3,
      ceremonyTier: "L3",
      signingKey: signers[0].secretKey,
      publicKey: signers[0].publicKey,
    });

    cert = addAuthorization(cert, signers[1].secretKey, signers[1].publicKey, {
      role: "council-member",
    });
    cert = addAuthorization(cert, signers[2].secretKey, signers[2].publicKey, {
      role: "council-member",
    });

    const result = verifyUpdateCertificate(cert, Date.now());
    expect(result.valid).toBe(true);
  });
});

// ─── verifyPackageProvenance ────────────────────────────────────────────────

describe("verifyPackageProvenance", () => {
  function makeProvenanceScenario() {
    const maintainer = makeKeyPair();
    const consumer = makeKeyPair();
    const maintainerDid = makeDid(maintainer);
    const consumerDid = makeDid(consumer);

    const cert = createUpdateCertificate({
      package: "soma-heart",
      targetVersion: "0.6.0",
      tarballSha256: hex64("a"),
      gitCommit: hex64("1"),
      releaseLogSequence: 0,
      releaseLogEntryHash: hex64("b"),
      threshold: 2,
      ceremonyTier: "L1",
      signingKey: maintainer.secretKey,
      publicKey: maintainer.publicKey,
    });
    const cosigned = addAuthorization(cert, consumer.secretKey, consumer.publicKey);
    const certHash = computeUpdateCertificateHash(cosigned);

    const provenance: PackageProvenance = {
      package: "soma-heart",
      version: "0.6.0",
      tarballSha256: hex64("a"),
      releaseLogSequence: 0,
      updateCertificateHash: certHash,
      ceremonyTier: "L1",
    };

    return {
      cert: cosigned,
      provenance,
      maintainerDid,
      consumerDid,
    };
  }

  it("returns official: true for valid provenance", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();

    const result = verifyPackageProvenance({
      provenance,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });

    expect(result.official).toBe(true);
    if (result.official) expect(result.ceremonyTier).toBe("L1");
  });

  it("rejects absent provenance", () => {
    const { cert, maintainerDid, consumerDid } = makeProvenanceScenario();
    const result = verifyPackageProvenance({
      provenance: null,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
    if (!result.official) expect(result.reason).toContain("no provenance");
  });

  it("rejects absent update certificate", () => {
    const { provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const result = verifyPackageProvenance({
      provenance,
      updateCertificate: null,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("no update certificate");
  });

  it("rejects forged certificate hash", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const forgedProvenance = { ...provenance, updateCertificateHash: hex64("z") };
    const result = verifyPackageProvenance({
      provenance: forgedProvenance,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("certificate hash mismatch");
  });

  it("rejects package name mismatch", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const wrong = { ...provenance, package: "soma-evil" };
    const result = verifyPackageProvenance({
      provenance: wrong,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("package name mismatch");
  });

  it("rejects version mismatch", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const wrong = { ...provenance, version: "99.0.0" };
    const result = verifyPackageProvenance({
      provenance: wrong,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
  });

  it("rejects tarball hash mismatch", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const wrong = { ...provenance, tarballSha256: hex64("z") };
    const result = verifyPackageProvenance({
      provenance: wrong,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
  });

  it("rejects when no trusted maintainer among authorizers", () => {
    const { cert, provenance, consumerDid } = makeProvenanceScenario();
    const result = verifyPackageProvenance({
      provenance,
      updateCertificate: cert,
      trustedMaintainers: ["did:key:zunknown"],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("no trusted maintainer");
  });

  it("rejects when no trusted consumer heart among authorizers", () => {
    const { cert, provenance, maintainerDid } = makeProvenanceScenario();
    const result = verifyPackageProvenance({
      provenance,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: ["did:key:zunknown"],
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("no trusted consumer heart");
  });

  it("rejects ceremony tier mismatch between provenance and cert", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const wrong = { ...provenance, ceremonyTier: "L3" as const };
    const result = verifyPackageProvenance({
      provenance: wrong,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
    });
    expect(result.official).toBe(false);
  });

  it("rejects when minCeremonyTier not met", () => {
    const { cert, provenance, maintainerDid, consumerDid } =
      makeProvenanceScenario();
    const result = verifyPackageProvenance({
      provenance,
      updateCertificate: cert,
      trustedMaintainers: [maintainerDid],
      trustedConsumerHearts: [consumerDid],
      minCeremonyTier: "L3",
    });
    expect(result.official).toBe(false);
    if (!result.official)
      expect(result.reason).toContain("certificate invalid");
  });
});
