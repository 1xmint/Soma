import { describe, it, expect } from "vitest";
import { getCryptoProvider } from "../../src/core/crypto-provider.js";
import { publicKeyToDid } from "../../src/core/genome.js";
import {
  ReleaseLog,
  verifyInstalledPackage,
  detectReleaseFork,
  type ReleaseEntry,
} from "../../src/supply-chain/release-log.js";

const crypto = getCryptoProvider();

function makeMaintainer() {
  const kp = crypto.signing.generateKeyPair();
  return {
    kp,
    did: publicKeyToDid(kp.publicKey),
  };
}

// 64 lowercase hex chars = valid SHA-256
function hex64(c: string): string {
  return c.repeat(64).toLowerCase();
}

function makeLog() {
  return new ReleaseLog({ package: "soma-heart" });
}

function append(
  log: ReleaseLog,
  maintainer: ReturnType<typeof makeMaintainer>,
  version: string,
  tarball: string,
  gitCommit: string,
) {
  return log.append({
    version,
    tarballSha256: tarball,
    gitCommit,
    maintainerSigningKey: maintainer.kp.secretKey,
    maintainerPublicKey: maintainer.kp.publicKey,
  });
}

describe("ReleaseLog — append + chain integrity", () => {
  it("appends releases in sequence", () => {
    const log = makeLog();
    const m = makeMaintainer();
    const e1 = append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const e2 = append(log, m, "0.1.1", hex64("b"), hex64("2"));
    expect(e1.sequence).toBe(0);
    expect(e2.sequence).toBe(1);
    expect(log.length).toBe(2);
  });

  it("chains entries via previousHash", () => {
    const log = makeLog();
    const m = makeMaintainer();
    const e1 = append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const e2 = append(log, m, "0.1.1", hex64("b"), hex64("2"));
    expect(e1.previousHash).toBe(log.genesisHash);
    expect(e2.previousHash).toBe(e1.hash);
  });

  it("genesis hash binds package name", () => {
    const a = new ReleaseLog({ package: "soma-heart" });
    const b = new ReleaseLog({ package: "soma-sense" });
    expect(a.genesisHash).not.toBe(b.genesisHash);
  });

  it("verify() passes on untouched log", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    append(log, m, "0.1.1", hex64("b"), hex64("2"));
    append(log, m, "0.2.0", hex64("c"), hex64("3"));
    expect(log.verify().valid).toBe(true);
  });

  it("rejects duplicate version", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    expect(() => append(log, m, "0.1.0", hex64("b"), hex64("2"))).toThrow(
      /already released/,
    );
  });

  it("rejects malformed tarball hash", () => {
    const log = makeLog();
    const m = makeMaintainer();
    expect(() =>
      log.append({
        version: "0.1.0",
        tarballSha256: "not-a-hash",
        gitCommit: hex64("1"),
        maintainerSigningKey: m.kp.secretKey,
        maintainerPublicKey: m.kp.publicKey,
      }),
    ).toThrow(/tarballSha256/);
  });

  it("rejects empty version", () => {
    const log = makeLog();
    const m = makeMaintainer();
    expect(() =>
      log.append({
        version: "",
        tarballSha256: hex64("a"),
        gitCommit: hex64("1"),
        maintainerSigningKey: m.kp.secretKey,
        maintainerPublicKey: m.kp.publicKey,
      }),
    ).toThrow(/version/);
  });

  it("normalizes hashes to lowercase", () => {
    const log = makeLog();
    const m = makeMaintainer();
    // ReleaseLog stores .toLowerCase() so regex still validates on input.
    // Provide lowercase here; sanity check normalization downstream.
    const e = log.append({
      version: "0.1.0",
      tarballSha256: hex64("a"),
      gitCommit: hex64("F"), // uppercase — doesn't match lowercase regex!
      maintainerSigningKey: m.kp.secretKey,
      maintainerPublicKey: m.kp.publicKey,
    });
    // gitCommit has no regex (just required string) so uppercase is ok;
    // it's normalized to lowercase inside the payload.
    expect(e.gitCommit).toBe(hex64("F").toLowerCase());
  });

  it("getByVersion returns matching entry", () => {
    const log = makeLog();
    const m = makeMaintainer();
    const e1 = append(log, m, "0.1.0", hex64("a"), hex64("1"));
    append(log, m, "0.2.0", hex64("b"), hex64("2"));
    expect(log.getByVersion("0.1.0")).toEqual(e1);
    expect(log.getByVersion("99.0.0")).toBeNull();
  });
});

describe("ReleaseLog — tamper detection", () => {
  function threeReleases() {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    append(log, m, "0.1.1", hex64("b"), hex64("2"));
    append(log, m, "0.2.0", hex64("c"), hex64("3"));
    return { log, m };
  }

  it("detects tampered tarball hash", () => {
    const { log } = threeReleases();
    const entries: ReleaseEntry[] = [...log.getEntries()].map((e, i) =>
      i === 1 ? { ...e, tarballSha256: hex64("f") } : e,
    );
    const check = ReleaseLog.verifyChain(entries, "soma-heart");
    expect(check.valid).toBe(false);
  });

  it("detects tampered git commit", () => {
    const { log } = threeReleases();
    const entries: ReleaseEntry[] = [...log.getEntries()].map((e, i) =>
      i === 0 ? { ...e, gitCommit: hex64("f") } : e,
    );
    const check = ReleaseLog.verifyChain(entries, "soma-heart");
    expect(check.valid).toBe(false);
  });

  it("detects dropped entry", () => {
    const { log } = threeReleases();
    const entries = [...log.getEntries()];
    entries.splice(1, 1);
    const check = ReleaseLog.verifyChain(entries, "soma-heart");
    expect(check.valid).toBe(false);
  });

  it("detects reordered entries", () => {
    const { log } = threeReleases();
    const entries = [...log.getEntries()];
    [entries[0], entries[2]] = [entries[2], entries[0]];
    const check = ReleaseLog.verifyChain(entries, "soma-heart");
    expect(check.valid).toBe(false);
  });

  it("detects forged signature", () => {
    const { log } = threeReleases();
    const entries = [...log.getEntries()];
    const bad = entries[0].signature.replace(/^./, (c) =>
      c === "A" ? "B" : "A",
    );
    const tampered: ReleaseEntry[] = [
      { ...entries[0], signature: bad },
      ...entries.slice(1),
    ];
    const check = ReleaseLog.verifyChain(tampered, "soma-heart");
    expect(check.valid).toBe(false);
  });

  it("detects wrong package", () => {
    const { log } = threeReleases();
    const check = ReleaseLog.verifyChain([...log.getEntries()], "soma-sense");
    expect(check.valid).toBe(false);
  });

  it("detects maintainerDid/publicKey mismatch", () => {
    const { log } = threeReleases();
    const other = makeMaintainer();
    const entries = [...log.getEntries()];
    const tampered: ReleaseEntry[] = [
      {
        ...entries[0],
        maintainerPublicKey: crypto.encoding.encodeBase64(other.kp.publicKey),
      },
      ...entries.slice(1),
    ];
    const check = ReleaseLog.verifyChain(tampered, "soma-heart");
    expect(check.valid).toBe(false);
  });
});

describe("ReleaseLog — signed heads", () => {
  it("maintainer signs head, verifier verifies", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    append(log, m, "0.1.1", hex64("b"), hex64("2"));
    const head = log.signHead(m.kp.secretKey, m.kp.publicKey);
    expect(head.sequence).toBe(1);
    expect(head.hash).toBe(log.head);
    expect(head.maintainerDid).toBe(m.did);
    expect(ReleaseLog.verifyHead(head).valid).toBe(true);
  });

  it("detects forged head signature", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const head = log.signHead(m.kp.secretKey, m.kp.publicKey);
    const tampered = { ...head, hash: hex64("f") };
    expect(ReleaseLog.verifyHead(tampered).valid).toBe(false);
  });

  it("empty log produces head at sequence=-1", () => {
    const log = makeLog();
    const m = makeMaintainer();
    const head = log.signHead(m.kp.secretKey, m.kp.publicKey);
    expect(head.sequence).toBe(-1);
    expect(head.hash).toBe(log.genesisHash);
    expect(ReleaseLog.verifyHead(head).valid).toBe(true);
  });
});

describe("verifyInstalledPackage", () => {
  it("accepts a matching install", () => {
    const log = makeLog();
    const m = makeMaintainer();
    const e = append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const result = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "0.1.0",
      installedTarballSha256: hex64("a"),
    });
    expect(result.valid).toBe(true);
    expect(result.entry).toEqual(e);
  });

  it("rejects mismatched tarball", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const result = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "0.1.0",
      installedTarballSha256: hex64("f"),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("mismatch");
  });

  it("case-insensitive tarball comparison", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const result = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "0.1.0",
      installedTarballSha256: hex64("A"), // uppercase
    });
    expect(result.valid).toBe(true);
  });

  it("rejects unknown version", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    const result = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "99.0.0",
      installedTarballSha256: hex64("a"),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("no release entry");
  });

  it("enforces trustedMaintainers allowlist", () => {
    const log = makeLog();
    const trustedMaintainer = makeMaintainer();
    append(log, trustedMaintainer, "0.1.0", hex64("a"), hex64("1"));

    // In trust set = ok
    const okResult = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "0.1.0",
      installedTarballSha256: hex64("a"),
      trustedMaintainers: [trustedMaintainer.did],
    });
    expect(okResult.valid).toBe(true);

    // Not in trust set = fail
    const badResult = verifyInstalledPackage({
      releaseLog: [...log.getEntries()],
      packageName: "soma-heart",
      version: "0.1.0",
      installedTarballSha256: hex64("a"),
      trustedMaintainers: ["did:key:z-someone-else"],
    });
    expect(badResult.valid).toBe(false);
    expect(badResult.reason).toContain("trust set");
  });

  it("rejects install when release chain is broken", () => {
    const log = makeLog();
    const m = makeMaintainer();
    append(log, m, "0.1.0", hex64("a"), hex64("1"));
    append(log, m, "0.1.1", hex64("b"), hex64("2"));
    // Tamper with chain
    const entries = [...log.getEntries()];
    const broken: ReleaseEntry[] = [
      entries[0],
      { ...entries[1], previousHash: hex64("f") },
    ];
    const result = verifyInstalledPackage({
      releaseLog: broken,
      packageName: "soma-heart",
      version: "0.1.1",
      installedTarballSha256: hex64("b"),
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("release chain invalid");
  });
});

describe("detectReleaseFork", () => {
  it("returns proof when same maintainer signs conflicting heads", () => {
    const m = makeMaintainer();
    // Build two independent release logs for the same package with the
    // same sequence count but different content — classic fork.
    const log1 = makeLog();
    append(log1, m, "0.1.0", hex64("a"), hex64("1"));
    append(log1, m, "0.1.1", hex64("b"), hex64("2"));
    const head1 = log1.signHead(m.kp.secretKey, m.kp.publicKey);

    const log2 = makeLog();
    append(log2, m, "0.1.0-evil", hex64("c"), hex64("3"));
    append(log2, m, "0.1.1-evil", hex64("d"), hex64("4"));
    const head2 = log2.signHead(m.kp.secretKey, m.kp.publicKey);

    expect(head1.sequence).toBe(head2.sequence);
    expect(head1.hash).not.toBe(head2.hash);

    const proof = detectReleaseFork(head1, head2);
    expect(proof).not.toBeNull();
    expect(proof?.maintainerDid).toBe(m.did);
    expect(proof?.sequence).toBe(1);
  });

  it("returns null when sequences differ", () => {
    const m = makeMaintainer();
    const log1 = makeLog();
    append(log1, m, "0.1.0", hex64("a"), hex64("1"));
    const head1 = log1.signHead(m.kp.secretKey, m.kp.publicKey);

    const log2 = makeLog();
    append(log2, m, "0.1.0", hex64("a"), hex64("1"));
    append(log2, m, "0.1.1", hex64("b"), hex64("2"));
    const head2 = log2.signHead(m.kp.secretKey, m.kp.publicKey);

    expect(detectReleaseFork(head1, head2)).toBeNull();
  });

  it("returns null for different packages", () => {
    const m = makeMaintainer();
    const logA = new ReleaseLog({ package: "soma-heart" });
    const logB = new ReleaseLog({ package: "soma-sense" });
    append(logA, m, "0.1.0", hex64("a"), hex64("1"));
    append(logB, m, "0.1.0", hex64("b"), hex64("2"));
    const headA = logA.signHead(m.kp.secretKey, m.kp.publicKey);
    const headB = logB.signHead(m.kp.secretKey, m.kp.publicKey);
    expect(detectReleaseFork(headA, headB)).toBeNull();
  });

  it("returns null when head signature is bad", () => {
    const m = makeMaintainer();
    const log1 = makeLog();
    append(log1, m, "0.1.0", hex64("a"), hex64("1"));
    const head1 = log1.signHead(m.kp.secretKey, m.kp.publicKey);
    const badHead = { ...head1, hash: hex64("f") };
    expect(detectReleaseFork(head1, badHead)).toBeNull();
  });
});

describe("ReleaseLog — replaceWith", () => {
  it("imports valid chain", () => {
    const src = makeLog();
    const m = makeMaintainer();
    append(src, m, "0.1.0", hex64("a"), hex64("1"));
    append(src, m, "0.1.1", hex64("b"), hex64("2"));

    const dest = makeLog();
    const result = dest.replaceWith([...src.getEntries()]);
    expect(result.valid).toBe(true);
    expect(dest.length).toBe(2);
    expect(dest.head).toBe(src.head);
  });

  it("rejects chain for wrong package", () => {
    const src = new ReleaseLog({ package: "soma-heart" });
    const m = makeMaintainer();
    append(src, m, "0.1.0", hex64("a"), hex64("1"));
    const dest = new ReleaseLog({ package: "soma-sense" });
    const result = dest.replaceWith([...src.getEntries()]);
    expect(result.valid).toBe(false);
    expect(dest.length).toBe(0);
  });
});
