/**
 * Revocation benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createRevocation,
  verifyRevocation,
  RevocationRegistry,
  type RevocationEvent,
} from "../src/heart/revocation.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

function setupRevocation(): RevocationEvent {
  const alice = crypto.signing.generateKeyPair();
  return createRevocation({
    targetId: "dg-abc123",
    targetKind: "delegation",
    issuerDid: publicKeyToDid(alice.publicKey),
    issuerPublicKey: crypto.encoding.encodeBase64(alice.publicKey),
    issuerSigningKey: alice.secretKey,
    reason: "compromised",
  });
}

export function revocationBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "createRevocation",
      setup: () => {
        const alice = crypto.signing.generateKeyPair();
        return {
          did: publicKeyToDid(alice.publicKey),
          pk: crypto.encoding.encodeBase64(alice.publicKey),
          sk: alice.secretKey,
        };
      },
      body: (ctx) => {
        const c = ctx as { did: string; pk: string; sk: Uint8Array };
        createRevocation({
          targetId: "dg-abc123",
          targetKind: "delegation",
          issuerDid: c.did,
          issuerPublicKey: c.pk,
          issuerSigningKey: c.sk,
          reason: "compromised",
        });
      },
    },
    {
      name: "verifyRevocation",
      setup: () => setupRevocation(),
      body: (ctx) => {
        verifyRevocation(ctx as RevocationEvent);
      },
    },
    {
      name: "registry.add",
      setup: () => {
        const registry = new RevocationRegistry();
        const rev = setupRevocation();
        return { registry, rev };
      },
      body: (ctx) => {
        // Fresh registry per op to measure add-cost, not no-op.
        const c = ctx as { registry: RevocationRegistry; rev: RevocationEvent };
        const r = new RevocationRegistry();
        r.add(c.rev);
      },
    },
    {
      name: "registry.isRevoked (hit)",
      setup: () => {
        const registry = new RevocationRegistry();
        const rev = setupRevocation();
        registry.add(rev);
        return { registry, id: rev.targetId };
      },
      body: (ctx) => {
        const c = ctx as { registry: RevocationRegistry; id: string };
        c.registry.isRevoked(c.id);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
