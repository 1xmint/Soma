/**
 * Spend receipts benchmarks.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  SpendLog,
  signSpendHead,
  verifySpendHead,
  type SpendHead,
} from "../src/heart/spend-receipts.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

export function spendReceiptsBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "SpendLog.append",
      setup: () => {
        const bob = crypto.signing.generateKeyPair();
        const log = new SpendLog({
          delegationId: "dg-abc123",
          subjectSigningKey: bob.secretKey,
          subjectPublicKey: bob.publicKey,
        });
        return { log };
      },
      body: (ctx) => {
        (ctx as { log: SpendLog }).log.append({
          amount: 10,
          capability: "api:compute",
        });
      },
    },
    {
      name: "signSpendHead",
      setup: () => {
        const alice = crypto.signing.generateKeyPair();
        const bob = crypto.signing.generateKeyPair();
        const log = new SpendLog({
          delegationId: "dg-abc123",
          subjectSigningKey: bob.secretKey,
          subjectPublicKey: bob.publicKey,
        });
        log.append({ amount: 10, capability: "api:compute" });
        log.append({ amount: 20, capability: "api:compute" });
        return {
          did: publicKeyToDid(alice.publicKey),
          pk: alice.publicKey,
          sk: alice.secretKey,
          seq: log.length - 1,
          hash: log.head,
          sum: log.cumulative,
        };
      },
      body: (ctx) => {
        const c = ctx as {
          pk: Uint8Array;
          sk: Uint8Array;
          seq: number;
          hash: string;
          sum: number;
        };
        signSpendHead({
          delegationId: "dg-abc123",
          sequence: c.seq,
          hash: c.hash,
          cumulative: c.sum,
          issuerSigningKey: c.sk,
          issuerPublicKey: c.pk,
        });
      },
    },
    {
      name: "verifySpendHead",
      setup: () => {
        const alice = crypto.signing.generateKeyPair();
        const bob = crypto.signing.generateKeyPair();
        const log = new SpendLog({
          delegationId: "dg-abc123",
          subjectSigningKey: bob.secretKey,
          subjectPublicKey: bob.publicKey,
        });
        log.append({ amount: 10, capability: "api:compute" });
        const head = signSpendHead({
          delegationId: "dg-abc123",
          sequence: log.length - 1,
          hash: log.head,
          cumulative: log.cumulative,
          issuerSigningKey: alice.secretKey,
          issuerPublicKey: alice.publicKey,
        });
        return { head };
      },
      body: (ctx) => {
        verifySpendHead((ctx as { head: SpendHead }).head);
      },
    },
    {
      name: "SpendLog.verify (10 entries)",
      setup: () => {
        const bob = crypto.signing.generateKeyPair();
        const log = new SpendLog({
          delegationId: "dg-abc123",
          subjectSigningKey: bob.secretKey,
          subjectPublicKey: bob.publicKey,
        });
        for (let i = 0; i < 10; i++) {
          log.append({ amount: 10, capability: "api:compute" });
        }
        return { log };
      },
      body: (ctx) => {
        (ctx as { log: SpendLog }).log.verify();
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
