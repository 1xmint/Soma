/**
 * Raw crypto primitives — the floor for everything above.
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

const crypto = getCryptoProvider();

export function cryptoBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "sha256 (32B)",
      setup: () => {
        return { data: "abc".repeat(11) };
      },
      body: (ctx) => {
        crypto.hashing.hash((ctx as { data: string }).data);
      },
    },
    {
      name: "ed25519 keygen",
      setup: () => ({}),
      body: () => {
        crypto.signing.generateKeyPair();
      },
    },
    {
      name: "ed25519 sign (32B)",
      setup: () => {
        const kp = crypto.signing.generateKeyPair();
        return { kp, msg: new TextEncoder().encode("x".repeat(32)) };
      },
      body: (ctx) => {
        const c = ctx as { kp: { secretKey: Uint8Array }; msg: Uint8Array };
        crypto.signing.sign(c.msg, c.kp.secretKey);
      },
    },
    {
      name: "ed25519 verify (32B)",
      setup: () => {
        const kp = crypto.signing.generateKeyPair();
        const msg = new TextEncoder().encode("x".repeat(32));
        const sig = crypto.signing.sign(msg, kp.secretKey);
        return { pk: kp.publicKey, msg, sig };
      },
      body: (ctx) => {
        const c = ctx as { pk: Uint8Array; msg: Uint8Array; sig: Uint8Array };
        crypto.signing.verify(c.msg, c.sig, c.pk);
      },
    },
    {
      name: "random 32B",
      setup: () => ({}),
      body: () => {
        crypto.random.randomBytes(32);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
