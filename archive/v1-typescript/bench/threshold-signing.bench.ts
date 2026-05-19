/**
 * Threshold signing benchmarks — 3-of-5 Ed25519 via Shamir reconstruction.
 */

import {
  generateThresholdKeyPair,
  thresholdSign,
  verifyThresholdSignature,
  type ThresholdKeyPair,
  type ThresholdSignature,
} from "../src/heart/threshold-signing.js";
import { runBench, type BenchCase, type BenchResult } from "./_runner.js";

export function thresholdSigningBenches(): BenchResult[] {
  const cases: BenchCase<unknown>[] = [
    {
      name: "generateThresholdKey (3/5)",
      setup: () => ({}),
      body: () => {
        generateThresholdKeyPair({ threshold: 3, totalShares: 5, keyId: "k" });
      },
    },
    {
      name: "thresholdSign (3/5, 32B msg)",
      setup: () => {
        const tk = generateThresholdKeyPair({
          threshold: 3,
          totalShares: 5,
          keyId: "k",
        });
        const msg = new TextEncoder().encode("x".repeat(32));
        return { tk, msg };
      },
      body: (ctx) => {
        const c = ctx as { tk: ThresholdKeyPair; msg: Uint8Array };
        thresholdSign(
          [c.tk.shares[0], c.tk.shares[2], c.tk.shares[4]],
          c.msg,
          {
            publicKey: c.tk.publicKey,
            threshold: c.tk.threshold,
            keyId: c.tk.keyId,
          },
        );
      },
    },
    {
      name: "verifyThresholdSig (32B msg)",
      setup: () => {
        const tk = generateThresholdKeyPair({
          threshold: 3,
          totalShares: 5,
          keyId: "k",
        });
        const msg = new TextEncoder().encode("x".repeat(32));
        const sig = thresholdSign(
          [tk.shares[0], tk.shares[2], tk.shares[4]],
          msg,
          { publicKey: tk.publicKey, threshold: tk.threshold, keyId: tk.keyId },
        );
        return { tk, msg, sig };
      },
      body: (ctx) => {
        const c = ctx as {
          tk: ThresholdKeyPair;
          msg: Uint8Array;
          sig: ThresholdSignature;
        };
        verifyThresholdSignature(c.msg, c.sig, c.tk.publicKey);
      },
    },
  ];
  return cases.map((c) => runBench(c));
}
