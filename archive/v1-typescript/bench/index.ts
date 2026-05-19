/**
 * Main bench runner. Imports every bench suite, runs them all, prints tables.
 *
 * Run: pnpm bench
 *
 * Each suite returns BenchResult[]; we print them grouped and then a flat
 * summary at the end.
 */

import { cryptoBenches } from "./crypto.bench.js";
import { delegationBenches } from "./delegation.bench.js";
import { popBenches } from "./pop.bench.js";
import { revocationBenches } from "./revocation.bench.js";
import { keyRotationBenches } from "./key-rotation.bench.js";
import { spendReceiptsBenches } from "./spend-receipts.bench.js";
import { mutualSessionBenches } from "./mutual-session.bench.js";
import { thresholdSigningBenches } from "./threshold-signing.bench.js";
import { selectiveDisclosureBenches } from "./selective-disclosure.bench.js";
import { printResults, type BenchResult } from "./_runner.js";

interface Suite {
  title: string;
  run: () => BenchResult[];
}

const SUITES: Suite[] = [
  { title: "Crypto primitives", run: cryptoBenches },
  { title: "Delegation", run: delegationBenches },
  { title: "Proof-of-possession", run: popBenches },
  { title: "Revocation", run: revocationBenches },
  { title: "Key rotation (KERI)", run: keyRotationBenches },
  { title: "Spend receipts", run: spendReceiptsBenches },
  { title: "Mutual session", run: mutualSessionBenches },
  { title: "Threshold signing (3/5)", run: thresholdSigningBenches },
  { title: "Selective disclosure", run: selectiveDisclosureBenches },
];

console.log("soma-heart benchmarks");
console.log("=====================");
console.log(`node    : ${process.version}`);
console.log(`platform: ${process.platform} ${process.arch}`);
console.log(`warmup  : 100 samples / calibrate`);
console.log(`samples : 1000 per case`);

for (const suite of SUITES) {
  const results = suite.run();
  printResults(suite.title, results);
}

console.log("\n— done —");
