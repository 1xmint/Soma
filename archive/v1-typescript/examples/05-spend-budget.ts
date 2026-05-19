/**
 * Example 05 — Spend receipts, signed heads, double-spend detection.
 *
 * A budget caveat says "up to 1000 credits". But what proves how much has
 * been spent? A subject could lie. This module backs budget caveats with a
 * hash-chained, signed log of spend receipts, plus the issuer can sign the
 * current head. If the subject later presents a forked chain, the issuer's
 * signed head + the new chain = cryptographic proof of double-spend.
 *
 * Flow:
 *   1. Alice grants Bob 1000 credits.
 *   2. Bob spends 250 (receipt 0), 300 (receipt 1), 150 (receipt 2) = 700 total.
 *   3. Alice signs the head at cumulative=700.
 *   4. Later, Bob tries to present a forked chain [250, 100, 200] at sequence 2.
 *   5. Alice holds both signed heads → produces a DoubleSpendProof.
 *
 * Run: pnpm tsx examples/05-spend-budget.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import { createDelegation } from "../src/heart/delegation.js";
import {
  SpendLog,
  signSpendHead,
  verifySpendHead,
  detectDoubleSpend,
} from "../src/heart/spend-receipts.js";

const crypto = getCryptoProvider();

function makeHeart() {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    publicKeyBytes: kp.publicKey,
    signingKey: kp.secretKey,
  };
}

const alice = makeHeart();
const bob = makeHeart();

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Alice delegates with a 1000-credit budget to Bob.
// ───────────────────────────────────────────────────────────────────────────
const delegation = createDelegation({
  issuerDid: alice.did,
  issuerPublicKey: alice.publicKey,
  issuerSigningKey: alice.signingKey,
  subjectDid: bob.did,
  capabilities: ["api:compute"],
  caveats: [{ kind: "budget", credits: 1000 }],
});
console.log("=== Step 1: Delegation with 1000-credit budget ===");
console.log(`id           : ${delegation.id}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. Bob maintains a SpendLog; 3 authorized spends.
// ───────────────────────────────────────────────────────────────────────────
const bobLog = new SpendLog({
  delegationId: delegation.id,
  subjectSigningKey: bob.signingKey,
  subjectPublicKey: bob.publicKeyBytes,
});
bobLog.append({ amount: 250, capability: "api:compute" });
bobLog.append({ amount: 300, capability: "api:compute" });
bobLog.append({ amount: 150, capability: "api:compute" });
console.log("\n=== Step 2: Bob records 3 spends ===");
console.log(`length       : ${bobLog.length}`);
console.log(`cumulative   : ${bobLog.cumulative}`);
console.log(`head hash    : ${bobLog.head.slice(0, 32)}...`);
console.log(`wouldExceed?(400, 1000) : ${bobLog.wouldExceed(400, 1000)}`);

// Bob's chain self-verifies.
console.log(`self-verify  : ${JSON.stringify(bobLog.verify())}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Alice signs a head commitment over Bob's log.
// ───────────────────────────────────────────────────────────────────────────
const aliceHead = signSpendHead({
  delegationId: delegation.id,
  sequence: bobLog.length - 1,
  hash: bobLog.head,
  cumulative: bobLog.cumulative,
  issuerSigningKey: alice.signingKey,
  issuerPublicKey: alice.publicKeyBytes,
});
console.log("\n=== Step 3: Alice signs the head ===");
console.log(`sequence     : ${aliceHead.sequence}`);
console.log(`cumulative   : ${aliceHead.cumulative}`);
console.log(`verify       : ${JSON.stringify(verifySpendHead(aliceHead))}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Bob constructs a DIFFERENT chain and shows it to a new verifier.
//   (He's trying to double-spend — re-use the same delegation differently.)
// ───────────────────────────────────────────────────────────────────────────
const bobForkLog = new SpendLog({
  delegationId: delegation.id,
  subjectSigningKey: bob.signingKey,
  subjectPublicKey: bob.publicKeyBytes,
});
bobForkLog.append({ amount: 250, capability: "api:compute" });
bobForkLog.append({ amount: 100, capability: "api:compute" });
bobForkLog.append({ amount: 200, capability: "api:compute" });
console.log("\n=== Step 4: Bob forks — alternate chain at the same sequence ===");
console.log(`fork head    : ${bobForkLog.head.slice(0, 32)}...`);
console.log(`fork sum     : ${bobForkLog.cumulative}`);

// Alice also signed a head over the forked chain (imagine Alice saw it first).
const aliceForkHead = signSpendHead({
  delegationId: delegation.id,
  sequence: bobForkLog.length - 1,
  hash: bobForkLog.head,
  cumulative: bobForkLog.cumulative,
  issuerSigningKey: alice.signingKey,
  issuerPublicKey: alice.publicKeyBytes,
});

// ───────────────────────────────────────────────────────────────────────────
// Step 5. Anyone holding both signed heads proves double-spend.
// ───────────────────────────────────────────────────────────────────────────
const proof = detectDoubleSpend(aliceHead, aliceForkHead);
console.log("\n=== Step 5: Double-spend proof ===");
if (proof) {
  console.log(`delegationId : ${proof.delegationId}`);
  console.log(`sequence     : ${proof.sequence}`);
  console.log(`hashA        : ${proof.commitmentA.hash.slice(0, 32)}...`);
  console.log(`hashB        : ${proof.commitmentB.hash.slice(0, 32)}...`);
  console.log(`cumulativeA  : ${proof.commitmentA.cumulative}`);
  console.log(`cumulativeB  : ${proof.commitmentB.cumulative}`);
  console.log("Both heads are issuer-signed for the same (delegationId, sequence).");
  console.log("Two different hashes at the same sequence ⇒ fork ⇒ double-spend.");
} else {
  console.log("No double-spend detected — unexpected.");
}

console.log("\nDone.");
