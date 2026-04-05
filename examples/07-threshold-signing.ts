/**
 * Example 07 — 3-of-5 threshold Ed25519 signing.
 *
 * No single party should be able to sign as the heart. 5 shareholders hold
 * shares; any 3 can cooperate to produce a signature; fewer than 3 cannot.
 * The resulting signature is a normal Ed25519 signature — verifiers don't
 * know (or care) that it was produced by a ceremony.
 *
 * Trust model: the signing coordinator reconstructs the secret briefly
 * during the ceremony. In production, run the coordinator in a TEE or
 * isolated process. This demo runs it in-process for clarity.
 *
 * Flow:
 *   1. Dealer generates the key, splits into 5 shares with threshold=3.
 *   2. Shares are handed to 5 separate shareholders (simulated).
 *   3. A ceremony begins; 3 shareholders contribute shares.
 *   4. Ceremony produces an Ed25519 signature.
 *   5. A verifier checks the signature with the public key alone.
 *   6. Attempt with only 2 shares fails.
 *   7. Mix-and-match shares from a different key fail.
 *
 * Run: pnpm tsx examples/07-threshold-signing.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import {
  generateThresholdKeyPair,
  SigningCeremony,
  verifyThresholdSignature,
} from "../src/heart/threshold-signing.js";

const crypto = getCryptoProvider();

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Generate the threshold key: 3-of-5 with a stable keyId.
// ───────────────────────────────────────────────────────────────────────────
const keyId = "team-ops-signing-key-2026";
const tk = generateThresholdKeyPair({
  threshold: 3,
  totalShares: 5,
  keyId,
});
console.log("=== Step 1: Key generated ===");
console.log(`keyId        : ${tk.keyId}`);
console.log(`threshold    : ${tk.threshold}-of-${tk.totalShares}`);
console.log(`publicKey    : ${crypto.encoding.encodeBase64(tk.publicKey).slice(0, 32)}...`);
console.log(`shares       : ${tk.shares.length} issued`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. Shares are distributed. In practice: different people, devices, HSMs.
// ───────────────────────────────────────────────────────────────────────────
const holder = (i: number) => ({
  name: ["Alice", "Bob", "Carol", "Dave", "Eve"][i],
  share: tk.shares[i],
});
const team = [0, 1, 2, 3, 4].map(holder);
console.log("\n=== Step 2: Shares distributed ===");
team.forEach((p) => console.log(`  ${p.name.padEnd(6)}: share index ${p.share.index}`));

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Ceremony: Alice, Carol, Eve each contribute. Bob and Dave out-of-office.
// ───────────────────────────────────────────────────────────────────────────
const message = new TextEncoder().encode("AUTHORIZE: deploy v1.4.2 to prod");
const ceremony = new SigningCeremony(message, {
  publicKey: tk.publicKey,
  threshold: tk.threshold,
  keyId: tk.keyId,
});

const contributors = [team[0], team[2], team[4]]; // Alice, Carol, Eve
console.log("\n=== Step 3: Ceremony ===");
for (const p of contributors) {
  const readyAfter = ceremony.contribute(p.share);
  console.log(`  ${p.name} contributes (share #${p.share.index}) — ready=${readyAfter}`);
}

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Produce signature.
// ───────────────────────────────────────────────────────────────────────────
const sig = ceremony.sign();
console.log("\n=== Step 4: Signature produced ===");
console.log(`contributing : [${sig.contributingShareIds.join(", ")}]`);
console.log(`keyId        : ${sig.keyId}`);
console.log(`sig (hex)    : ${Buffer.from(sig.signature).toString("hex").slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 5. Verifier. Just an Ed25519 check — no knowledge of the ceremony.
// ───────────────────────────────────────────────────────────────────────────
const ok = verifyThresholdSignature(message, sig, tk.publicKey);
console.log("\n=== Step 5: Verifier check (vanilla Ed25519) ===");
console.log(`valid        : ${ok}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 6. Below-threshold attempt.
// ───────────────────────────────────────────────────────────────────────────
const lonely = new SigningCeremony(message, {
  publicKey: tk.publicKey,
  threshold: tk.threshold,
  keyId: tk.keyId,
});
lonely.contribute(team[0].share);
lonely.contribute(team[1].share);
console.log("\n=== Step 6: Below threshold (2/3) ===");
try {
  lonely.sign();
  console.log("!! Signed with 2 shares — should not happen");
} catch (err) {
  console.log(`Error        : ${(err as Error).message}`);
}

// ───────────────────────────────────────────────────────────────────────────
// Step 7. Mix-and-match with a different key's shares.
// ───────────────────────────────────────────────────────────────────────────
const otherKey = generateThresholdKeyPair({
  threshold: 3,
  totalShares: 5,
  keyId: "different-key-id",
});
const mixedCeremony = new SigningCeremony(message, {
  publicKey: tk.publicKey,
  threshold: tk.threshold,
  keyId: tk.keyId,
});
mixedCeremony.contribute(team[0].share);
mixedCeremony.contribute(team[1].share);
console.log("\n=== Step 7: Mix-and-match attempt (foreign share) ===");
try {
  mixedCeremony.contribute(otherKey.shares[2]);
  console.log("!! Accepted foreign share — should not happen");
} catch (err) {
  console.log(`Error        : ${(err as Error).message}`);
}

console.log("\nDone.");
