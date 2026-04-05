/**
 * Example 04 — KERI-style pre-rotation.
 *
 * Alice's identity is stable (her inception-key DID). But keys must rotate:
 * scheduled hygiene, or reactive compromise response. Pre-rotation closes
 * the obvious attack: even if attacker steals the current key, they cannot
 * rotate to a key of their choosing because the NEXT key's digest was
 * committed in the PREVIOUS event.
 *
 * This example walks through:
 *   1. Alice incepts (sequence 0) — commits to K1's digest.
 *   2. Alice rotates from K0 → K1, committing to K2's digest.
 *   3. Alice rotates from K1 → K2, committing to K3's digest.
 *   4. A stranger exports her chain and verifies it independently.
 *   5. An attacker who stole K1 tries to rotate to their own key — rejected.
 *
 * Run: pnpm tsx examples/04-key-rotation.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { KeyHistory } from "../src/heart/key-rotation.js";

const crypto = getCryptoProvider();

// Pre-generate the full rotation schedule. In practice each next keypair is
// generated just before the rotation that commits to its digest.
const k0 = crypto.signing.generateKeyPair();
const k1 = crypto.signing.generateKeyPair();
const k2 = crypto.signing.generateKeyPair();
const k3 = crypto.signing.generateKeyPair();

console.log("=== Keys generated ===");
console.log("K0 (inception), K1, K2, K3 — four Ed25519 keypairs");

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Inception — Alice's identity is established, commits to K1's digest.
// ───────────────────────────────────────────────────────────────────────────
const { history, event: inception } = KeyHistory.incept({
  inceptionSecretKey: k0.secretKey,
  inceptionPublicKey: k0.publicKey,
  nextPublicKey: k1.publicKey,
});
console.log("\n=== Step 1: Inception ===");
console.log(`identity     : ${history.identity.slice(0, 40)}...`);
console.log(`sequence     : ${inception.sequence}`);
console.log(`nextKeyDigest: ${inception.nextKeyDigest.slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. First rotation — K0 → K1, commits to K2's digest.
// ───────────────────────────────────────────────────────────────────────────
const rot1 = history.rotate({
  currentSecretKey: k1.secretKey,
  currentPublicKey: k1.publicKey,
  nextPublicKey: k2.publicKey,
});
console.log("\n=== Step 2: Rotation 1 (K0 → K1) ===");
console.log(`sequence     : ${rot1.sequence}`);
console.log(`previousHash : ${rot1.previousEventHash.slice(0, 32)}...`);
console.log(`nextKeyDigest: ${rot1.nextKeyDigest.slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Second rotation — K1 → K2, commits to K3's digest.
// ───────────────────────────────────────────────────────────────────────────
const rot2 = history.rotate({
  currentSecretKey: k2.secretKey,
  currentPublicKey: k2.publicKey,
  nextPublicKey: k3.publicKey,
});
console.log("\n=== Step 3: Rotation 2 (K1 → K2) ===");
console.log(`sequence     : ${rot2.sequence}`);
console.log(`length       : ${history.length} events`);
console.log(`current key  : ${history.currentPublicKey.slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Export + independent verification.
// ───────────────────────────────────────────────────────────────────────────
const exportedEvents = history.getEvents();
const verifyResult = KeyHistory.verifyChain(exportedEvents, history.identity);
console.log("\n=== Step 4: Third party verifies chain ===");
console.log(`Verification : ${JSON.stringify(verifyResult)}`);
console.log(`Current key  : ${KeyHistory.currentPublicKey(exportedEvents).slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 5. Attacker stole K1. Tries to rotate to their own evil key.
// ───────────────────────────────────────────────────────────────────────────
const evil = crypto.signing.generateKeyPair();
try {
  history.rotate({
    currentSecretKey: k1.secretKey,
    currentPublicKey: k1.publicKey,
    nextPublicKey: evil.publicKey,
    // Note: K1 was already consumed at rotation 1 — this call will also fail
    // because the current head's nextKeyDigest commits to K3, not K1.
  });
  console.log("\n!! Attacker rotation accepted — this should not happen");
} catch (err) {
  console.log("\n=== Step 5: Attacker tries to rotate past K2 using K1 → rejected ===");
  console.log(`Error        : ${(err as Error).message}`);
}

// Even with the real next-in-sequence key (K3), the attacker can't rotate
// to a key whose digest wasn't pre-committed. Pre-rotation doesn't prevent
// this class of attack alone — the protection is that K2's secret must
// have been PROTECTED during the window between commitment and rotation.
console.log("\nDone.");
