/**
 * Example 02 — Proof-of-possession challenge flow.
 *
 * Bob holds a delegation. A verifier wants to confirm Bob actually has the
 * subject's private key (not just a copy of the JSON blob). 3-step flow:
 *   1. Verifier issues a challenge (random nonce bound to the delegation ID).
 *   2. Bob signs (nonce || delegationId) with his signing key.
 *   3. Verifier checks the signature against bob's public key via subjectDid.
 *
 * Also demonstrates: an attacker who holds the token but not the key fails.
 *
 * Run: pnpm tsx examples/02-pop-challenge.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import { createDelegation } from "../src/heart/delegation.js";
import {
  issueChallenge,
  proveChallenge,
  verifyProof,
} from "../src/heart/proof-of-possession.js";

const crypto = getCryptoProvider();

function makeHeart() {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    signingKey: kp.secretKey,
  };
}

const alice = makeHeart();
const bob = makeHeart();
const eve = makeHeart();

console.log("=== Participants ===");
console.log(`Alice : issuer`);
console.log(`Bob   : legitimate subject/holder`);
console.log(`Eve   : stole the JSON, doesn't have Bob's key`);

const delegation = createDelegation({
  issuerDid: alice.did,
  issuerPublicKey: alice.publicKey,
  issuerSigningKey: alice.signingKey,
  subjectDid: bob.did,
  capabilities: ["api:account:read"],
});

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Verifier challenges holder.
// ───────────────────────────────────────────────────────────────────────────
const challenge = issueChallenge(delegation);
console.log("\n=== Step 1: challenge issued ===");
console.log(`nonceB64        : ${challenge.nonceB64.slice(0, 20)}...`);
console.log(`delegationId    : ${challenge.delegationId}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2a. Bob answers correctly.
// ───────────────────────────────────────────────────────────────────────────
const bobProof = proveChallenge(challenge, bob.signingKey);
const bobResult = verifyProof(challenge, bobProof, delegation);
console.log("\n=== Step 2: Bob signs with real key ===");
console.log(`Result          : ${JSON.stringify(bobResult)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2b. Eve has the JSON but not Bob's key. She signs with her own key.
// ───────────────────────────────────────────────────────────────────────────
const eveProof = proveChallenge(challenge, eve.signingKey);
const eveResult = verifyProof(challenge, eveProof, delegation);
console.log("\n=== Step 3: Eve attempts with wrong key ===");
console.log(`Result          : ${JSON.stringify(eveResult)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Replay prevention: reusing Bob's old proof with a new nonce fails.
// ───────────────────────────────────────────────────────────────────────────
const newChallenge = issueChallenge(delegation);
const replayResult = verifyProof(newChallenge, bobProof, delegation);
console.log("\n=== Step 4: replay old proof vs. new nonce ===");
console.log(`Result          : ${JSON.stringify(replayResult)}`);

console.log("\nDone.");
