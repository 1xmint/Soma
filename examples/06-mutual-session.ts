/**
 * Example 06 — Three-message mutual-auth handshake.
 *
 * Two hearts (Alice, Bob) want to open an authenticated session. One-sided
 * PoP isn't enough: if only Bob proves to Alice, Alice could be a MITM.
 * Mutual session PoP has BOTH parties sign the SAME transcript, binding
 * their DIDs + public keys + nonces + purpose into a single hash that
 * either side can reference in follow-up operations (receipts, heartbeats).
 *
 * Protocol:
 *   1. initiate: Alice → {sessionId, nonceA, purpose}
 *   2. accept  : Bob → {nonceB, signature over transcript}
 *   3. confirm : Alice verifies Bob, signs same transcript
 *   4. verify  : either party confirms both signatures match
 *
 * Run: pnpm tsx examples/06-mutual-session.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  initiateSession,
  acceptSession,
  confirmSession,
  verifyMutualSession,
} from "../src/heart/mutual-session.js";

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

console.log("=== Participants ===");
console.log(`Alice : initiator`);
console.log(`Bob   : responder`);

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Alice proposes a session. No signature yet — just identity + nonce.
// ───────────────────────────────────────────────────────────────────────────
const init = initiateSession({
  initiatorDid: alice.did,
  initiatorPublicKey: alice.publicKey,
  purpose: "subtask dispatch: audit-log-scan",
  ttlMs: 60_000,
});
console.log("\n=== Step 1: Alice initiates ===");
console.log(`sessionId    : ${init.sessionId}`);
console.log(`nonceA       : ${init.nonceA.slice(0, 20)}...`);
console.log(`purpose      : ${init.purpose}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. Bob accepts. Signs the full transcript (init + his nonce + his DID).
// ───────────────────────────────────────────────────────────────────────────
const accept = acceptSession({
  init,
  responderDid: bob.did,
  responderPublicKey: bob.publicKey,
  responderSigningKey: bob.signingKey,
});
console.log("\n=== Step 2: Bob accepts (signs transcript) ===");
console.log(`nonceB       : ${accept.nonceB.slice(0, 20)}...`);
console.log(`sig (Bob)    : ${accept.responderSignature.slice(0, 20)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Alice verifies Bob, then signs the SAME transcript.
// ───────────────────────────────────────────────────────────────────────────
const confirm = confirmSession({
  init,
  accept,
  initiatorSigningKey: alice.signingKey,
});
console.log("\n=== Step 3: Alice confirms (verifies Bob, signs transcript) ===");
console.log(`sig (Alice)  : ${confirm.initiatorSignature.slice(0, 20)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Either party (or an auditor) verifies the completed session.
// ───────────────────────────────────────────────────────────────────────────
const result = verifyMutualSession({ init, accept, confirm });
console.log("\n=== Step 4: Full mutual verification ===");
console.log(`valid        : ${result.valid}`);
if (result.valid) {
  console.log(`transcript   : ${result.bindings.transcriptHash.slice(0, 32)}...`);
  console.log(`initiator    : ${result.bindings.initiatorDid.slice(0, 32)}...`);
  console.log(`responder    : ${result.bindings.responderDid.slice(0, 32)}...`);
  console.log("Both sides proved key possession; transcriptHash is the session id");
  console.log("to bind into all follow-up messages (receipts, heartbeats).");
}

// ───────────────────────────────────────────────────────────────────────────
// Step 5. Eve tries to MITM: swap Bob's public key for her own.
// ───────────────────────────────────────────────────────────────────────────
const eve = makeHeart();
const tamperedAccept = { ...accept, responderPublicKey: eve.publicKey };
const tampered = verifyMutualSession({ init, accept: tamperedAccept, confirm });
console.log("\n=== Step 5: Eve swaps Bob's public key ===");
console.log(`result       : ${JSON.stringify(tampered)}`);

console.log("\nDone.");
