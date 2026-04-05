/**
 * Example 01 — Basic delegation + attenuation + caveats.
 *
 * Alice grants Bob the ability to call `tool:db:read` with a 1000-credit
 * budget cap and a 1-hour TTL. Bob then narrows the delegation for Carol
 * to 100 credits and 5 minutes.
 *
 * Run: pnpm tsx examples/01-basic-delegation.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createDelegation,
  attenuateDelegation,
  verifyDelegation,
} from "../src/heart/delegation.js";

const crypto = getCryptoProvider();

function makeHeart(name: string) {
  const kp = crypto.signing.generateKeyPair();
  return {
    name,
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    signingKey: kp.secretKey,
  };
}

const alice = makeHeart("Alice");
const bob = makeHeart("Bob");
const carol = makeHeart("Carol");

console.log("=== Participants ===");
console.log(`Alice : ${alice.did.slice(0, 32)}...`);
console.log(`Bob   : ${bob.did.slice(0, 32)}...`);
console.log(`Carol : ${carol.did.slice(0, 32)}...`);

// ───────────────────────────────────────────────────────────────────────────
// Step 1. Alice grants Bob tool:db:read with 1000 credits, expiring in 1h.
// ───────────────────────────────────────────────────────────────────────────
const nowMs = Date.now();
const alice2bob = createDelegation({
  issuerDid: alice.did,
  issuerPublicKey: alice.publicKey,
  issuerSigningKey: alice.signingKey,
  subjectDid: bob.did,
  capabilities: ["tool:db:read"],
  caveats: [
    { kind: "expires-at", timestamp: nowMs + 60 * 60 * 1000 },
    { kind: "budget", credits: 1000 },
  ],
});
console.log("\n=== Step 1: Alice delegates to Bob ===");
console.log(`Delegation id  : ${alice2bob.id}`);
console.log(`Capabilities   : ${JSON.stringify(alice2bob.capabilities)}`);
console.log(`Caveats        : ${JSON.stringify(alice2bob.caveats)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. Bob verifies + uses it.
// ───────────────────────────────────────────────────────────────────────────
const check1 = verifyDelegation(alice2bob, {
  invokerDid: bob.did,
  capability: "tool:db:read",
  creditsSpent: 50,
  cumulativeCreditsSpent: 0,
});
console.log("\n=== Step 2: Bob invokes under budget ===");
console.log(`Verification   : ${JSON.stringify(check1)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Bob attenuates for Carol: 100 credits, expires in 5 minutes.
// ───────────────────────────────────────────────────────────────────────────
const bob2carol = attenuateDelegation({
  parent: alice2bob,
  newSubjectDid: carol.did,
  newSubjectSigningKey: bob.signingKey,
  newSubjectPublicKey: bob.publicKey,
  additionalCaveats: [
    { kind: "expires-at", timestamp: nowMs + 5 * 60 * 1000 },
    { kind: "budget", credits: 100 }, // narrowing happens at caveat level too
    { kind: "max-invocations", count: 10 },
  ],
});
console.log("\n=== Step 3: Bob attenuates to Carol ===");
console.log(`Child id       : ${bob2carol.id}`);
console.log(`Parent id      : ${bob2carol.parentId}`);
console.log(`Caveats (all)  : ${JSON.stringify(bob2carol.caveats)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Carol uses it; spends 60, then 50 (which would blow 100-budget).
// ───────────────────────────────────────────────────────────────────────────
const carolOk = verifyDelegation(bob2carol, {
  invokerDid: carol.did,
  capability: "tool:db:read",
  creditsSpent: 60,
  cumulativeCreditsSpent: 0,
  invocationCount: 0,
});
const carolFail = verifyDelegation(bob2carol, {
  invokerDid: carol.did,
  capability: "tool:db:read",
  creditsSpent: 50,
  cumulativeCreditsSpent: 60, // already spent 60
  invocationCount: 1,
});
console.log("\n=== Step 4: Carol invocations ===");
console.log(`Spend 60 (first): ${JSON.stringify(carolOk)}`);
console.log(`Spend 50 (would exceed 100): ${JSON.stringify(carolFail)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 5. What Carol CANNOT do: broaden the capability.
// ───────────────────────────────────────────────────────────────────────────
try {
  attenuateDelegation({
    parent: bob2carol,
    newSubjectDid: carol.did,
    newSubjectSigningKey: carol.signingKey,
    newSubjectPublicKey: carol.publicKey,
    narrowedCapabilities: ["tool:db:write"], // NOT in parent
  });
  console.log("\n!! Broadening accepted — this should not happen");
} catch (err) {
  console.log("\n=== Step 5: Carol tries to broaden → rejected ===");
  console.log(`Error          : ${(err as Error).message}`);
}

console.log("\nDone.");
