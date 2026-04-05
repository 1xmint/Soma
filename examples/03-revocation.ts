/**
 * Example 03 — Revocation: declare a credential dead.
 *
 * Alice issues a delegation to Bob. Later, Bob's machine is suspected
 * compromised. Alice publishes a RevocationEvent. Verifiers with a
 * RevocationRegistry reject the delegation even though its signature is
 * still valid.
 *
 * Run: pnpm tsx examples/03-revocation.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createDelegation,
  verifyDelegation,
} from "../src/heart/delegation.js";
import {
  createRevocation,
  RevocationRegistry,
} from "../src/heart/revocation.js";

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

const delegation = createDelegation({
  issuerDid: alice.did,
  issuerPublicKey: alice.publicKey,
  issuerSigningKey: alice.signingKey,
  subjectDid: bob.did,
  capabilities: ["api:pay", "api:balance"],
});
console.log("=== Delegation issued ===");
console.log(`id            : ${delegation.id}`);

// Bob uses it successfully.
const beforeRevoke = verifyDelegation(delegation, {
  invokerDid: bob.did,
  capability: "api:pay",
});
console.log(`\nPre-revoke    : ${JSON.stringify(beforeRevoke)}`);

// Something bad happens. Alice revokes.
const revocation = createRevocation({
  targetId: delegation.id,
  targetKind: "delegation",
  issuerDid: alice.did,
  issuerPublicKey: alice.publicKey,
  issuerSigningKey: alice.signingKey,
  reason: "compromised",
  detail: "incident-2026-04-04",
});
console.log("\n=== Revocation published ===");
console.log(`id            : ${revocation.id}`);
console.log(`target        : ${revocation.targetId}`);
console.log(`reason        : ${revocation.reason}`);
console.log(`detail        : ${revocation.detail}`);

// Verifier's registry accepts the signed event.
const registry = new RevocationRegistry();
const added = registry.add(revocation);
console.log(`\nRegistry added: ${added}`);
console.log(`Is revoked?   : ${registry.isRevoked(delegation.id)}`);

// Application policy — verifier must check the registry before honoring.
const sigStillValid = verifyDelegation(delegation, {
  invokerDid: bob.did,
  capability: "api:pay",
});
console.log("\n=== Verifier pipeline ===");
console.log(`Signature     : ${JSON.stringify(sigStillValid)}`);
console.log(`Registry      : ${registry.isRevoked(delegation.id) ? "REVOKED" : "ok"}`);
console.log(`Overall       : ${registry.isRevoked(delegation.id) ? "REJECT" : "ACCEPT"}`);

console.log("\nDone.");
