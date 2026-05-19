/**
 * Example 08 — Selective disclosure of signed claims.
 *
 * The issuer signs a document with 4 claims: name, dob, country, kyc-tier.
 * The subject holds the document privately. A verifier only needs to know
 * the country + kyc-tier — the subject reveals just those two fields,
 * holding back name + dob, and the verifier can still check that the
 * issuer signed the full set.
 *
 * Mechanism:
 *   - Each field commits as hash(salt || canonical({field, value})).
 *   - Commitment root = hash(sorted(field → commitment) pairs).
 *   - Issuer signs envelope containing root (not the individual fields).
 *   - Holder reveals (value, salt) for disclosed fields, raw commitments
 *     for withheld ones, verifier recomputes root + checks signature.
 *
 * Run: pnpm tsx examples/08-selective-disclosure.ts
 */

import { getCryptoProvider } from "../src/core/crypto-provider.js";
import { publicKeyToDid } from "../src/core/genome.js";
import {
  createDisclosableDocument,
  createDisclosureProof,
  verifyDisclosureProof,
  verifyDisclosableDocument,
} from "../src/heart/selective-disclosure.js";

const crypto = getCryptoProvider();

function makeHeart() {
  const kp = crypto.signing.generateKeyPair();
  return {
    did: publicKeyToDid(kp.publicKey),
    publicKey: crypto.encoding.encodeBase64(kp.publicKey),
    signingKey: kp.secretKey,
  };
}

const kycProvider = makeHeart(); // issuer
const alice = makeHeart(); // subject

// ───────────────────────────────────────────────────────────────────────────
// Step 1. KYC provider issues a disclosable document about Alice.
// ───────────────────────────────────────────────────────────────────────────
const doc = createDisclosableDocument({
  issuerDid: kycProvider.did,
  issuerPublicKey: kycProvider.publicKey,
  issuerSigningKey: kycProvider.signingKey,
  subjectDid: alice.did,
  claims: {
    name: "Alice Chen",
    dob: "1990-04-15",
    country: "SG",
    "kyc-tier": 3,
  },
  expiresAt: Date.now() + 365 * 24 * 60 * 60 * 1000,
});
console.log("=== Step 1: KYC document issued ===");
console.log(`id           : ${doc.id}`);
console.log(`commitmentRoot: ${doc.commitmentRoot.slice(0, 32)}...`);
console.log(`claims held  : ${Object.keys(doc.claims).join(", ")}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 2. Alice verifies her own document is well-formed.
// ───────────────────────────────────────────────────────────────────────────
const selfCheck = verifyDisclosableDocument(doc);
console.log("\n=== Step 2: Alice verifies her document ===");
console.log(`valid        : ${selfCheck.valid}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 3. Alice presents to a service that only needs country + tier.
//   name + dob stay private.
// ───────────────────────────────────────────────────────────────────────────
const proof = createDisclosureProof(doc, ["country", "kyc-tier"]);
console.log("\n=== Step 3: Alice presents (country + kyc-tier only) ===");
console.log(`disclosed    : ${Object.keys(proof.disclosed).join(", ")}`);
console.log(`withheld     : ${Object.keys(proof.undisclosedCommitments).join(", ")}`);
console.log(`disclosed.country : ${JSON.stringify(proof.disclosed.country.value)}`);
console.log(`disclosed.tier    : ${JSON.stringify(proof.disclosed["kyc-tier"].value)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 4. Verifier checks the proof — re-derives root, verifies signature.
// ───────────────────────────────────────────────────────────────────────────
const verified = verifyDisclosureProof(proof, {
  requiredFields: ["country", "kyc-tier"],
});
console.log("\n=== Step 4: Verifier checks ===");
if (verified.valid) {
  console.log(`valid        : true`);
  console.log(`issuer       : ${verified.issuerDid.slice(0, 32)}...`);
  console.log(`subject      : ${verified.subjectDid.slice(0, 32)}...`);
  console.log(`disclosed    : ${JSON.stringify(verified.disclosed)}`);
} else {
  console.log(`valid        : false — ${verified.reason}`);
}

// ───────────────────────────────────────────────────────────────────────────
// Step 5. Alice tries to lie: swap her tier from 3 to 5 before presenting.
// ───────────────────────────────────────────────────────────────────────────
const cheated = createDisclosureProof(doc, ["country", "kyc-tier"]);
cheated.disclosed["kyc-tier"] = { value: 5, salt: cheated.disclosed["kyc-tier"].salt };
const cheatedResult = verifyDisclosureProof(cheated);
console.log("\n=== Step 5: Alice tampers tier 3 → 5 ===");
console.log(`result       : ${JSON.stringify(cheatedResult)}`);

// ───────────────────────────────────────────────────────────────────────────
// Step 6. Required-field enforcement — verifier wants a field Alice didn't reveal.
// ───────────────────────────────────────────────────────────────────────────
const onlyCountry = createDisclosureProof(doc, ["country"]);
const missing = verifyDisclosureProof(onlyCountry, {
  requiredFields: ["country", "kyc-tier"],
});
console.log("\n=== Step 6: Verifier requires kyc-tier, Alice revealed only country ===");
console.log(`result       : ${JSON.stringify(missing)}`);

console.log("\nDone.");
