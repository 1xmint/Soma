import test from "node:test";
import assert from "node:assert/strict";
import { createInitialKeyMaterial, privateKeyForRole } from "../src/crypto.mjs";
import { RECEIPT_SCHEMA, createReceipt } from "../src/receipt.mjs";
import {
  DISCLOSURE_SCHEMA,
  createMethodDisclosure,
  disclosureIndex,
  methodContradicted,
  verifyMethodDisclosure
} from "../src/method-disclosure.mjs";

const CREATED_AT = "2026-07-28T00:00:00Z";

function party() {
  const material = createInitialKeyMaterial(CREATED_AT);
  return {
    did: material.publicIdentity.agent_did,
    privateKeyBase64: privateKeyForRole(material.secretBundle, "agent_signing").private_key_pkcs8_base64
  };
}

function receiptFor(attester, subject) {
  return createReceipt(
    {
      attester_did: attester.did,
      basis: "verified",
      capability: "code-review",
      claim_hash: "a".repeat(64),
      domain: "software",
      fault: "none",
      issued_at: "2026-07-28T12:00:00Z",
      observed_at: "2026-07-28T11:00:00Z",
      outcome: "succeeded",
      schema_version: RECEIPT_SCHEMA,
      subject_did: subject.did,
      task_id: "task-1"
    },
    attester.privateKeyBase64
  );
}

function disclosureFor(attester, receipt, overrides = {}) {
  return createMethodDisclosure(
    {
      attester_did: attester.did,
      inputs_hash: "b".repeat(64),
      method: "re-ran-test-suite",
      receipt_id: receipt.receipt_id,
      result_hash: "c".repeat(64),
      schema_version: DISCLOSURE_SCHEMA,
      ...overrides
    },
    attester.privateKeyBase64
  );
}

test("a disclosure verifies against the key its attester DID commits to", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = disclosureFor(attester, receipt);
  assert.equal(verifyMethodDisclosure(disclosure), disclosure);
  assert.match(disclosure.disclosure_id, /^[a-f0-9]{64}$/);
});

test("the identifier is derived, so it cannot be chosen", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = disclosureFor(attester, receipt);
  const tampered = { ...disclosure, disclosure_id: "d".repeat(64) };
  assert.throws(() => verifyMethodDisclosure(tampered), /does not match its contents/);
});

test("altering the method after signing breaks the disclosure", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = disclosureFor(attester, receipt);
  const tampered = { ...disclosure, method: "trust-me" };
  assert.throws(() => verifyMethodDisclosure(tampered), /does not match its contents/);
});

test("an unknown field is refused rather than ignored", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = { ...disclosureFor(attester, receipt), extra: "smuggled" };
  assert.throws(() => verifyMethodDisclosure(disclosure), /must carry exactly/);
});

test("a method name outside the vocabulary shape is refused", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  assert.throws(
    () => disclosureFor(attester, receipt, { method: "Re Ran The Suite" }),
    /lowercase dash-separated/
  );
});

test("nobody can disclose a method for somebody else's receipt", () => {
  // Otherwise anyone could attach a flattering or damning method to a receipt
  // they had nothing to do with, and the record would say whatever its loudest
  // reader wanted.
  const attester = party();
  const impostor = party();
  const receipt = receiptFor(attester, party());
  const forged = disclosureFor(impostor, receipt);

  const byId = new Map([[receipt.receipt_id, receipt]]);
  assert.throws(() => disclosureIndex([forged], byId), /someone other than the receipt's attester/);
});

test("a re-run that matches contradicts nothing", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = disclosureFor(attester, receipt);
  assert.equal(methodContradicted(disclosure, "c".repeat(64)), null);
});

test("a re-run that differs produces a contradiction naming the attester", () => {
  const attester = party();
  const receipt = receiptFor(attester, party());
  const disclosure = disclosureFor(attester, receipt);
  const contradiction = methodContradicted(disclosure, "e".repeat(64));

  assert.ok(contradiction);
  assert.equal(contradiction.attester_did, attester.did);
  assert.equal(contradiction.receipt_id, receipt.receipt_id);
  assert.equal(contradiction.committed_result_hash, "c".repeat(64));
  assert.equal(contradiction.observed_result_hash, "e".repeat(64));
});

test("a method contradiction states that it is reproducible, not self-authenticating", () => {
  // This is weaker than an equivocation proof and the difference must not be
  // blurred: somebody has to actually re-run the method for it to hold.
  const attester = party();
  const receipt = receiptFor(attester, party());
  const contradiction = methodContradicted(disclosureFor(attester, receipt), "e".repeat(64));
  assert.match(contradiction.truth_claim, /reproducible rather than self-authenticating/);
});

test("disclosures index by the receipt they describe", () => {
  const attester = party();
  const r1 = receiptFor(attester, party());
  const r2 = receiptFor(attester, party());
  const index = disclosureIndex([
    disclosureFor(attester, r1),
    disclosureFor(attester, r2, { method: "recomputed-hash" })
  ]);
  assert.equal(index.size, 2);
  assert.equal(index.get(r1.receipt_id).method, "re-ran-test-suite");
  assert.equal(index.get(r2.receipt_id).method, "recomputed-hash");
});
