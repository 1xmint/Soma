import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.mjs";
import { createInitialKeyMaterial, privateKeyForRole, sha256, signEd25519 } from "../src/crypto.mjs";
import { RECEIPT_SCHEMA, createReceipt } from "../src/receipt.mjs";
import { detectEquivocation } from "../src/equivocation.mjs";
import {
  CONTRADICTION_KINDS,
  composeVouchingContradiction,
  verifyVouchingContradiction,
  vouchingDiscounts
} from "../src/vouching-proof.mjs";

const HEAD_ID_DOMAIN = "soma:evidence-head:provisional-v1";
const HEAD_SIGNATURE_DOMAIN = "soma:evidence-head:signature:provisional-v1";
const CREATED_AT = "2026-07-28T00:00:00Z";

/**
 * A party, exposing both the agent identity a receipt names and the controller
 * key that signs evidence heads.
 *
 * The tests below use the CONTROLLER did as the receipt subject, because that
 * is the only case where the composite binds without a third document. See the
 * key-binding gap documented in vouching-proof.mjs -- against stock artifacts,
 * where receipts name the agent DID and heads are controller-signed, this
 * composes to null, and one of these tests pins exactly that.
 */
function party() {
  const material = createInitialKeyMaterial(CREATED_AT);
  const agentKey = material.publicIdentity.keys.find((k) => k.role === "agent_signing");
  const controllerKey = material.publicIdentity.keys.find((k) => k.role === "controller_signing");
  return {
    agentDid: material.publicIdentity.agent_did,
    controllerDid: controllerKey.key_id.slice(0, controllerKey.key_id.indexOf("#")),
    controllerKeyId: controllerKey.key_id,
    agentPrivate: privateKeyForRole(material.secretBundle, "agent_signing").private_key_pkcs8_base64,
    controllerPrivate: privateKeyForRole(material.secretBundle, "controller_signing")
      .private_key_pkcs8_base64,
    agentKeyId: agentKey.key_id
  };
}

function head(who, sequence, entryHash) {
  const core = {
    schema_version: "soma.evidence-head.provisional-v1",
    anchors: [],
    assurance: "local_only_unanchored",
    entry_count: sequence + 1,
    entry_hash: entryHash,
    issued_at: "2026-08-03T12:00:00.000Z",
    sequence,
    signer_key_id: who.controllerKeyId
  };
  const headHash = sha256(Buffer.from(`${HEAD_ID_DOMAIN}\n${canonicalize(core)}`, "utf8"));
  const preimage = Buffer.concat([
    Buffer.from(`${HEAD_SIGNATURE_DOMAIN}\n`, "utf8"),
    Buffer.from(headHash, "hex")
  ]);
  return {
    ...core,
    head_hash: headHash,
    signature: {
      key_id: who.controllerKeyId,
      suite: "Ed25519-v1",
      value: signEd25519(who.controllerPrivate, preimage)
    }
  };
}

function vouch(attester, subjectDid, overrides = {}) {
  return createReceipt(
    {
      attester_did: attester.agentDid,
      basis: "verified",
      capability: "code-review",
      claim_hash: "a".repeat(64),
      domain: "software",
      fault: "none",
      issued_at: "2026-07-28T12:00:00Z",
      observed_at: "2026-07-28T11:00:00Z",
      outcome: "succeeded",
      schema_version: RECEIPT_SCHEMA,
      subject_did: subjectDid,
      task_id: "task-1",
      ...overrides
    },
    attester.agentPrivate
  );
}

function equivocationOf(who) {
  const a = head(who, 7, "b".repeat(64));
  const b = head(who, 7, "c".repeat(64));
  const proof = detectEquivocation(a, b);
  assert.ok(proof, "fixture should produce a genuine equivocation");
  return proof;
}

test("a vouch for a proven equivocator composes into a checkable contradiction", () => {
  const attester = party();
  const subject = party();
  const proof = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid),
    equivocationProof: equivocationOf(subject)
  });

  assert.ok(proof, "the pair should compose");
  assert.equal(proof.kind, CONTRADICTION_KINDS.SUBJECT_EQUIVOCATION);
  assert.equal(proof.attester_did, attester.agentDid);
  assert.equal(proof.subject_did, subject.controllerDid);
  assert.match(proof.proof_id, /^[a-f0-9]{64}$/);
});

test("the composite carries no signature of its own", () => {
  const attester = party();
  const subject = party();
  const proof = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid),
    equivocationProof: equivocationOf(subject)
  });
  // Both halves are already self-authenticating. A signature would introduce a
  // signer whose honesty mattered, and that signer would be an adjudicator.
  assert.ok(!("signature" in proof), "a composite must not need anyone to be believed");
});

test("a stranger can re-check it from scratch", () => {
  const attester = party();
  const subject = party();
  const built = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid),
    equivocationProof: equivocationOf(subject)
  });
  const roundTripped = JSON.parse(JSON.stringify(built));
  const verified = verifyVouchingContradiction(roundTripped);
  assert.equal(verified.attester_did, attester.agentDid);
  assert.equal(verified.subject_did, subject.controllerDid);
});

test("a composite whose identifier was tampered with is refused", () => {
  const attester = party();
  const subject = party();
  const built = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid),
    equivocationProof: equivocationOf(subject)
  });
  const tampered = { ...built, attester_did: party().agentDid };
  assert.throws(() => verifyVouchingContradiction(tampered), /misnames|misstates/);
});

test("a vouch for a DIFFERENT party does not compose", () => {
  const attester = party();
  const subject = party();
  const innocent = party();
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, innocent.controllerDid),
    equivocationProof: equivocationOf(subject)
  });
  assert.equal(composed, null, "an unrelated vouch must never become an accusation");
});

test("recording a FAILURE against a party who later equivocates costs the attester nothing", () => {
  // The attester was right. Charging them would invert the incentive exactly,
  // and would punish the reporting this system depends on.
  const attester = party();
  const subject = party();
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid, { outcome: "failed", fault: "subject" }),
    equivocationProof: equivocationOf(subject)
  });
  assert.equal(composed, null);
});

test("the stock artifact shapes do NOT bind, and that is recorded rather than hidden", () => {
  // Receipts conventionally name the agent DID; heads are controller-signed.
  // This is the key-binding gap. If this test ever starts failing, the gap has
  // been closed and the documentation in vouching-proof.mjs must be updated.
  const attester = party();
  const subject = party();
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.agentDid),
    equivocationProof: equivocationOf(subject)
  });
  assert.equal(
    composed,
    null,
    "the key-binding gap appears to be closed — update the module documentation"
  );
});

test("discounts compound with repeated contradictions", () => {
  const attester = party();
  const s1 = party();
  const s2 = party();
  const proofs = [
    composeVouchingContradiction({
      receipt: vouch(attester, s1.controllerDid),
      equivocationProof: equivocationOf(s1)
    }),
    composeVouchingContradiction({
      receipt: vouch(attester, s2.controllerDid, { task_id: "task-2" }),
      equivocationProof: equivocationOf(s2)
    })
  ];
  const discounts = vouchingDiscounts(proofs);
  assert.ok(Math.abs(discounts.get(attester.agentDid) - 0.25) < 1e-9, "two contradictions should compound");
});

test("replaying one genuine proof cannot be used to destroy an attester", () => {
  const attester = party();
  const subject = party();
  const proof = composeVouchingContradiction({
    receipt: vouch(attester, subject.controllerDid),
    equivocationProof: equivocationOf(subject)
  });
  const once = vouchingDiscounts([proof]).get(attester.agentDid);
  const spammed = vouchingDiscounts(Array.from({ length: 50 }, () => proof)).get(attester.agentDid);
  assert.equal(spammed, once, "a replayed proof counted more than once — this is a weapon, not a bond");
});

test("the discount has a floor, so 'known to have been wrong' stays distinct from 'unknown'", () => {
  const attester = party();
  const subjects = Array.from({ length: 30 }, () => party());
  const proofs = subjects.map((s, i) =>
    composeVouchingContradiction({
      receipt: vouch(attester, s.controllerDid, { task_id: `task-${i}` }),
      equivocationProof: equivocationOf(s)
    })
  );
  const discount = vouchingDiscounts(proofs).get(attester.agentDid);
  assert.ok(discount > 0, "an attester driven to exactly zero is indistinguishable from a stranger");
});

test("an accusation that does not hold is thrown, never returned as a weaker one", () => {
  assert.throws(() => verifyVouchingContradiction(null), /shape is invalid/);
  assert.throws(() => verifyVouchingContradiction({ schema_version: "nope" }), /shape is invalid/);
});
