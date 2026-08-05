import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.mjs";
import { createInitialKeyMaterial, privateKeyForRole, sha256, signEd25519 } from "../src/crypto.mjs";
import { RECEIPT_SCHEMA, createReceipt } from "../src/receipt.mjs";
import { detectEquivocation } from "../src/equivocation.mjs";
import { createKeyLinkage } from "../src/key-linkage.mjs";
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
 * Two bindings are exercised below. Where the receipt names the CONTROLLER did,
 * the composite binds on exact equality with no third artifact. Where it names
 * the agent DID -- the stock shape -- binding requires a mutual key-linkage
 * record, and the tests cover both that it works and that it cannot be forged,
 * stripped, or borrowed from a stranger.
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

/** The party's own two keys, each signing that the pair is one party. */
function linkageFor(who) {
  return createKeyLinkage({
    keyIdA: who.controllerKeyId,
    privateKeyA: who.controllerPrivate,
    keyIdB: who.agentKeyId,
    privateKeyB: who.agentPrivate
  });
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

test("stock artifact shapes do not bind on their own", () => {
  // Receipts name the agent DID; heads are controller-signed. Without a
  // linkage there is nothing honest connecting them, and the composite must
  // refuse rather than guess.
  const attester = party();
  const subject = party();
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.agentDid),
    equivocationProof: equivocationOf(subject)
  });
  assert.equal(composed, null, "an unbound pair must never become an accusation");
});

test("a mutual key linkage binds the stock shapes, and M2 bites", () => {
  const attester = party();
  const subject = party();
  const linkage = linkageFor(subject);

  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.agentDid),
    equivocationProof: equivocationOf(subject),
    linkages: [linkage]
  });

  assert.ok(composed, "a mutually signed linkage should bind agent DID to controller key");
  assert.equal(composed.attester_did, attester.agentDid);
  assert.equal(composed.subject_did, subject.agentDid);
  assert.deepEqual(composed.linkage_ids, [linkage.linkage_id]);
});

test("a composite commits to the linkage it relied on, so it cannot be stripped", () => {
  const attester = party();
  const subject = party();
  const linkage = linkageFor(subject);
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.agentDid),
    equivocationProof: equivocationOf(subject),
    linkages: [linkage]
  });

  const stripped = { ...composed, linkages: [] };
  assert.throws(
    () => verifyVouchingContradiction(stripped),
    /do not compose/,
    "an accusation whose binding was removed must not still verify"
  );
});

test("someone else's linkage cannot bind you to an equivocator", () => {
  const attester = party();
  const subject = party();
  const unrelated = party();
  const composed = composeVouchingContradiction({
    receipt: vouch(attester, subject.agentDid),
    equivocationProof: equivocationOf(subject),
    linkages: [linkageFor(unrelated)]
  });
  assert.equal(composed, null, "an unrelated linkage bound two strangers together");
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
