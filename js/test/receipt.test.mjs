import test from "node:test";
import assert from "node:assert/strict";
import { createInitialKeyMaterial, privateKeyForRole } from "../src/crypto.mjs";
import {
  RECEIPT_SCHEMA,
  classifyIndependence,
  createReceipt,
  deriveReceiptId,
  summariseReceipts,
  verifyReceipt
} from "../src/receipt.mjs";

const CREATED_AT = "2026-07-28T00:00:00Z";

function party() {
  const material = createInitialKeyMaterial(CREATED_AT);
  const agentKey = material.publicIdentity.keys.find((key) => key.role === "agent_signing");
  return {
    did: material.publicIdentity.agent_did,
    publicKeyMultibase: agentKey.public_key_multibase,
    privateKeyBase64: privateKeyForRole(material.secretBundle, "agent_signing").private_key_pkcs8_base64
  };
}

function core(attester, subject, overrides = {}) {
  return {
    attester_did: attester.did,
    basis: "party",
    capability: "code-review",
    claim_hash: "a".repeat(64),
    domain: "software",
    fault: "none",
    issued_at: "2026-07-28T12:00:00Z",
    observed_at: "2026-07-28T11:00:00Z",
    outcome: "succeeded",
    schema_version: RECEIPT_SCHEMA,
    subject_did: subject.did,
    task_id: "task-1",
    ...overrides
  };
}

test("a verified receipt binds a named attester to another party's work", () => {
  const attester = party();
  const subject = party();

  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);
  const verified = verifyReceipt(receipt);

  assert.equal(verified.attester_did, attester.did);
  assert.equal(verified.subject_did, subject.did);
  assert.notEqual(verified.attester_did, verified.subject_did);
});

// This is the property the entire system rests on. A subject holds its own
// keys and can sign anything it likes; what it must not be able to do is
// produce a receipt about itself that verifies.
test("a subject cannot forge a receipt about itself, even holding its own keys", () => {
  const subject = party();

  assert.throws(
    () => createReceipt(core(subject, subject), subject.privateKeyBase64),
    (error) => error.code === "RECEIPT_SELF_ATTESTED",
    "a self-attested receipt must be rejected at construction"
  );

  // And the same claim assembled by hand, bypassing createReceipt entirely,
  // must still fail verification. Rejecting only in the constructor would be
  // an honour system.
  const selfCore = core(subject, subject);
  const forged = {
    ...selfCore,
    receipt_id: deriveReceiptId(selfCore),
    signature: createReceipt(core(subject, party()), subject.privateKeyBase64).signature
  };

  assert.throws(
    () => verifyReceipt(forged),
    (error) => error.code === "RECEIPT_SELF_ATTESTED",
    "a hand-assembled self-receipt must fail verification"
  );
});

test("a receipt signed by anyone other than its named attester fails", () => {
  const attester = party();
  const subject = party();
  const impostor = party();

  // The impostor signs a receipt that names the attester. The signature is
  // real; the attribution is a lie.
  const receipt = createReceipt(core(attester, subject), impostor.privateKeyBase64);

  assert.throws(
    () => verifyReceipt(receipt),
    (error) => error.code === "RECEIPT_SIGNATURE_INVALID"
  );
});

// The verifier derives the attester's key from attester_did rather than
// accepting one. An earlier revision took the key as a parameter, which meant a
// receipt naming Alice could be verified against Mallory's key if the caller
// supplied it — attribution, the only thing a receipt establishes, depended on
// the caller getting that right. It cannot be got wrong now.
test("a receipt cannot be verified against a key other than the one its DID commits to", () => {
  const impostor = party();
  const subject = party();

  // Impostor signs, then relabels the receipt as coming from a victim DID.
  const signed = createReceipt(core(impostor, subject), impostor.privateKeyBase64);
  const victim = party();
  const relabelled = { ...signed, attester_did: victim.did };

  assert.throws(
    () => verifyReceipt(relabelled),
    (error) => error.code === "RECEIPT_ID_MISMATCH" || error.code === "RECEIPT_SIGNATURE_INVALID",
    "a relabelled attester must not verify"
  );

  // Even with receipt_id recomputed so the relabelling is internally consistent,
  // the signature is checked against the key committed to by the new DID.
  const consistentCore = { ...core(impostor, subject), attester_did: victim.did };
  const laundered = {
    ...consistentCore,
    receipt_id: deriveReceiptId(consistentCore),
    signature: signed.signature
  };

  assert.throws(
    () => verifyReceipt(laundered),
    (error) => error.code === "RECEIPT_SIGNATURE_INVALID",
    "a self-consistent relabelling must still fail against the DID's committed key"
  );
});

test("a DID that does not commit to a key is refused outright", () => {
  const attester = party();
  const subject = party();
  const opaqueCore = { ...core(attester, subject), attester_did: "did:soma:opaque-identifier" };
  const receipt = {
    ...opaqueCore,
    receipt_id: deriveReceiptId(opaqueCore),
    signature: createReceipt(core(attester, subject), attester.privateKeyBase64).signature
  };

  assert.throws(
    () => verifyReceipt(receipt),
    (error) => error.code === "RECEIPT_DID_UNSUPPORTED",
    "an attester whose key cannot be recovered offline must be refused, not assumed"
  );
});

test("mutating any core field invalidates the receipt", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  const mutations = {
    outcome: "failed",
    capability: "database-migration",
    claim_hash: "b".repeat(64),
    task_id: "task-2",
    domain: "hardware",
    subject_did: party().did
  };

  for (const [field, value] of Object.entries(mutations)) {
    const tampered = { ...receipt, [field]: value };
    assert.throws(
      () => verifyReceipt(tampered),
      (error) => error.code === "RECEIPT_ID_MISMATCH" || error.code === "RECEIPT_FAULT_INCONSISTENT",
      `mutating ${field} was not detected`
    );
  }
});

test("receipt_id is derived, so a chosen one is rejected", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  assert.throws(
    () => verifyReceipt({ ...receipt, receipt_id: "c".repeat(64) }),
    (error) => error.code === "RECEIPT_ID_MISMATCH"
  );
});

test("a receipt cannot be observed after it was issued", () => {
  const attester = party();
  const subject = party();

  assert.throws(
    () => createReceipt(
      core(attester, subject, { observed_at: "2026-07-28T13:00:00Z", issued_at: "2026-07-28T12:00:00Z" }),
      attester.privateKeyBase64
    ),
    (error) => error.code === "RECEIPT_FIELD_INVALID"
  );
});

test("unknown and missing fields both fail closed", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  assert.throws(
    () => verifyReceipt({ ...receipt, priority: "high" }),
    (error) => error.code === "RECEIPT_SHAPE_INVALID"
  );

  const { task_id, ...missing } = receipt;
  assert.throws(
    () => verifyReceipt(missing),
    (error) => error.code === "RECEIPT_SHAPE_INVALID"
  );
});

test("only succeeded, failed and disputed are outcomes", () => {
  const attester = party();
  const subject = party();

  for (const outcome of ["succeeded", "failed", "disputed"]) {
    const fault = outcome === "succeeded" ? "none" : "unattributed";
    const receipt = createReceipt(core(attester, subject, { outcome, fault }), attester.privateKeyBase64);
    assert.equal(verifyReceipt(receipt).outcome, outcome);
  }

  assert.throws(
    () => createReceipt(core(attester, subject, { outcome: "excellent" }), attester.privateKeyBase64),
    (error) => error.code === "RECEIPT_OUTCOME_INVALID"
  );
});

test("independence is classified from lineage, not asserted", () => {
  assert.equal(classifyIndependence(["did:soma:x"], ["did:soma:x"]), "self");

  // A parent attesting to its child. Genuinely informative, not independent.
  assert.equal(
    classifyIndependence(["did:soma:root", "did:soma:parent"], ["did:soma:root", "did:soma:parent", "did:soma:child"]),
    "shared_lineage"
  );

  // Siblings under one root: the cheap Sybil shape.
  assert.equal(
    classifyIndependence(["did:soma:root", "did:soma:a"], ["did:soma:root", "did:soma:b"]),
    "shared_lineage"
  );

  assert.equal(
    classifyIndependence(["did:soma:root-a", "did:soma:a"], ["did:soma:root-b", "did:soma:b"]),
    "no_known_common_ancestor"
  );
});

test("a lineage Sybil cannot look independent no matter how deep it nests", () => {
  const root = "did:soma:operator";
  const subject = [root, "did:soma:worker"];

  // 500 descendants of the same root, at varying depths. Every one of them is
  // shared_lineage, so no amount of spawning manufactures independence.
  for (let index = 0; index < 500; index += 1) {
    const depth = (index % 5) + 1;
    const attester = [root, ...Array.from({ length: depth }, (_, level) => `did:soma:sub-${index}-${level}`)];
    assert.equal(classifyIndependence(attester, subject), "shared_lineage");
  }
});

test("a summary reports counts and refuses to produce a score", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  const entries = [{
    receipt,
    attester_lineage: ["did:soma:root-a", attester.did],
    subject_lineage: ["did:soma:root-b", subject.did]
  }];

  const blind = summariseReceipts(entries, []);
  assert.equal(blind.score, null, "the protocol must never emit a score");
  assert.equal(
    blind.basis,
    "insufficient",
    "an evaluator who trusts nobody must be told the system cannot tell them, not given a zero"
  );
  assert.equal(blind.by_outcome.succeeded, 1);
  assert.equal(blind.distinct_attesters, 1);

  const informed = summariseReceipts(entries, [attester.did]);
  assert.equal(informed.basis, "evaluator_trusted_attesters");
  assert.equal(informed.from_trusted_attesters, 1);
  assert.equal(informed.score, null, "still no score, even with a trusted attester");
});

test("manufactured attesters cannot raise a summary for an evaluator who does not trust them", () => {
  const subject = party();
  const entries = [];

  // 1,000 attesters conjured from nothing, each with its own root. The graph is
  // indistinguishable from 1,000 genuine strangers, which is exactly why the
  // protocol refuses to aggregate.
  for (let index = 0; index < 1000; index += 1) {
    const sybil = party();
    entries.push({
      receipt: createReceipt(core(sybil, subject), sybil.privateKeyBase64),
      attester_lineage: [`did:soma:sybil-root-${index}`, sybil.did],
      subject_lineage: ["did:soma:honest-root", subject.did]
    });
  }

  const summary = summariseReceipts(entries, []);
  assert.equal(summary.distinct_attesters, 1000);
  assert.equal(summary.by_outcome.succeeded, 1000);
  assert.equal(
    summary.basis,
    "insufficient",
    "a thousand strangers vouching is still no basis for an evaluator who trusts none of them"
  );
  assert.equal(summary.score, null);
});

// An earlier revision took the independence label as input. A label that can be
// passed in is a label that can be wrong, and whether an attester is related to
// the subject is the one thing worth lying about.
test("independence cannot be asserted by the caller", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  const sameRoot = {
    receipt,
    attester_lineage: ["did:soma:operator", attester.did],
    subject_lineage: ["did:soma:operator", subject.did],
    independence: "no_known_common_ancestor"
  };

  const summary = summariseReceipts([sameRoot], []);
  assert.equal(
    summary.by_independence.shared_lineage,
    1,
    "the computed label must win over anything the caller supplied"
  );
  assert.equal(summary.by_independence.no_known_common_ancestor, 0);
});

test("absent lineage is reported as unknown, not assumed unrelated", () => {
  const attester = party();
  const subject = party();
  const receipt = createReceipt(core(attester, subject), attester.privateKeyBase64);

  const summary = summariseReceipts([{ receipt }], []);
  assert.equal(summary.by_independence.unknown, 1);
  assert.equal(summary.by_independence.no_known_common_ancestor, 0);
});

// Outcome says what happened; fault says who it is attributable to. Conflating
// them means an agent that correctly reported a broken upstream API is recorded
// as having failed, and composed work — which is most agent work — becomes
// unreadable.
test("fault is separate from outcome, and the two must agree", () => {
  const attester = party();
  const subject = party();

  const upstream = createReceipt(
    core(attester, subject, { outcome: "failed", fault: "upstream_tool" }),
    attester.privateKeyBase64
  );
  assert.equal(verifyReceipt(upstream).fault, "upstream_tool");

  const delegated = createReceipt(
    core(attester, subject, { outcome: "failed", fault: "delegate" }),
    attester.privateKeyBase64
  );
  assert.equal(verifyReceipt(delegated).fault, "delegate");

  // A success cannot blame anyone.
  assert.throws(
    () => createReceipt(core(attester, subject, { outcome: "succeeded", fault: "subject" }), attester.privateKeyBase64),
    (e) => e.code === "RECEIPT_FAULT_INCONSISTENT"
  );

  // A failure cannot blame nobody. Where the attester genuinely cannot say,
  // that is `unattributed` — an explicit statement of ignorance, not silence.
  assert.throws(
    () => createReceipt(core(attester, subject, { outcome: "failed", fault: "none" }), attester.privateKeyBase64),
    (e) => e.code === "RECEIPT_FAULT_INCONSISTENT"
  );

  assert.throws(
    () => createReceipt(core(attester, subject, { outcome: "failed", fault: "the-weather" }), attester.privateKeyBase64),
    (e) => e.code === "RECEIPT_FAULT_INVALID"
  );
});

test("a summary counts fault separately from outcome", () => {
  const attester = party();
  const subject = party();

  const entries = [
    { receipt: createReceipt(core(attester, subject, { outcome: "failed", fault: "upstream_tool" }), attester.privateKeyBase64) },
    { receipt: createReceipt(core(attester, subject, { outcome: "failed", fault: "subject", task_id: "task-2" }), attester.privateKeyBase64) }
  ];

  const summary = summariseReceipts(entries, []);
  assert.equal(summary.by_outcome.failed, 2);
  assert.equal(summary.by_fault.upstream_tool, 1);
  assert.equal(summary.by_fault.subject, 1);
  // Two failures, but only one is the subject's. An evaluator reading only
  // by_outcome would treat these identically.
  assert.notEqual(summary.by_fault.subject, summary.by_outcome.failed);
});

// Agent Y saying "the data was good" and Vera saying "the data matches the
// source" are not the same claim. Only the second is falsifiable — anyone can
// redo the check. An evaluator that cannot tell them apart is treating an
// opinion as a measurement.
test("basis distinguishes a checkable claim from an opinion", () => {
  const counterparty = party();
  const verifier = party();
  const subject = party();

  const experience = createReceipt(
    core(counterparty, subject, { basis: "party" }),
    counterparty.privateKeyBase64
  );
  const verification = createReceipt(
    core(verifier, subject, { basis: "verified" }),
    verifier.privateKeyBase64
  );

  assert.equal(verifyReceipt(experience).basis, "party");
  assert.equal(verifyReceipt(verification).basis, "verified");

  const summary = summariseReceipts([{ receipt: experience }, { receipt: verification }], []);
  assert.equal(summary.by_basis.party, 1);
  assert.equal(summary.by_basis.verified, 1);

  assert.throws(
    () => createReceipt(core(counterparty, subject, { basis: "vibes" }), counterparty.privateKeyBase64),
    (e) => e.code === "RECEIPT_BASIS_INVALID"
  );
});

// A Vera host is not privileged. It is an ordinary identity whose attestations
// happen to be verificational, and its standing is at stake like anyone's.
// Nothing here makes it an adjudicator.
test("a verifying host is an ordinary attester, not an authority", () => {
  const host = party();
  const subject = party();

  const receipt = createReceipt(
    core(host, subject, { basis: "verified", outcome: "failed", fault: "subject" }),
    host.privateKeyBase64
  );
  const verified = verifyReceipt(receipt);

  assert.equal(verified.basis, "verified");
  assert.equal(verified.attester_did, host.did);

  // An evaluator who does not trust this host gets nothing from its verdict.
  const blind = summariseReceipts([{ receipt }], []);
  assert.equal(blind.basis, "insufficient", "a host's verification is not authoritative by being a host");
  assert.equal(blind.score, null);
});
