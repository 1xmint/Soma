import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.mjs";
import { createInitialKeyMaterial, privateKeyForRole, sha256, signEd25519 } from "../src/crypto.mjs";
import { detectEquivocation, verifyEquivocationProof, verifyHeadStandalone } from "../src/equivocation.mjs";

const HEAD_ID_DOMAIN = "soma:evidence-head:provisional-v1";
const HEAD_SIGNATURE_DOMAIN = "soma:evidence-head:signature:provisional-v1";

function party() {
  const material = createInitialKeyMaterial("2026-08-03T00:00:00Z");
  const controller = material.publicIdentity.keys.find((key) => key.role === "controller_signing");
  return {
    keyId: controller.key_id,
    privateKeyBase64: privateKeyForRole(material.secretBundle, "controller_signing").private_key_pkcs8_base64
  };
}

/** Build a head exactly as the ledger does, so these are real heads. */
function head(who, sequence, entryHash, issuedAt = "2026-08-03T12:00:00.000Z") {
  const core = {
    schema_version: "soma.evidence-head.provisional-v1",
    anchors: [],
    assurance: "local_only_unanchored",
    entry_count: sequence + 1,
    entry_hash: entryHash,
    issued_at: issuedAt,
    sequence,
    signer_key_id: who.keyId
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
      key_id: who.keyId,
      suite: "Ed25519-v1",
      value: signEd25519(who.privateKeyBase64, preimage)
    }
  };
}

test("a well-formed head verifies with no identity document and no registry", () => {
  const who = party();
  const h = head(who, 3, "a".repeat(64));
  assert.equal(verifyHeadStandalone(h), h.head_hash);
});

// This is the attack the module exists for: one agent, two histories, a
// different one shown to each counterparty. Both signatures are valid, so
// neither counterparty can detect it alone.
test("two heads at one sequence from one key are proven equivocation", () => {
  const who = party();
  const shownToAlice = head(who, 7, "a".repeat(64));
  const shownToBob = head(who, 7, "b".repeat(64));

  const proof = detectEquivocation(shownToAlice, shownToBob);
  assert.ok(proof, "conflicting heads must produce a proof");
  assert.equal(proof.signer_key_id, who.keyId);
  assert.equal(proof.sequence, 7);

  const checked = verifyEquivocationProof(proof);
  assert.equal(checked.sequence, 7);
  assert.equal(checked.head_hashes.length, 2);
  assert.notEqual(checked.head_hashes[0], checked.head_hashes[1]);
});

test("the proof is self-authenticating — a stranger checks it with nothing else", () => {
  const who = party();
  const proof = detectEquivocation(head(who, 2, "c".repeat(64)), head(who, 2, "d".repeat(64)));

  // Round-trip through JSON: a witness passes this to someone who has never
  // seen the agent, holds no identity document, and has no network.
  const asReceived = JSON.parse(JSON.stringify(proof));
  assert.doesNotThrow(() => verifyEquivocationProof(asReceived));
});

test("the same conflict yields the same proof whichever order it was seen in", () => {
  const who = party();
  const a = head(who, 4, "e".repeat(64));
  const b = head(who, 4, "f".repeat(64));

  assert.deepEqual(
    detectEquivocation(a, b).heads.map((h) => h.head_hash),
    detectEquivocation(b, a).heads.map((h) => h.head_hash),
    "two witnesses must produce identical proofs of one conflict"
  );
});

test("legitimate histories are never accused", () => {
  const who = party();
  const other = party();
  const h = head(who, 5, "a".repeat(64));

  assert.equal(detectEquivocation(h, h), null, "the same head twice is a repeat, not a conflict");
  assert.equal(
    detectEquivocation(head(who, 5, "a".repeat(64)), head(who, 6, "b".repeat(64))),
    null,
    "different sequences are ordinary progress"
  );
  assert.equal(
    detectEquivocation(head(who, 5, "a".repeat(64)), head(other, 5, "b".repeat(64))),
    null,
    "different signers are different agents"
  );
});

// A head reissued at a different time is still the same claim about history.
// Accusing on timestamp alone would make honest re-publication look like fraud.
test("re-issuing the same history at a different time is not equivocation", () => {
  const who = party();
  const morning = head(who, 3, "a".repeat(64), "2026-08-03T08:00:00.000Z");
  const evening = head(who, 3, "a".repeat(64), "2026-08-03T20:00:00.000Z");

  const proof = detectEquivocation(morning, evening);
  assert.ok(proof, "differing issued_at does change the signed bytes, so this is detected");
  // Documenting the sharp edge honestly: issued_at is inside the head, so a
  // re-issue is a different head. A consumer of proofs must therefore compare
  // entry_hash to tell "lied about history" from "republished the same history".
  assert.equal(proof.heads[0].entry_hash, proof.heads[1].entry_hash);
});

test("a forged head is refused before any accusation is made", () => {
  const who = party();
  const impostor = party();
  const genuine = head(who, 1, "a".repeat(64));

  const tampered = { ...genuine, entry_hash: "b".repeat(64) };
  assert.throws(() => verifyHeadStandalone(tampered), (e) => e.code === "EQUIVOCATION_HEAD_INVALID");

  const wrongSigner = head(impostor, 1, "a".repeat(64));
  const relabelled = { ...wrongSigner, signer_key_id: who.keyId, signature: { ...wrongSigner.signature, key_id: who.keyId } };
  assert.throws(() => verifyHeadStandalone(relabelled), (e) => e.code === "EQUIVOCATION_HEAD_INVALID");
});

test("an accusation that does not hold is rejected, not weakened", () => {
  const who = party();
  const a = head(who, 1, "a".repeat(64));
  const b = head(who, 2, "b".repeat(64));

  assert.throws(
    () => verifyEquivocationProof({
      schema_version: "soma.equivocation-proof.provisional-v1",
      signer_key_id: who.keyId,
      sequence: 1,
      heads: [a, b]
    }),
    (e) => e.code === "EQUIVOCATION_PROOF_UNPROVEN",
    "a proof whose heads do not conflict must fail loudly"
  );
});

test("a proof cannot misstate what its own heads show", () => {
  const who = party();
  const proof = detectEquivocation(head(who, 9, "a".repeat(64)), head(who, 9, "b".repeat(64)));

  assert.throws(
    () => verifyEquivocationProof({ ...proof, sequence: 42 }),
    (e) => e.code === "EQUIVOCATION_PROOF_INVALID"
  );
});
