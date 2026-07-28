import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "./canonicalize.mjs";
import {
  bindTokenlessState,
  decodeTokenlessTransaction,
  encodeTokenlessTransaction,
  evaluateTokenlessBlock,
  tokenlessBlockId,
  tokenlessTransactionId,
  tokenlessTransactionSignatureMessage,
  validateTokenlessState
} from "./tokenless-reducer.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, Buffer.alloc(32, 0x42)]),
  format: "der",
  type: "pkcs8"
});
const secondPrivateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, Buffer.alloc(32, 0x24)]),
  format: "der",
  type: "pkcs8"
});
const secondPublicKey = createPublicKey(secondPrivateKey)
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");
let checks = 0;

function assert(condition, message) {
  if (!condition) throw new Error(`tokenless reducer conformance failed: ${message}`);
  checks += 1;
}

function exact(left, right, message) {
  assert(canonicalize(left) === canonicalize(right), message);
}

async function json(relative) {
  return JSON.parse(await readFile(path.join(root, relative), "utf8"));
}

function signedTransaction(base, mutate, { preserveId = false, signingKey = privateKey } = {}) {
  const transaction = structuredClone(base);
  mutate(transaction);
  if (!preserveId) transaction.transaction_id = tokenlessTransactionId(transaction);
  transaction.signature.value = sign(
    null,
    tokenlessTransactionSignatureMessage(transaction.transaction_id),
    signingKey
  ).toString("base64");
  return transaction;
}

function blockFor(state, transactions, mutate = () => {}) {
  const block = {
    $schema: "../schemas/tokenless-reducer-block.schema.json",
    schema_version: "somavera.tokenless-block.v1",
    profile_status: "pilot_only_not_ratified",
    network_lineage_id: state.network_lineage_id,
    execution_context_id: state.execution_context_id,
    height: (BigInt(state.height) + 1n).toString(),
    consensus_time_ms: (BigInt(state.last_consensus_time_ms) + 1000n).toString(),
    prior_app_hash: state.app_hash,
    transactions: transactions.map((entry) =>
      typeof entry === "string" ? entry : encodeTokenlessTransaction(entry)
    ),
    block_id: "0".repeat(64)
  };
  mutate(block);
  block.block_id = tokenlessBlockId(block);
  return block;
}

function rejectCase(name, state, block, expectedCode) {
  const before = canonicalize(state);
  const evaluated = evaluateTokenlessBlock(state, block);
  assert(evaluated.accepted === false, `${name} was accepted`);
  assert(evaluated.error.code === expectedCode,
    `${name} returned ${evaluated.error.code}, expected ${expectedCode}`);
  assert(canonicalize(evaluated.state) === before, `${name} was not atomic`);
  assert(canonicalize(state) === before, `${name} mutated its input state`);
  return { name, expected_code: expectedCode };
}

const vector = await json("conformance/tokenless-reducer-v1.json");
const declaredInvalid = await json("conformance/tokenless-reducer-invalid-v1.json");
assert(vector.schema_version === "somavera.tokenless-reducer-conformance.v1", "vector profile mismatch");
assert(vector.profile_status === "synthetic_test_only_not_ratified", "vector status mismatch");
assert(declaredInvalid.profile_status === "synthetic_test_only_not_ratified", "invalid-vector status mismatch");

let state = structuredClone(vector.initial_state);
validateTokenlessState(state);
checks += 1;
const states = [structuredClone(state)];
for (const step of vector.steps) {
  const before = canonicalize(state);
  const first = evaluateTokenlessBlock(state, step.block);
  const second = evaluateTokenlessBlock(state, step.block);
  assert(first.accepted && second.accepted, `${step.name} was not accepted twice`);
  exact(first, second, `${step.name} was nondeterministic`);
  exact(first.result, step.expected_result, `${step.name} result differs`);
  exact(first.state, step.expected_state, `${step.name} state differs`);
  assert(canonicalize(state) === before, `${step.name} mutated its input`);
  assert(first.state.token.activated === false, `${step.name} activated the token`);
  assert(first.state.balances.length === 0, `${step.name} created a balance`);
  state = first.state;
  states.push(structuredClone(state));
}

for (const projection of vector.transaction_projections) {
  const encoded = encodeTokenlessTransaction(projection.transaction);
  assert(encoded === projection.encoded_transaction_base64, `${projection.name} encoded bytes differ`);
  assert(Buffer.from(encoded, "base64").toString("utf8") === projection.canonical_transaction_utf8,
    `${projection.name} canonical UTF-8 differs`);
  assert(
    tokenlessTransactionSignatureMessage(projection.transaction.transaction_id).toString("hex") ===
      projection.signature_message_hex,
    `${projection.name} signature projection differs`
  );
  exact(decodeTokenlessTransaction(encoded), projection.transaction,
    `${projection.name} decode differs`);
}

const initial = states[0];
const afterRegister = states[1];
const register = vector.transaction_projections[0].transaction;
const tombstone = vector.transaction_projections[1].transaction;
const observed = [];

const canonicalRegister = Buffer.from(encodeTokenlessTransaction(register), "base64").toString("utf8");
observed.push(rejectCase(
  "noncanonical_transaction_bytes",
  initial,
  blockFor(initial, [Buffer.from(canonicalRegister + "\n", "utf8").toString("base64")]),
  "TRANSACTION_CANONICAL_BYTES_INVALID"
));
observed.push(rejectCase(
  "schema_locator_in_consensus_bytes",
  initial,
  blockFor(initial, [Buffer.from(canonicalize({ ...register, $schema: "forbidden" })).toString("base64")]),
  "TRANSACTION_SCHEMA_LOCATOR_FORBIDDEN"
));
observed.push(rejectCase(
  "noncanonical_base64",
  initial,
  blockFor(initial, [encodeTokenlessTransaction(register) + "="]),
  "TRANSACTION_BASE64_INVALID"
));
observed.push(rejectCase(
  "invalid_utf8",
  initial,
  blockFor(initial, [Buffer.from([0xff]).toString("base64")]),
  "TRANSACTION_UTF8_INVALID"
));
observed.push(rejectCase(
  "invalid_json",
  initial,
  blockFor(initial, [Buffer.from("{", "utf8").toString("base64")]),
  "TRANSACTION_JSON_INVALID"
));

const wrongNetwork = signedTransaction(register, (tx) => {
  tx.network_lineage_id = "somavera:network:v1:" + "f".repeat(64);
});
observed.push(rejectCase(
  "wrong_network", initial, blockFor(initial, [wrongNetwork]), "TRANSACTION_NETWORK_MISMATCH"
));
const wrongContext = signedTransaction(register, (tx) => {
  tx.execution_context_id = "somavera:context:v1:" + "f".repeat(64);
});
observed.push(rejectCase(
  "wrong_context", initial, blockFor(initial, [wrongContext]), "TRANSACTION_CONTEXT_MISMATCH"
));
const wrongAudience = signedTransaction(register, (tx) => {
  tx.audience = "somavera:ledger:wrong-v1";
});
observed.push(rejectCase(
  "wrong_audience", initial, blockFor(initial, [wrongAudience]), "TRANSACTION_AUDIENCE_MISMATCH"
));
const wrongId = signedTransaction(register, (tx) => {
  tx.transaction_id = "f".repeat(64);
}, { preserveId: true });
observed.push(rejectCase(
  "wrong_transaction_id", initial, blockFor(initial, [wrongId]), "TRANSACTION_ID_MISMATCH"
));
const badSignature = structuredClone(register);
badSignature.signature.value =
  Buffer.from(badSignature.signature.value, "base64")
    .map((byte, index) => index === 0 ? byte ^ 1 : byte)
    .toString("base64");
observed.push(rejectCase(
  "bad_signature", initial, blockFor(initial, [badSignature]), "TRANSACTION_SIGNATURE_INVALID"
));
const staleSequence = signedTransaction(register, (tx) => { tx.sequence = "1"; });
observed.push(rejectCase(
  "stale_sequence", initial, blockFor(initial, [staleSequence]), "TRANSACTION_SEQUENCE_MISMATCH"
));
observed.push(rejectCase(
  "replayed_transaction", afterRegister, blockFor(afterRegister, [register]), "TRANSACTION_REPLAY"
));
const reusedNonce = signedTransaction(register, (tx) => {
  tx.sequence = "1";
  tx.payload.content_hash = "e".repeat(64);
  tx.payload.object_id = "e".repeat(64);
});
observed.push(rejectCase(
  "reused_nonce", afterRegister, blockFor(afterRegister, [reusedNonce]), "TRANSACTION_NONCE_REUSE"
));
const unknownAction = signedTransaction(register, (tx) => {
  tx.action = "pilot.unknown";
  tx.payload = {};
});
observed.push(rejectCase(
  "unknown_action",
  initial,
  blockFor(initial, [Buffer.from(canonicalize(unknownAction), "utf8").toString("base64")]),
  "TRANSACTION_ACTION_UNSUPPORTED"
));
const wrongObjectId = signedTransaction(register, (tx) => {
  tx.payload.object_id = "f".repeat(64);
});
observed.push(rejectCase(
  "wrong_object_id", initial, blockFor(initial, [wrongObjectId]), "PUBLIC_COMMITMENT_ID_INVALID"
));
const duplicateObject = signedTransaction(register, (tx) => {
  tx.sequence = "1";
  tx.nonce = "d".repeat(32);
});
observed.push(rejectCase(
  "duplicate_object", afterRegister, blockFor(afterRegister, [duplicateObject]), "PUBLIC_COMMITMENT_EXISTS"
));
const missingObject = signedTransaction(tombstone, (tx) => {
  tx.sequence = "0";
  tx.issued_at_ms = (BigInt(initial.last_consensus_time_ms) + 1n).toString();
  tx.expires_at_ms = (BigInt(initial.last_consensus_time_ms) + 60000n).toString();
  tx.payload.object_id = "f".repeat(64);
});
observed.push(rejectCase(
  "missing_object", initial, blockFor(initial, [missingObject]), "PUBLIC_COMMITMENT_NOT_FOUND"
));

const missingKey = signedTransaction(register, (tx) => {
  tx.actor_key_id = tx.actor_did + "#missing";
});
observed.push(rejectCase(
  "missing_key", initial, blockFor(initial, [missingKey]), "TRANSACTION_KEY_ACTOR_MISMATCH"
));
const retiredState = bindTokenlessState({
  ...structuredClone(initial),
  authorized_keys: initial.authorized_keys.map((key) => ({ ...key, status: "retired" }))
});
observed.push(rejectCase(
  "retired_key", retiredState, blockFor(retiredState, [register]), "TRANSACTION_KEY_NOT_ACTIVE"
));
const revokedState = bindTokenlessState({
  ...structuredClone(initial),
  authorized_keys: initial.authorized_keys.map((key) => ({ ...key, status: "revoked" }))
});
observed.push(rejectCase(
  "revoked_key", revokedState, blockFor(revokedState, [register]), "TRANSACTION_KEY_NOT_ACTIVE"
));
const outOfWindowState = bindTokenlessState({
  ...structuredClone(initial),
  authorized_keys: initial.authorized_keys.map((key) => ({
    ...key,
    valid_until_ms: (BigInt(initial.last_consensus_time_ms) + 500n).toString()
  }))
});
observed.push(rejectCase(
  "out_of_window_key",
  outOfWindowState,
  blockFor(outOfWindowState, [register]),
  "TRANSACTION_KEY_WINDOW_INVALID"
));

const secondActorDid = "did:example:somavera-pilot-bob";
const secondActorKeyId = secondActorDid + "#ledger-key-1";
const twoActorState = bindTokenlessState({
  ...structuredClone(afterRegister),
  authorized_keys: [
    ...afterRegister.authorized_keys,
    {
      actor_did: secondActorDid,
      key_id: secondActorKeyId,
      purpose: "pilot_ledger_signing",
      suite: "Ed25519-v1",
      public_key_base64: secondPublicKey,
      valid_from_ms: initial.authorized_keys[0].valid_from_ms,
      valid_until_ms: initial.authorized_keys[0].valid_until_ms,
      status: "active"
    }
  ].sort((left, right) => left.key_id < right.key_id ? -1 : left.key_id > right.key_id ? 1 : 0),
  actor_sequences: [
    ...afterRegister.actor_sequences,
    { actor_did: secondActorDid, next_sequence: "0" }
  ].sort((left, right) =>
    left.actor_did < right.actor_did ? -1 : left.actor_did > right.actor_did ? 1 : 0
  )
});
validateTokenlessState(twoActorState);
checks += 1;

const actorKeyMismatch = signedTransaction(register, (tx) => {
  tx.actor_key_id = secondActorKeyId;
  tx.sequence = "1";
}, { signingKey: secondPrivateKey });
observed.push(rejectCase(
  "actor_key_mismatch",
  twoActorState,
  blockFor(twoActorState, [actorKeyMismatch]),
  "TRANSACTION_KEY_ACTOR_MISMATCH"
));
const skippedSequence = signedTransaction(register, (tx) => { tx.sequence = "2"; });
observed.push(rejectCase(
  "skipped_sequence", initial, blockFor(initial, [skippedSequence]), "TRANSACTION_SEQUENCE_MISMATCH"
));
const wrongOwner = signedTransaction(tombstone, (tx) => {
  tx.actor_did = secondActorDid;
  tx.actor_key_id = secondActorKeyId;
  tx.sequence = "0";
  tx.nonce = "b".repeat(32);
  tx.issued_at_ms = (BigInt(afterRegister.last_consensus_time_ms) + 1n).toString();
  tx.expires_at_ms = (BigInt(afterRegister.last_consensus_time_ms) + 60000n).toString();
}, { signingKey: secondPrivateKey });
observed.push(rejectCase(
  "wrong_owner", twoActorState, blockFor(twoActorState, [wrongOwner]), "PUBLIC_COMMITMENT_OWNER_MISMATCH"
));
const afterTombstone = states[3];
const secondTombstone = signedTransaction(tombstone, (tx) => {
  tx.sequence = "2";
  tx.nonce = "c".repeat(32);
  tx.issued_at_ms = (BigInt(afterTombstone.last_consensus_time_ms) + 1n).toString();
  tx.expires_at_ms = (BigInt(afterTombstone.last_consensus_time_ms) + 60000n).toString();
});
observed.push(rejectCase(
  "second_tombstone",
  afterTombstone,
  blockFor(afterTombstone, [secondTombstone]),
  "PUBLIC_COMMITMENT_ALREADY_TOMBSTONED"
));
const unknownField = { ...register, unexpected: true };
observed.push(rejectCase(
  "unknown_field",
  initial,
  blockFor(initial, [Buffer.from(canonicalize(unknownField), "utf8").toString("base64")]),
  "TRANSACTION_SHAPE_INVALID"
));
observed.push(rejectCase(
  "oversized_transaction",
  initial,
  blockFor(initial, [Buffer.alloc(65537, 0x20).toString("base64")]),
  "TRANSACTION_BASE64_INVALID"
));
const invalidPurposeState = bindTokenlessState({
  ...structuredClone(initial),
  authorized_keys: initial.authorized_keys.map((key) => ({
    ...key,
    purpose: "not_a_ledger_signing_purpose"
  }))
});
observed.push(rejectCase(
  "invalid_prior_key_purpose",
  invalidPurposeState,
  blockFor(invalidPurposeState, []),
  "STATE_KEY_INVALID"
));

observed.push(rejectCase(
  "wrong_block_network",
  initial,
  blockFor(initial, [], (block) => {
    block.network_lineage_id = "somavera:network:v1:" + "f".repeat(64);
  }),
  "BLOCK_NETWORK_MISMATCH"
));
observed.push(rejectCase(
  "wrong_block_context",
  initial,
  blockFor(initial, [], (block) => {
    block.execution_context_id = "somavera:context:v1:" + "f".repeat(64);
  }),
  "BLOCK_CONTEXT_MISMATCH"
));
observed.push(rejectCase(
  "wrong_block_height",
  initial,
  blockFor(initial, [], (block) => { block.height = "2"; }),
  "BLOCK_HEIGHT_MISMATCH"
));
observed.push(rejectCase(
  "wrong_prior_app_hash",
  initial,
  blockFor(initial, [], (block) => { block.prior_app_hash = "f".repeat(64); }),
  "BLOCK_PRIOR_APP_HASH_MISMATCH"
));
observed.push(rejectCase(
  "wrong_block_time",
  initial,
  blockFor(initial, [], (block) => { block.consensus_time_ms = initial.last_consensus_time_ms; }),
  "BLOCK_TIME_INVALID"
));
const wrongBlockId = blockFor(initial, []);
wrongBlockId.block_id = "f".repeat(64);
observed.push(rejectCase("wrong_block_id", initial, wrongBlockId, "BLOCK_ID_MISMATCH"));
observed.push(rejectCase(
  "too_many_transactions",
  initial,
  blockFor(initial, Array.from({ length: 257 }, () => encodeTokenlessTransaction(register))),
  "BLOCK_TRANSACTION_COUNT_INVALID"
));

exact(observed, declaredInvalid.cases, "declared adversarial corpus differs from executed corpus");

const atomicBlock = blockFor(initial, [register, register]);
const atomicFailure = evaluateTokenlessBlock(initial, atomicBlock);
assert(atomicFailure.accepted === false, "multi-transaction failure was accepted");
assert(atomicFailure.error.transaction_index === 1, "multi-transaction failure index differs");
assert(atomicFailure.error.code === "TRANSACTION_REPLAY", "multi-transaction failure code differs");
exact(atomicFailure.state, initial, "multi-transaction failure committed a prefix");

console.log(
  `Tokenless reducer checks passed: ${checks} assertions, ${vector.steps.length} replay steps, ` +
  `${observed.length} declared adversarial cases, and atomic-prefix rejection.`
);
