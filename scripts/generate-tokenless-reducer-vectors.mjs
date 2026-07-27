import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "./lib/canonicalize.mjs";
import {
  bindTokenlessState,
  emptyBalancesRoot,
  encodeTokenlessTransaction,
  evaluateTokenlessBlock,
  pilotPublicCommitmentId,
  tokenlessBlockId,
  tokenlessBlockResultRoot,
  tokenlessTransactionId,
  tokenlessTransactionSignatureMessage,
  validateTokenlessState
} from "./lib/tokenless-reducer.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, Buffer.alloc(32, 0x42)]),
  format: "der",
  type: "pkcs8"
});
const publicKey = createPublicKey(privateKey)
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");

function sha256(label) {
  return createHash("sha256").update(label, "utf8").digest("hex");
}

function signTransaction(fields) {
  const transaction = {
    schema_version: "somavera.tokenless-transaction.v1",
    profile_status: "pilot_only_not_ratified",
    ...fields,
    transaction_id: "0".repeat(64),
    signature: { suite: "Ed25519-v1", value: Buffer.alloc(64).toString("base64") }
  };
  transaction.transaction_id = tokenlessTransactionId(transaction);
  transaction.signature.value = sign(
    null,
    tokenlessTransactionSignatureMessage(transaction.transaction_id),
    privateKey
  ).toString("base64");
  return transaction;
}

function makeBlock(state, height, consensusTime, transactions) {
  const block = {
    $schema: "../schemas/tokenless-reducer-block.schema.json",
    schema_version: "somavera.tokenless-block.v1",
    profile_status: "pilot_only_not_ratified",
    network_lineage_id: state.network_lineage_id,
    execution_context_id: state.execution_context_id,
    height,
    consensus_time_ms: consensusTime,
    prior_app_hash: state.app_hash,
    transactions: transactions.map(encodeTokenlessTransaction),
    block_id: "0".repeat(64)
  };
  block.block_id = tokenlessBlockId(block);
  return block;
}

function accept(state, block) {
  const evaluated = evaluateTokenlessBlock(state, block);
  if (!evaluated.accepted) {
    throw new Error(`generated fixture rejected: ${evaluated.error.code}`);
  }
  return evaluated;
}

async function writeJson(relative, value) {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, JSON.stringify(value, null, 2) + "\n", "utf8");
}

const actorDid = "did:example:somavera-pilot-alice";
const actorKeyId = actorDid + "#ledger-key-1";
const networkLineageId = "somavera:network:v1:" + sha256("somavera tokenless reducer test network");
const executionContextId = "somavera:context:v1:" + sha256("somavera tokenless reducer test context");
const initialTime = 1798761600000n;

const initialState = bindTokenlessState({
  $schema: "../schemas/tokenless-reducer-state.schema.json",
  schema_version: "somavera.tokenless-reducer-state.v1",
  profile_status: "pilot_only_not_ratified",
  network_lineage_id: networkLineageId,
  execution_context_id: executionContextId,
  context_epoch: 0,
  ledger_audience: "somavera:ledger:pilot-v1",
  height: "0",
  last_consensus_time_ms: initialTime.toString(),
  maximum_block_time_advance_ms: "60000",
  origin_hash: sha256("synthetic origin capsule; not a ratified release"),
  protocol_release_hash: sha256("synthetic reducer protocol release; not ratified"),
  last_block_id: sha256("synthetic height zero predecessor"),
  last_block_result_root: tokenlessBlockResultRoot([]),
  authorized_keys: [{
    actor_did: actorDid,
    key_id: actorKeyId,
    purpose: "pilot_ledger_signing",
    suite: "Ed25519-v1",
    public_key_base64: publicKey,
    valid_from_ms: (initialTime - 86400000n).toString(),
    valid_until_ms: (initialTime + 86400000n).toString(),
    status: "active"
  }],
  actor_sequences: [{ actor_did: actorDid, next_sequence: "0" }],
  consumed_transaction_ids: [],
  consumed_nonces: [],
  public_commitments: [],
  balances: [],
  balances_root: emptyBalancesRoot(),
  token: {
    activated: false,
    activation_core_hash: null,
    asset_lineage_id: null,
    live_supply_grain: "0",
    lifetime_minted_grain: "0",
    lifetime_burned_grain: "0"
  },
  state_root: "0".repeat(64),
  app_hash: "0".repeat(64)
});
validateTokenlessState(initialState);

const registerPayload = {
  object_id: "0".repeat(64),
  content_hash: sha256("synthetic encrypted contribution commitment"),
  license_hash: sha256("synthetic consent and license terms"),
  source_event_id: sha256("synthetic source event")
};
registerPayload.object_id = pilotPublicCommitmentId(actorDid, registerPayload);

const register = signTransaction({
  network_lineage_id: networkLineageId,
  execution_context_id: executionContextId,
  actor_did: actorDid,
  actor_key_id: actorKeyId,
  sequence: "0",
  audience: initialState.ledger_audience,
  action: "pilot.public-commitment.register",
  nonce: sha256("register nonce").slice(0, 32),
  issued_at_ms: (initialTime + 1n).toString(),
  expires_at_ms: (initialTime + 60000n).toString(),
  payload: registerPayload
});

const block1 = makeBlock(initialState, "1", (initialTime + 1000n).toString(), [register]);
const accepted1 = accept(initialState, block1);
const block2 = makeBlock(accepted1.state, "2", (initialTime + 2000n).toString(), []);
const accepted2 = accept(accepted1.state, block2);

const tombstone = signTransaction({
  network_lineage_id: networkLineageId,
  execution_context_id: executionContextId,
  actor_did: actorDid,
  actor_key_id: actorKeyId,
  sequence: "1",
  audience: initialState.ledger_audience,
  action: "pilot.public-commitment.tombstone",
  nonce: sha256("tombstone nonce").slice(0, 32),
  issued_at_ms: (initialTime + 2001n).toString(),
  expires_at_ms: (initialTime + 62000n).toString(),
  payload: {
    object_id: registerPayload.object_id,
    reason: "owner_withdrawal"
  }
});
const block3 = makeBlock(accepted2.state, "3", (initialTime + 3000n).toString(), [tombstone]);
const accepted3 = accept(accepted2.state, block3);

const vector = {
  schema_version: "somavera.tokenless-reducer-conformance.v1",
  profile_status: "synthetic_test_only_not_ratified",
  description: "Deterministic register, empty-block, and owner-tombstone replay.",
  public_key_base64: publicKey,
  initial_state: initialState,
  steps: [
    { name: "register", block: block1, expected_result: accepted1.result, expected_state: accepted1.state },
    { name: "empty_block", block: block2, expected_result: accepted2.result, expected_state: accepted2.state },
    { name: "owner_tombstone", block: block3, expected_result: accepted3.result, expected_state: accepted3.state }
  ],
  transaction_projections: [
    {
      name: "register",
      transaction: register,
      canonical_transaction_utf8: canonicalize(register),
      encoded_transaction_base64: encodeTokenlessTransaction(register),
      signature_message_hex: tokenlessTransactionSignatureMessage(register.transaction_id).toString("hex")
    },
    {
      name: "owner_tombstone",
      transaction: tombstone,
      canonical_transaction_utf8: canonicalize(tombstone),
      encoded_transaction_base64: encodeTokenlessTransaction(tombstone),
      signature_message_hex: tokenlessTransactionSignatureMessage(tombstone.transaction_id).toString("hex")
    }
  ]
};

const invalid = {
  schema_version: "somavera.tokenless-reducer-invalid-cases.v1",
  profile_status: "synthetic_test_only_not_ratified",
  cases: [
    ["noncanonical_transaction_bytes", "TRANSACTION_CANONICAL_BYTES_INVALID"],
    ["schema_locator_in_consensus_bytes", "TRANSACTION_SCHEMA_LOCATOR_FORBIDDEN"],
    ["noncanonical_base64", "TRANSACTION_BASE64_INVALID"],
    ["invalid_utf8", "TRANSACTION_UTF8_INVALID"],
    ["invalid_json", "TRANSACTION_JSON_INVALID"],
    ["wrong_network", "TRANSACTION_NETWORK_MISMATCH"],
    ["wrong_context", "TRANSACTION_CONTEXT_MISMATCH"],
    ["wrong_audience", "TRANSACTION_AUDIENCE_MISMATCH"],
    ["wrong_transaction_id", "TRANSACTION_ID_MISMATCH"],
    ["bad_signature", "TRANSACTION_SIGNATURE_INVALID"],
    ["stale_sequence", "TRANSACTION_SEQUENCE_MISMATCH"],
    ["replayed_transaction", "TRANSACTION_REPLAY"],
    ["reused_nonce", "TRANSACTION_NONCE_REUSE"],
    ["unknown_action", "TRANSACTION_ACTION_UNSUPPORTED"],
    ["wrong_object_id", "PUBLIC_COMMITMENT_ID_INVALID"],
    ["duplicate_object", "PUBLIC_COMMITMENT_EXISTS"],
    ["missing_object", "PUBLIC_COMMITMENT_NOT_FOUND"],
    ["missing_key", "TRANSACTION_KEY_ACTOR_MISMATCH"],
    ["retired_key", "TRANSACTION_KEY_NOT_ACTIVE"],
    ["revoked_key", "TRANSACTION_KEY_NOT_ACTIVE"],
    ["out_of_window_key", "TRANSACTION_KEY_WINDOW_INVALID"],
    ["actor_key_mismatch", "TRANSACTION_KEY_ACTOR_MISMATCH"],
    ["skipped_sequence", "TRANSACTION_SEQUENCE_MISMATCH"],
    ["wrong_owner", "PUBLIC_COMMITMENT_OWNER_MISMATCH"],
    ["second_tombstone", "PUBLIC_COMMITMENT_ALREADY_TOMBSTONED"],
    ["unknown_field", "TRANSACTION_SHAPE_INVALID"],
    ["oversized_transaction", "TRANSACTION_BASE64_INVALID"],
    ["invalid_prior_key_purpose", "STATE_KEY_INVALID"],
    ["wrong_block_network", "BLOCK_NETWORK_MISMATCH"],
    ["wrong_block_context", "BLOCK_CONTEXT_MISMATCH"],
    ["wrong_block_height", "BLOCK_HEIGHT_MISMATCH"],
    ["wrong_prior_app_hash", "BLOCK_PRIOR_APP_HASH_MISMATCH"],
    ["wrong_block_time", "BLOCK_TIME_INVALID"],
    ["wrong_block_id", "BLOCK_ID_MISMATCH"],
    ["too_many_transactions", "BLOCK_TRANSACTION_COUNT_INVALID"]
  ].map(([name, expected_code]) => ({ name, expected_code }))
};

await writeJson("conformance/tokenless-reducer-v1.json", vector);
await writeJson("conformance/tokenless-reducer-invalid-v1.json", invalid);
await writeJson("examples/tokenless-reducer-state.example.json", initialState);
await writeJson("examples/tokenless-reducer-transaction.example.json", {
  $schema: "../schemas/tokenless-reducer-transaction.schema.json",
  ...register
});
await writeJson("examples/tokenless-reducer-block.example.json", block1);
await writeJson("examples/tokenless-reducer-block-result.example.json", accepted1.result);

console.log(
  `Tokenless reducer vectors generated: ${vector.steps.length} accepted blocks, ` +
  `${invalid.cases.length} declared adversarial cases.`
);
