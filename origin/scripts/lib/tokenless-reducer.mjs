import { createHash, createPublicKey, verify } from "node:crypto";
import { TextDecoder } from "node:util";
import { canonicalize } from "./canonicalize.mjs";

const D = Object.freeze({
  state: "somavera:tokenless-state:v1\n",
  app: "somavera:tokenless-app-hash:v1\n",
  transaction: "somavera:tokenless-transaction:v1\n",
  transactionSignature: "somavera:tokenless-transaction-signature:v1\n",
  nonce: "somavera:tokenless-nonce-key:v1\n",
  object: "somavera:pilot-public-commitment:v1\n",
  block: "somavera:tokenless-block:v1\n",
  result: "somavera:tokenless-block-results:v1\n",
  effect: "somavera:tokenless-state-change:v1\n",
  emptyBalances: "somavera:tokenless-empty-balances:v1\n"
});

const PROFILE = "pilot_only_not_ratified";
const MAX_TRANSACTION_BYTES = 65536;
const MAX_TRANSACTIONS = 256;
const HASH = /^[a-f0-9]{64}$/;
const UINT = /^(0|[1-9][0-9]*)$/;
const DID = /^did:[a-z0-9]+:.+$/;
const NONCE = /^[a-f0-9]{32,128}$/;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const STATE_FIELDS = [
  "schema_version", "profile_status", "network_lineage_id", "execution_context_id",
  "context_epoch", "ledger_audience", "height", "last_consensus_time_ms",
  "maximum_block_time_advance_ms", "origin_hash", "protocol_release_hash",
  "last_block_id", "last_block_result_root", "authorized_keys", "actor_sequences",
  "consumed_transaction_ids", "consumed_nonces", "public_commitments", "balances",
  "balances_root", "token", "state_root", "app_hash"
];
const TRANSACTION_FIELDS = [
  "schema_version", "profile_status", "network_lineage_id", "execution_context_id",
  "transaction_id", "actor_did", "actor_key_id", "sequence", "audience", "action",
  "nonce", "issued_at_ms", "expires_at_ms", "payload", "signature"
];
const BLOCK_FIELDS = [
  "schema_version", "profile_status", "network_lineage_id", "execution_context_id",
  "height", "consensus_time_ms", "prior_app_hash", "transactions", "block_id"
];

export class TokenlessReducerError extends Error {
  constructor(code) {
    super(code);
    this.name = "TokenlessReducerError";
    this.code = code;
  }
}

function reject(code) {
  throw new TokenlessReducerError(code);
}

function digest(domain, value) {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(typeof value === "string" ? value : canonicalize(value), "utf8")
    .digest("hex");
}

function digestBytes(parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function exactObject(value, fields, code, allowSchema = true) {
  if (!value || typeof value !== "object" || Array.isArray(value)) reject(code);
  const expected = allowSchema ? [...fields, "$schema"].sort() : [...fields].sort();
  const actual = Object.keys(value).sort();
  if (actual.length !== fields.length && !(allowSchema && actual.length === fields.length + 1)) {
    reject(code);
  }
  const selected = actual.includes("$schema") ? expected : [...fields].sort();
  if (actual.length !== selected.length ||
      actual.some((entry, index) => entry !== selected[index])) reject(code);
}

function exactKeys(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) reject(code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length ||
      actual.some((entry, index) => entry !== expected[index])) reject(code);
}

function uint(value, code) {
  if (typeof value !== "string" || !UINT.test(value)) reject(code);
  return BigInt(value);
}

function hash(value, code) {
  if (typeof value !== "string" || !HASH.test(value)) reject(code);
  return value;
}

function canonicalBase64(value, bytes, code) {
  if (typeof value !== "string") reject(code);
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== bytes || decoded.toString("base64") !== value) reject(code);
  return decoded;
}

function sortedUnique(values, key, code) {
  const keys = values.map((entry) => key(entry));
  if (new Set(keys).size !== keys.length) reject(code);
  const sorted = [...keys].sort();
  if (keys.some((entry, index) => entry !== sorted[index])) reject(code);
}

function stateCore(state) {
  return Object.fromEntries(
    Object.entries(state).filter(([name]) => !["$schema", "state_root", "app_hash"].includes(name))
  );
}

function transactionCore(transaction) {
  return Object.fromEntries(
    Object.entries(transaction).filter(([name]) => !["$schema", "transaction_id", "signature"].includes(name))
  );
}

function blockCore(block) {
  return Object.fromEntries(
    Object.entries(block).filter(([name]) => !["$schema", "block_id"].includes(name))
  );
}

export function emptyBalancesRoot() {
  return createHash("sha256").update(D.emptyBalances, "utf8").digest("hex");
}

export function tokenlessStateRoot(state) {
  return digest(D.state, stateCore(state));
}

export function tokenlessAppHash(stateRoot) {
  hash(stateRoot, "STATE_ROOT_INVALID");
  return digestBytes([Buffer.from(D.app, "utf8"), Buffer.from(stateRoot, "hex")]);
}

export function tokenlessTransactionId(transaction) {
  return digest(D.transaction, transactionCore(transaction));
}

export function tokenlessTransactionSignatureMessage(transactionId) {
  hash(transactionId, "TRANSACTION_ID_INVALID");
  return Buffer.concat([
    Buffer.from(D.transactionSignature, "utf8"),
    Buffer.from(transactionId, "hex")
  ]);
}

export function tokenlessNonceKey(transaction) {
  return digest(D.nonce, {
    network_lineage_id: transaction.network_lineage_id,
    execution_context_id: transaction.execution_context_id,
    actor_did: transaction.actor_did,
    actor_key_id: transaction.actor_key_id,
    audience: transaction.audience,
    action: transaction.action,
    nonce: transaction.nonce
  });
}

export function pilotPublicCommitmentId(actorDid, payload) {
  return digest(D.object, {
    owner_did: actorDid,
    content_hash: payload.content_hash,
    license_hash: payload.license_hash,
    source_event_id: payload.source_event_id
  });
}

export function tokenlessBlockId(block) {
  return digest(D.block, blockCore(block));
}

export function tokenlessBlockResultRoot(transactionResults) {
  return digest(D.result, transactionResults);
}

export function bindTokenlessState(state) {
  const value = structuredClone(state);
  value.state_root = tokenlessStateRoot(value);
  value.app_hash = tokenlessAppHash(value.state_root);
  return value;
}

function validateToken(token) {
  exactKeys(token, [
    "activated", "activation_core_hash", "asset_lineage_id", "live_supply_grain",
    "lifetime_minted_grain", "lifetime_burned_grain"
  ], "STATE_TOKEN_SHAPE_INVALID");
  if (token.activated !== false || token.activation_core_hash !== null ||
      token.asset_lineage_id !== null || token.live_supply_grain !== "0" ||
      token.lifetime_minted_grain !== "0" || token.lifetime_burned_grain !== "0") {
    reject("STATE_TOKEN_NOT_ZERO");
  }
}

export function validateTokenlessState(state) {
  exactObject(state, STATE_FIELDS, "STATE_SHAPE_INVALID");
  if (state.schema_version !== "somavera.tokenless-reducer-state.v1" ||
      state.profile_status !== PROFILE) reject("STATE_PROFILE_INVALID");
  if (!/^somavera:network:v1:[a-f0-9]{64}$/.test(state.network_lineage_id || "") ||
      !/^somavera:context:v1:[a-f0-9]{64}$/.test(state.execution_context_id || "") ||
      !/^somavera:ledger:[a-z0-9][a-z0-9._-]{2,127}$/.test(state.ledger_audience || "")) {
    reject("STATE_DOMAIN_INVALID");
  }
  if (!Number.isSafeInteger(state.context_epoch) || state.context_epoch < 0) {
    reject("STATE_CONTEXT_EPOCH_INVALID");
  }
  const stateHeight = uint(state.height, "STATE_HEIGHT_INVALID");
  uint(state.last_consensus_time_ms, "STATE_TIME_INVALID");
  if (uint(state.maximum_block_time_advance_ms, "STATE_TIME_ADVANCE_INVALID") === 0n) {
    reject("STATE_TIME_ADVANCE_INVALID");
  }
  for (const field of [
    "origin_hash", "protocol_release_hash", "last_block_id", "last_block_result_root",
    "balances_root", "state_root", "app_hash"
  ]) hash(state[field], "STATE_HASH_INVALID");
  if (!Array.isArray(state.authorized_keys) || !Array.isArray(state.actor_sequences) ||
      !Array.isArray(state.consumed_transaction_ids) || !Array.isArray(state.consumed_nonces) ||
      !Array.isArray(state.public_commitments) || !Array.isArray(state.balances)) {
    reject("STATE_COLLECTION_INVALID");
  }
  if (state.authorized_keys.length < 1 || state.authorized_keys.length > 10000 ||
      state.actor_sequences.length < 1 || state.actor_sequences.length > 10000) {
    reject("STATE_COLLECTION_INVALID");
  }
  if (state.balances.length !== 0 || state.balances_root !== emptyBalancesRoot()) {
    reject("STATE_BALANCES_NOT_EMPTY");
  }
  validateToken(state.token);

  sortedUnique(state.authorized_keys, (entry) => entry.key_id, "STATE_KEY_ORDER_INVALID");
  for (const key of state.authorized_keys) {
    exactKeys(key, [
      "actor_did", "key_id", "purpose", "suite", "public_key_base64",
      "valid_from_ms", "valid_until_ms", "status"
    ], "STATE_KEY_SHAPE_INVALID");
    if (!DID.test(key.actor_did || "") || typeof key.key_id !== "string" ||
        key.key_id.length < 3 || key.key_id.length > 512 ||
        key.purpose !== "pilot_ledger_signing" || key.suite !== "Ed25519-v1" ||
        !["active", "retired", "revoked"].includes(key.status)) reject("STATE_KEY_INVALID");
    canonicalBase64(key.public_key_base64, 32, "STATE_KEY_INVALID");
    if (uint(key.valid_from_ms, "STATE_KEY_WINDOW_INVALID") >=
        uint(key.valid_until_ms, "STATE_KEY_WINDOW_INVALID")) reject("STATE_KEY_WINDOW_INVALID");
  }

  sortedUnique(state.actor_sequences, (entry) => entry.actor_did, "STATE_SEQUENCE_ORDER_INVALID");
  for (const sequence of state.actor_sequences) {
    exactKeys(sequence, ["actor_did", "next_sequence"], "STATE_SEQUENCE_SHAPE_INVALID");
    if (!DID.test(sequence.actor_did || "")) reject("STATE_SEQUENCE_INVALID");
    uint(sequence.next_sequence, "STATE_SEQUENCE_INVALID");
  }
  const sequenceActors = new Set(state.actor_sequences.map((entry) => entry.actor_did));
  if (state.authorized_keys.some((entry) => !sequenceActors.has(entry.actor_did))) {
    reject("STATE_SEQUENCE_MISSING");
  }

  sortedUnique(state.consumed_transaction_ids, (entry) => entry, "STATE_TRANSACTION_ORDER_INVALID");
  state.consumed_transaction_ids.forEach((entry) => hash(entry, "STATE_TRANSACTION_ID_INVALID"));
  sortedUnique(state.consumed_nonces, (entry) => entry.nonce_key, "STATE_NONCE_ORDER_INVALID");
  for (const nonce of state.consumed_nonces) {
    exactKeys(nonce, ["nonce_key", "transaction_id"], "STATE_NONCE_SHAPE_INVALID");
    hash(nonce.nonce_key, "STATE_NONCE_INVALID");
    hash(nonce.transaction_id, "STATE_NONCE_INVALID");
  }
  const consumedTransactionSet = new Set(state.consumed_transaction_ids);
  const nonceTransactionIds = state.consumed_nonces.map((entry) => entry.transaction_id);
  if (new Set(nonceTransactionIds).size !== nonceTransactionIds.length ||
      nonceTransactionIds.length !== consumedTransactionSet.size ||
      nonceTransactionIds.some((entry) => !consumedTransactionSet.has(entry))) {
    reject("STATE_NONCE_TRANSACTION_INVALID");
  }

  sortedUnique(state.public_commitments, (entry) => entry.object_id, "STATE_OBJECT_ORDER_INVALID");
  for (const object of state.public_commitments) {
    exactKeys(object, [
      "object_id", "owner_did", "content_hash", "license_hash", "source_event_id",
      "registered_height", "status", "tombstone_event_id", "tombstone_reason",
      "tombstoned_height"
    ], "STATE_OBJECT_SHAPE_INVALID");
    for (const field of ["object_id", "content_hash", "license_hash", "source_event_id"]) {
      hash(object[field], "STATE_OBJECT_INVALID");
    }
    if (!DID.test(object.owner_did || "")) reject("STATE_OBJECT_INVALID");
    const registeredHeight = uint(object.registered_height, "STATE_OBJECT_INVALID");
    if (registeredHeight > stateHeight || !sequenceActors.has(object.owner_did)) {
      reject("STATE_OBJECT_HEIGHT_OR_OWNER_INVALID");
    }
    if (object.status === "active") {
      if (object.tombstone_event_id !== null || object.tombstone_reason !== null ||
          object.tombstoned_height !== null) reject("STATE_OBJECT_LIFECYCLE_INVALID");
    } else if (object.status === "tombstoned") {
      hash(object.tombstone_event_id, "STATE_OBJECT_LIFECYCLE_INVALID");
      if (!["owner_withdrawal", "superseded", "invalid_fixture"].includes(object.tombstone_reason) ||
          object.tombstoned_height === null) reject("STATE_OBJECT_LIFECYCLE_INVALID");
      const tombstonedHeight = uint(object.tombstoned_height, "STATE_OBJECT_LIFECYCLE_INVALID");
      if (tombstonedHeight < registeredHeight || tombstonedHeight > stateHeight ||
          !consumedTransactionSet.has(object.tombstone_event_id)) {
        reject("STATE_OBJECT_LIFECYCLE_INVALID");
      }
    } else {
      reject("STATE_OBJECT_LIFECYCLE_INVALID");
    }
  }

  if (state.state_root !== tokenlessStateRoot(state) ||
      state.app_hash !== tokenlessAppHash(state.state_root)) reject("STATE_ROOT_INVALID");
  return true;
}

function validateTransactionShape(transaction) {
  exactObject(transaction, TRANSACTION_FIELDS, "TRANSACTION_SHAPE_INVALID", false);
  if (transaction.schema_version !== "somavera.tokenless-transaction.v1" ||
      transaction.profile_status !== PROFILE) reject("TRANSACTION_PROFILE_INVALID");
  if (!/^somavera:network:v1:[a-f0-9]{64}$/.test(transaction.network_lineage_id || "") ||
      !/^somavera:context:v1:[a-f0-9]{64}$/.test(transaction.execution_context_id || "") ||
      !DID.test(transaction.actor_did || "") ||
      typeof transaction.actor_key_id !== "string" || transaction.actor_key_id.length < 3 ||
      transaction.actor_key_id.length > 512 ||
      !/^somavera:ledger:[a-z0-9][a-z0-9._-]{2,127}$/.test(transaction.audience || "") ||
      !NONCE.test(transaction.nonce || "")) reject("TRANSACTION_FIELD_INVALID");
  hash(transaction.transaction_id, "TRANSACTION_ID_INVALID");
  uint(transaction.sequence, "TRANSACTION_SEQUENCE_INVALID");
  uint(transaction.issued_at_ms, "TRANSACTION_TIME_INVALID");
  uint(transaction.expires_at_ms, "TRANSACTION_TIME_INVALID");
  exactKeys(transaction.signature, ["suite", "value"], "TRANSACTION_SIGNATURE_SHAPE_INVALID");
  if (transaction.signature.suite !== "Ed25519-v1") reject("TRANSACTION_SIGNATURE_SUITE_INVALID");
  canonicalBase64(transaction.signature.value, 64, "TRANSACTION_SIGNATURE_INVALID");

  if (transaction.action === "pilot.public-commitment.register") {
    exactKeys(transaction.payload, [
      "object_id", "content_hash", "license_hash", "source_event_id"
    ], "TRANSACTION_PAYLOAD_SHAPE_INVALID");
    for (const field of ["object_id", "content_hash", "license_hash", "source_event_id"]) {
      hash(transaction.payload[field], "TRANSACTION_PAYLOAD_INVALID");
    }
  } else if (transaction.action === "pilot.public-commitment.tombstone") {
    exactKeys(transaction.payload, ["object_id", "reason"], "TRANSACTION_PAYLOAD_SHAPE_INVALID");
    hash(transaction.payload.object_id, "TRANSACTION_PAYLOAD_INVALID");
    if (!["owner_withdrawal", "superseded", "invalid_fixture"].includes(transaction.payload.reason)) {
      reject("TRANSACTION_PAYLOAD_INVALID");
    }
  } else {
    reject("TRANSACTION_ACTION_UNSUPPORTED");
  }
}

export function decodeTokenlessTransaction(encoded) {
  if (typeof encoded !== "string") reject("TRANSACTION_BASE64_INVALID");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length === 0 || bytes.length > MAX_TRANSACTION_BYTES ||
      bytes.toString("base64") !== encoded) reject("TRANSACTION_BASE64_INVALID");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    reject("TRANSACTION_UTF8_INVALID");
  }
  let transaction;
  try {
    transaction = JSON.parse(text);
  } catch {
    reject("TRANSACTION_JSON_INVALID");
  }
  if (transaction && Object.prototype.hasOwnProperty.call(transaction, "$schema")) {
    reject("TRANSACTION_SCHEMA_LOCATOR_FORBIDDEN");
  }
  try {
    if (canonicalize(transaction) !== text) reject("TRANSACTION_CANONICAL_BYTES_INVALID");
  } catch (error) {
    if (error instanceof TokenlessReducerError) throw error;
    reject("TRANSACTION_CANONICAL_BYTES_INVALID");
  }
  validateTransactionShape(transaction);
  return transaction;
}

export function encodeTokenlessTransaction(transaction) {
  const value = structuredClone(transaction);
  delete value.$schema;
  validateTransactionShape(value);
  return Buffer.from(canonicalize(value), "utf8").toString("base64");
}

function verifyTransactionAgainstState(state, transaction, consensusTime) {
  if (transaction.network_lineage_id !== state.network_lineage_id) reject("TRANSACTION_NETWORK_MISMATCH");
  if (transaction.execution_context_id !== state.execution_context_id) reject("TRANSACTION_CONTEXT_MISMATCH");
  if (transaction.audience !== state.ledger_audience) reject("TRANSACTION_AUDIENCE_MISMATCH");
  if (transaction.transaction_id !== tokenlessTransactionId(transaction)) reject("TRANSACTION_ID_MISMATCH");
  if (state.consumed_transaction_ids.includes(transaction.transaction_id)) reject("TRANSACTION_REPLAY");

  const nonceKey = tokenlessNonceKey(transaction);
  if (state.consumed_nonces.some((entry) => entry.nonce_key === nonceKey)) reject("TRANSACTION_NONCE_REUSE");
  const sequence = state.actor_sequences.find((entry) => entry.actor_did === transaction.actor_did);
  if (!sequence || sequence.next_sequence !== transaction.sequence) reject("TRANSACTION_SEQUENCE_MISMATCH");
  const key = state.authorized_keys.find((entry) => entry.key_id === transaction.actor_key_id);
  if (!key || key.actor_did !== transaction.actor_did) reject("TRANSACTION_KEY_ACTOR_MISMATCH");
  if (key.purpose !== "pilot_ledger_signing" || key.suite !== "Ed25519-v1" ||
      key.status !== "active") reject("TRANSACTION_KEY_NOT_ACTIVE");

  const issued = BigInt(transaction.issued_at_ms);
  const expires = BigInt(transaction.expires_at_ms);
  if (issued >= expires || expires - issued > 900000n ||
      consensusTime < issued || consensusTime > expires) reject("TRANSACTION_TIME_INVALID");
  if (consensusTime < BigInt(key.valid_from_ms) ||
      consensusTime >= BigInt(key.valid_until_ms)) reject("TRANSACTION_KEY_WINDOW_INVALID");

  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, canonicalBase64(key.public_key_base64, 32, "STATE_KEY_INVALID")]),
    format: "der",
    type: "spki"
  });
  const signature = canonicalBase64(transaction.signature.value, 64, "TRANSACTION_SIGNATURE_INVALID");
  if (!verify(null, tokenlessTransactionSignatureMessage(transaction.transaction_id), publicKey, signature)) {
    reject("TRANSACTION_SIGNATURE_INVALID");
  }
  return nonceKey;
}

function applyTransaction(state, transaction, height, nonceKey) {
  let effect;
  if (transaction.action === "pilot.public-commitment.register") {
    if (transaction.payload.object_id !==
        pilotPublicCommitmentId(transaction.actor_did, transaction.payload)) {
      reject("PUBLIC_COMMITMENT_ID_INVALID");
    }
    if (state.public_commitments.some((entry) => entry.object_id === transaction.payload.object_id)) {
      reject("PUBLIC_COMMITMENT_EXISTS");
    }
    const record = {
      object_id: transaction.payload.object_id,
      owner_did: transaction.actor_did,
      content_hash: transaction.payload.content_hash,
      license_hash: transaction.payload.license_hash,
      source_event_id: transaction.payload.source_event_id,
      registered_height: height,
      status: "active",
      tombstone_event_id: null,
      tombstone_reason: null,
      tombstoned_height: null
    };
    state.public_commitments.push(record);
    effect = {
      operation: "insert",
      collection: "public_commitments",
      key: record.object_id,
      value: record
    };
  } else {
    const record = state.public_commitments.find(
      (entry) => entry.object_id === transaction.payload.object_id
    );
    if (!record) reject("PUBLIC_COMMITMENT_NOT_FOUND");
    if (record.owner_did !== transaction.actor_did) reject("PUBLIC_COMMITMENT_OWNER_MISMATCH");
    if (record.status !== "active") reject("PUBLIC_COMMITMENT_ALREADY_TOMBSTONED");
    record.status = "tombstoned";
    record.tombstone_event_id = transaction.transaction_id;
    record.tombstone_reason = transaction.payload.reason;
    record.tombstoned_height = height;
    effect = {
      operation: "tombstone",
      collection: "public_commitments",
      key: record.object_id,
      transaction_id: transaction.transaction_id,
      reason: transaction.payload.reason,
      height
    };
  }

  const sequence = state.actor_sequences.find((entry) => entry.actor_did === transaction.actor_did);
  sequence.next_sequence = (BigInt(sequence.next_sequence) + 1n).toString();
  state.consumed_transaction_ids.push(transaction.transaction_id);
  state.consumed_nonces.push({ nonce_key: nonceKey, transaction_id: transaction.transaction_id });
  state.public_commitments.sort((left, right) => left.object_id < right.object_id ? -1 : left.object_id > right.object_id ? 1 : 0);
  state.consumed_transaction_ids.sort();
  state.consumed_nonces.sort((left, right) => left.nonce_key < right.nonce_key ? -1 : left.nonce_key > right.nonce_key ? 1 : 0);

  return {
    transaction_id: transaction.transaction_id,
    action: transaction.action,
    code: "OK",
    state_change_hash: digest(D.effect, effect)
  };
}

function validateBlockShape(block) {
  exactObject(block, BLOCK_FIELDS, "BLOCK_SHAPE_INVALID");
  if (block.schema_version !== "somavera.tokenless-block.v1" ||
      block.profile_status !== PROFILE) reject("BLOCK_PROFILE_INVALID");
  if (!/^somavera:network:v1:[a-f0-9]{64}$/.test(block.network_lineage_id || "") ||
      !/^somavera:context:v1:[a-f0-9]{64}$/.test(block.execution_context_id || "")) {
    reject("BLOCK_DOMAIN_INVALID");
  }
  uint(block.height, "BLOCK_HEIGHT_INVALID");
  uint(block.consensus_time_ms, "BLOCK_TIME_INVALID");
  hash(block.prior_app_hash, "BLOCK_PRIOR_APP_HASH_INVALID");
  hash(block.block_id, "BLOCK_ID_INVALID");
  if (!Array.isArray(block.transactions) || block.transactions.length > MAX_TRANSACTIONS) {
    reject("BLOCK_TRANSACTION_COUNT_INVALID");
  }
}

export function evaluateTokenlessBlock(priorState, block) {
  const unchanged = structuredClone(priorState);
  let transactionIndex = null;
  try {
    validateTokenlessState(priorState);
    validateBlockShape(block);
    if (block.block_id !== tokenlessBlockId(block)) reject("BLOCK_ID_MISMATCH");
    if (block.network_lineage_id !== priorState.network_lineage_id) reject("BLOCK_NETWORK_MISMATCH");
    if (block.execution_context_id !== priorState.execution_context_id) reject("BLOCK_CONTEXT_MISMATCH");
    if (block.prior_app_hash !== priorState.app_hash) reject("BLOCK_PRIOR_APP_HASH_MISMATCH");
    if (BigInt(block.height) !== BigInt(priorState.height) + 1n) reject("BLOCK_HEIGHT_MISMATCH");
    const consensusTime = BigInt(block.consensus_time_ms);
    const priorTime = BigInt(priorState.last_consensus_time_ms);
    if (consensusTime <= priorTime ||
        consensusTime - priorTime > BigInt(priorState.maximum_block_time_advance_ms)) {
      reject("BLOCK_TIME_INVALID");
    }

    const state = structuredClone(priorState);
    const transactionResults = [];
    for (let index = 0; index < block.transactions.length; index += 1) {
      transactionIndex = index;
      const transaction = decodeTokenlessTransaction(block.transactions[index]);
      const nonceKey = verifyTransactionAgainstState(state, transaction, consensusTime);
      transactionResults.push(applyTransaction(state, transaction, block.height, nonceKey));
    }
    const resultRoot = tokenlessBlockResultRoot(transactionResults);
    state.height = block.height;
    state.last_consensus_time_ms = block.consensus_time_ms;
    state.last_block_id = block.block_id;
    state.last_block_result_root = resultRoot;
    const boundState = bindTokenlessState(state);
    validateTokenlessState(boundState);
    return {
      accepted: true,
      state: boundState,
      result: {
        $schema: "../schemas/tokenless-reducer-block-result.schema.json",
        schema_version: "somavera.tokenless-block-result.v1",
        profile_status: PROFILE,
        accepted: true,
        block_id: block.block_id,
        height: block.height,
        pre_state_root: priorState.state_root,
        post_state_root: boundState.state_root,
        app_hash: boundState.app_hash,
        block_result_root: resultRoot,
        transaction_results: transactionResults
      }
    };
  } catch (error) {
    if (!(error instanceof TokenlessReducerError)) throw error;
    return {
      accepted: false,
      state: unchanged,
      error: {
        code: error.code,
        transaction_index: transactionIndex
      }
    };
  }
}
