import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  genesisCoreHash,
  genesisExecutionContextId,
  genesisNetworkLineageId,
  validateGenesisIdentityAndTokenless
} from "./genesis-validation.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const structural = JSON.parse(
  await readFile(path.join(root, "examples", "network-genesis.example.json"), "utf8")
);
let checks = 0;
const assert = (condition, message) => {
  if (!condition) throw new Error(`Genesis validation conformance failed: ${message}`);
  checks += 1;
};

function bindDerivedIds(value) {
  value.genesis_core_hash = genesisCoreHash(value);
  value.network_lineage_id = genesisNetworkLineageId(value);
  value.execution_context_id = genesisExecutionContextId(value);
  return value;
}

const valid = structuredClone(structural);
valid.chain.consensus_profile = "somavera-pilot-cometbft-0.39-abci-v1";
valid.validator_set.forEach((entry, index) => {
  entry.public_key = Buffer.alloc(32, index + 1).toString("base64");
});
bindDerivedIds(valid);
assert(validateGenesisIdentityAndTokenless(valid).ok, "synthetic identity fixture was rejected");

const placeholderResult = validateGenesisIdentityAndTokenless(structural);
assert(!placeholderResult.ok, "structural placeholder example was accepted as semantic Genesis");
assert(placeholderResult.errors.includes("GENESIS_CORE_HASH_INVALID"), "placeholder core hash was not rejected");
assert(placeholderResult.errors.includes("GENESIS_VALIDATOR_KEY_DUPLICATE"), "placeholder validator keys were not rejected");

function expect(name, mutate, requiredCode, rebind = false) {
  const value = structuredClone(valid);
  mutate(value);
  if (rebind) bindDerivedIds(value);
  const result = validateGenesisIdentityAndTokenless(value);
  assert(!result.ok, `${name} was accepted`);
  assert(result.errors.includes(requiredCode), `${name} did not report ${requiredCode}`);
}

expect("core mutation", (value) => { value.chain.block_time_ms += 1; }, "GENESIS_CORE_HASH_INVALID");
expect("network lineage mutation", (value) => { value.network_lineage_id = "somavera:network:v1:" + "0".repeat(64); }, "GENESIS_NETWORK_LINEAGE_INVALID");
expect("context mutation", (value) => { value.execution_context_id = "somavera:context:v1:" + "0".repeat(64); }, "GENESIS_EXECUTION_CONTEXT_INVALID");
expect("token activation", (value) => { value.token.activated = true; }, "GENESIS_TOKEN_NOT_ZERO", true);
expect("duplicate validator ID", (value) => { value.validator_set[1].validator_id = value.validator_set[0].validator_id; }, "GENESIS_VALIDATOR_ID_DUPLICATE", true);
expect("duplicate validator key", (value) => { value.validator_set[1].public_key = value.validator_set[0].public_key; }, "GENESIS_VALIDATOR_KEY_DUPLICATE", true);
expect("unsafe voting power", (value) => { value.validator_set[0].voting_power = "2"; }, "GENESIS_SINGLE_VALIDATOR_POWER_UNSAFE", true);
expect("duplicate anchor", (value) => { value.external_anchors[1] = value.external_anchors[0]; }, "GENESIS_EXTERNAL_ANCHOR_DUPLICATE");
expect("duplicate chamber role", (value) => { value.ratification_signatures[1].role = value.ratification_signatures[0].role; }, "GENESIS_CHAMBER_ROLE_SET_INVALID");

console.log(`Genesis identity/tokenless checks passed: ${checks}; authority and signatures remain unimplemented.`);
