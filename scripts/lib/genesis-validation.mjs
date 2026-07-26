import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.mjs";

const CORE_DOMAIN = "somavera:genesis-core:v1\n";
const LINEAGE_DOMAIN = "somavera:network-lineage:v1\n";
const CONTEXT_DOMAIN = "somavera:execution-context:v1\n";

function sha256(parts) {
  const hash = createHash("sha256");
  for (const [value, encoding] of parts) hash.update(value, encoding);
  return hash.digest("hex");
}

export function genesisCore(genesis) {
  const excluded = new Set([
    "$schema",
    "schema_version",
    "genesis_core_hash",
    "network_lineage_id",
    "execution_context_id",
    "external_anchors",
    "ratification_signatures"
  ]);
  return Object.fromEntries(
    Object.entries(genesis).filter(([name]) => !excluded.has(name))
  );
}

export function genesisCoreHash(genesis) {
  return sha256([[CORE_DOMAIN + canonicalize(genesisCore(genesis)), "utf8"]]);
}

export function genesisNetworkLineageId(genesis) {
  const coreHash = genesisCoreHash(genesis);
  return "somavera:network:v1:" + sha256([
    [LINEAGE_DOMAIN, "utf8"],
    [genesis.origin_hash, "hex"],
    [coreHash, "hex"]
  ]);
}

export function genesisExecutionContextId(genesis) {
  const coreHash = genesisCoreHash(genesis);
  const lineage = genesisNetworkLineageId(genesis);
  const epoch = Buffer.alloc(8);
  epoch.writeBigUInt64BE(BigInt(genesis.context_epoch));
  return "somavera:context:v1:" + sha256([
    [CONTEXT_DOMAIN, "utf8"],
    [lineage, "utf8"],
    [epoch, undefined],
    [coreHash, "hex"]
  ]);
}

export function validateGenesisIdentityAndTokenless(genesis) {
  const errors = new Set();
  if (genesis.context_epoch !== 0) errors.add("GENESIS_CONTEXT_EPOCH_INVALID");
  if (genesis.genesis_core_hash !== genesisCoreHash(genesis)) {
    errors.add("GENESIS_CORE_HASH_INVALID");
  }
  if (genesis.network_lineage_id !== genesisNetworkLineageId(genesis)) {
    errors.add("GENESIS_NETWORK_LINEAGE_INVALID");
  }
  if (genesis.execution_context_id !== genesisExecutionContextId(genesis)) {
    errors.add("GENESIS_EXECUTION_CONTEXT_INVALID");
  }
  if (genesis.token?.activated !== false ||
      genesis.token?.activation_core_hash !== null ||
      genesis.token?.asset_lineage_id !== null ||
      genesis.token?.genesis_supply_grain !== "0") {
    errors.add("GENESIS_TOKEN_NOT_ZERO");
  }

  const validators = genesis.validator_set ?? [];
  if (validators.length < 4) errors.add("GENESIS_VALIDATOR_COUNT_UNSAFE");
  const validatorIds = validators.map((entry) => entry.validator_id);
  const publicKeys = validators.map((entry) => entry.public_key);
  if (new Set(validatorIds).size !== validatorIds.length) {
    errors.add("GENESIS_VALIDATOR_ID_DUPLICATE");
  }
  if (new Set(publicKeys).size !== publicKeys.length) {
    errors.add("GENESIS_VALIDATOR_KEY_DUPLICATE");
  }
  let powers;
  try {
    if (validators.some((entry) => !/^[1-9][0-9]*$/.test(entry.voting_power))) {
      throw new Error("noncanonical voting power");
    }
    powers = validators.map((entry) => BigInt(entry.voting_power));
  } catch {
    powers = [];
    errors.add("GENESIS_VOTING_POWER_INVALID");
  }
  if (powers.length > 0) {
    const total = powers.reduce((sum, value) => sum + value, 0n);
    if (total <= 0n || powers.some((value) => value <= 0n)) {
      errors.add("GENESIS_VOTING_POWER_INVALID");
    } else if (powers.some((value) => value * 3n >= total)) {
      errors.add("GENESIS_SINGLE_VALIDATOR_POWER_UNSAFE");
    }
  }

  const anchors = genesis.external_anchors ?? [];
  if (new Set(anchors).size !== anchors.length) {
    errors.add("GENESIS_EXTERNAL_ANCHOR_DUPLICATE");
  }
  const roles = (genesis.ratification_signatures ?? []).map((entry) => entry.role);
  const requiredRoles = new Set([
    "economic_chamber",
    "operator_contributor_chamber",
    "public_data_rights_chamber"
  ]);
  if (new Set(roles).size !== roles.length ||
      roles.length !== requiredRoles.size ||
      roles.some((role) => !requiredRoles.has(role))) {
    errors.add("GENESIS_CHAMBER_ROLE_SET_INVALID");
  }

  return {
    ok: errors.size === 0,
    errors: [...errors].sort()
  };
}
