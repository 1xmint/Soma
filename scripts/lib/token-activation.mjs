import { createHash, createPublicKey, verify } from "node:crypto";
import { canonicalize } from "./canonicalize.mjs";

export const TOKEN_CHAMBERS = Object.freeze([
  "economic",
  "operator_contributor",
  "public_data_rights"
]);

const EPOCH_RECIPIENTS = new Set([
  "verified_services_hosts",
  "validators",
  "public_goods",
  "evaluation_recovery"
]);
const FEE_RECIPIENTS = new Set(["validators", "public_goods", "burn"]);
const PREACTIVATION_ECONOMIC_FIELDS = Object.freeze([
  "balances",
  "bonds",
  "escrows",
  "fee_pools",
  "governed_pools",
  "pending_mints",
  "pending_burns",
  "consumed_issuance_receipts"
]);
const HASH = /^[a-f0-9]{64}$/;
const NETWORK_LINEAGE = /^somavera:network:v1:[a-f0-9]{64}$/;
const UINT = /^(0|[1-9][0-9]*)$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function issue(errors, code, path, message) {
  errors.push({ code, path, message });
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactObject(value, path, required, optional, errors) {
  if (!object(value)) {
    issue(errors, "SHAPE_OBJECT_REQUIRED", path, "must be an object");
    return false;
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!Object.hasOwn(value, key)) issue(errors, "SHAPE_REQUIRED_FIELD", path + "/" + key, "is required");
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) issue(errors, "SHAPE_UNKNOWN_FIELD", path + "/" + key, "is not allowed");
  }
  return true;
}

function isSafeNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isGrain(value) {
  return typeof value === "string" && UINT.test(value);
}

function isTimestamp(value) {
  return typeof value === "string" && RFC3339.test(value) && Number.isFinite(Date.parse(value));
}

function isCanonicalBase64(value, byteLength) {
  if (typeof value !== "string") return false;
  try {
    const bytes = Buffer.from(value, "base64");
    return bytes.length === byteLength && bytes.toString("base64") === value;
  } catch {
    return false;
  }
}

function splitErrors(entries, path, allowedRecipients, errors) {
  if (!Array.isArray(entries)) {
    issue(errors, "SPLIT_ARRAY_REQUIRED", path, "must be an array");
    return;
  }
  const seen = new Set();
  let total = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const at = path + "/" + index;
    if (!exactObject(entry, at, ["recipient", "basis_points"], [], errors)) continue;
    if (!allowedRecipients.has(entry.recipient)) {
      issue(errors, "SPLIT_RECIPIENT_INVALID", at + "/recipient", "recipient is not permitted for this split");
    }
    if (seen.has(entry.recipient)) {
      issue(errors, "SPLIT_RECIPIENT_DUPLICATE", at + "/recipient", "recipient occurs more than once");
    }
    seen.add(entry.recipient);
    if (!Number.isSafeInteger(entry.basis_points) || entry.basis_points < 0 || entry.basis_points > 10000) {
      issue(errors, "SPLIT_BASIS_POINTS_INVALID", at + "/basis_points", "must be an integer from 0 through 10000");
    } else {
      total += entry.basis_points;
    }
  }
  for (const recipient of allowedRecipients) {
    if (!seen.has(recipient)) issue(errors, "SPLIT_RECIPIENT_MISSING", path, "missing required recipient " + recipient);
  }
  if (total !== 10000) issue(errors, "SPLIT_TOTAL_INVALID", path, "basis points must total exactly 10000");
}

function coreShapeErrors(core, errors) {
  const required = [
    "origin_hash",
    "network_lineage_id",
    "activation_time",
    "activation_height",
    "preactivation_governance_manifest_hash",
    "token",
    "issuance",
    "epoch_allocation",
    "fee_policy",
    "parameter_decision_hash",
    "economic_simulation_hash",
    "launch_gate_report_hash",
    "external_settlement_policy_hash",
    "bond_policy_hash",
    "governance_hash",
    "data_rights_hash",
    "recovery_hash",
    "protocol_release_hashes",
    "bootstrap",
    "legal",
    "abort_conditions_hash"
  ];
  if (!exactObject(core, "/activation_core", required, [], errors)) return;

  for (const field of [
    "origin_hash",
    "preactivation_governance_manifest_hash",
    "parameter_decision_hash",
    "economic_simulation_hash",
    "launch_gate_report_hash",
    "external_settlement_policy_hash",
    "bond_policy_hash",
    "governance_hash",
    "data_rights_hash",
    "recovery_hash",
    "abort_conditions_hash"
  ]) {
    if (!HASH.test(core[field] ?? "")) issue(errors, "HASH_INVALID", "/activation_core/" + field, "must be 64 lowercase hex characters");
  }
  if (!NETWORK_LINEAGE.test(core.network_lineage_id ?? "")) {
    issue(errors, "NETWORK_LINEAGE_INVALID", "/activation_core/network_lineage_id", "invalid network lineage ID");
  }
  if (!isSafePositiveInteger(core.activation_height)) issue(errors, "ACTIVATION_HEIGHT_INVALID", "/activation_core/activation_height", "must be a positive safe integer");
  if (!isTimestamp(core.activation_time)) issue(errors, "ACTIVATION_TIME_INVALID", "/activation_core/activation_time", "must be an RFC 3339 timestamp");

  if (exactObject(core.token, "/activation_core/token", ["name", "symbol", "denom", "decimals", "genesis_supply_grain"], [], errors)) {
    if (typeof core.token.name !== "string" || core.token.name.length < 1 || core.token.name.length > 64) issue(errors, "TOKEN_NAME_INVALID", "/activation_core/token/name", "must contain from one through sixty-four characters");
    if (typeof core.token.symbol !== "string" || !/^[A-Z][A-Z0-9]{1,11}$/.test(core.token.symbol)) issue(errors, "TOKEN_SYMBOL_INVALID", "/activation_core/token/symbol", "must be two through twelve uppercase alphanumeric characters");
    if (core.token.denom !== "grain") issue(errors, "TOKEN_DENOM_INVALID", "/activation_core/token/denom", "schema v1 requires the grain atomic denomination");
    if (!Number.isSafeInteger(core.token.decimals) || core.token.decimals < 0 || core.token.decimals > 18) issue(errors, "TOKEN_DECIMALS_INVALID", "/activation_core/token/decimals", "must be an integer from zero through eighteen");
    if (core.token.genesis_supply_grain !== "0") issue(errors, "GENESIS_SUPPLY_NONZERO", "/activation_core/token/genesis_supply_grain", "must be zero");
  }

  const issuance = core.issuance;
  if (exactObject(issuance, "/activation_core/issuance", [
    "lifetime_mint_ceiling_grain",
    "epoch_seconds",
    "schedule_year_seconds",
    "cumulative_ceilings",
    "tail_annual_cap_basis_points",
    "tail_supply_basis"
  ], [], errors)) {
    if (!isGrain(issuance.lifetime_mint_ceiling_grain) || BigInt(issuance.lifetime_mint_ceiling_grain) === 0n) issue(errors, "LIFETIME_CEILING_INVALID", "/activation_core/issuance/lifetime_mint_ceiling_grain", "must be positive canonical unsigned grain");
    if (!Number.isSafeInteger(issuance.epoch_seconds) || issuance.epoch_seconds < 60 || issuance.epoch_seconds > 31557600) issue(errors, "EPOCH_SECONDS_INVALID", "/activation_core/issuance/epoch_seconds", "must be from sixty seconds through one Julian year");
    if (!Number.isSafeInteger(issuance.schedule_year_seconds) || issuance.schedule_year_seconds < 86400 || issuance.schedule_year_seconds > 63115200) issue(errors, "SCHEDULE_YEAR_SECONDS_INVALID", "/activation_core/issuance/schedule_year_seconds", "must be from one day through two Julian years");
    if (issuance.tail_supply_basis !== "live_supply_at_anniversary") issue(errors, "TAIL_SUPPLY_BASIS_INVALID", "/activation_core/issuance/tail_supply_basis", "must use live_supply_at_anniversary");
    if (!Number.isSafeInteger(issuance.tail_annual_cap_basis_points) || issuance.tail_annual_cap_basis_points < 0 || issuance.tail_annual_cap_basis_points > 100) {
      issue(errors, "TAIL_CAP_INVALID", "/activation_core/issuance/tail_annual_cap_basis_points", "must be an integer from 0 through 100");
    }
    if (!Array.isArray(issuance.cumulative_ceilings) || issuance.cumulative_ceilings.length < 1 || issuance.cumulative_ceilings.length > 100) {
      issue(errors, "CEILING_ARRAY_INVALID", "/activation_core/issuance/cumulative_ceilings", "requires from one through one hundred anchors");
    } else {
      let priorYear = 0;
      let priorMax = -1n;
      const lifetime = isGrain(issuance.lifetime_mint_ceiling_grain) ? BigInt(issuance.lifetime_mint_ceiling_grain) : 0n;
      issuance.cumulative_ceilings.forEach((anchor, index) => {
        const at = "/activation_core/issuance/cumulative_ceilings/" + index;
        if (!exactObject(anchor, at, ["elapsed_year", "max_grain"], [], errors)) return;
        if (!isSafePositiveInteger(anchor.elapsed_year)) issue(errors, "CEILING_YEAR_INVALID", at + "/elapsed_year", "must be a positive safe integer");
        if (!isGrain(anchor.max_grain)) issue(errors, "CEILING_MAX_INVALID", at + "/max_grain", "must be canonical unsigned grain");
        if (isSafePositiveInteger(anchor.elapsed_year) && anchor.elapsed_year <= priorYear) issue(errors, "CEILING_YEARS_NOT_STRICT", at + "/elapsed_year", "years must be sorted and unique");
        if (isGrain(anchor.max_grain)) {
          const maximum = BigInt(anchor.max_grain);
          if (maximum <= priorMax) issue(errors, "CEILING_MAX_NOT_STRICT", at + "/max_grain", "ceilings must strictly increase");
          if (maximum > lifetime) issue(errors, "CEILING_ABOVE_LIFETIME", at + "/max_grain", "ceiling exceeds lifetime maximum");
          priorMax = maximum;
        }
        if (isSafePositiveInteger(anchor.elapsed_year)) priorYear = anchor.elapsed_year;
      });
    }
  }

  splitErrors(core.epoch_allocation, "/activation_core/epoch_allocation", EPOCH_RECIPIENTS, errors);
  if (exactObject(core.fee_policy, "/activation_core/fee_policy", ["service_price_to_provider_basis_points", "network_fee"], [], errors)) {
    if (core.fee_policy.service_price_to_provider_basis_points !== 10000) issue(errors, "SERVICE_PRICE_REDIRECTED", "/activation_core/fee_policy/service_price_to_provider_basis_points", "must remain 10000");
    splitErrors(core.fee_policy.network_fee, "/activation_core/fee_policy/network_fee", FEE_RECIPIENTS, errors);
  }
  if (!Array.isArray(core.protocol_release_hashes) || core.protocol_release_hashes.length < 2 || core.protocol_release_hashes.length > 100 || new Set(core.protocol_release_hashes).size !== core.protocol_release_hashes.length || core.protocol_release_hashes.some((value) => !HASH.test(value))) {
    issue(errors, "PROTOCOL_RELEASE_HASHES_INVALID", "/activation_core/protocol_release_hashes", "requires from two through one hundred unique hashes");
  }
  if (exactObject(core.bootstrap, "/activation_core/bootstrap", ["validator_manifest_hash", "automatic_sunset_height", "permissionless_gate_hash"], [], errors)) {
    if (!HASH.test(core.bootstrap.validator_manifest_hash ?? "") || !HASH.test(core.bootstrap.permissionless_gate_hash ?? "")) issue(errors, "BOOTSTRAP_HASH_INVALID", "/activation_core/bootstrap", "bootstrap hashes are invalid");
    if (!isSafePositiveInteger(core.bootstrap.automatic_sunset_height) || core.bootstrap.automatic_sunset_height <= core.activation_height) issue(errors, "BOOTSTRAP_SUNSET_INVALID", "/activation_core/bootstrap/automatic_sunset_height", "must follow activation height");
  }
  if (exactObject(core.legal, "/activation_core/legal", ["review_hash", "disclosures_uri"], [], errors)) {
    if (!HASH.test(core.legal.review_hash ?? "")) issue(errors, "LEGAL_REVIEW_HASH_INVALID", "/activation_core/legal/review_hash", "invalid hash");
    try {
      const url = new URL(core.legal.disclosures_uri);
      if (url.protocol !== "https:") throw new Error();
    } catch {
      issue(errors, "LEGAL_DISCLOSURE_URI_INVALID", "/activation_core/legal/disclosures_uri", "must be an HTTPS URI");
    }
  }
}

export function preactivationGovernanceManifestHash(manifest) {
  if (!object(manifest)) throw new TypeError("preactivation governance manifest must be an object");
  const core = { ...manifest };
  delete core.$schema;
  return createHash("sha256")
    .update("somavera:preactivation-governance-manifest:v1\n", "utf8")
    .update(canonicalize(core), "utf8")
    .digest("hex");
}

function governanceErrors(governance, core, preState, errors) {
  if (!object(governance)) {
    issue(errors, "PRESTATE_GOVERNANCE_REQUIRED", "/preState/governance", "active governance state is required");
    return { policyByChamber: new Map(), seatByKey: new Map() };
  }
  exactObject(governance, "/preState/governance", ["governance_manifest_hash", "manifest"], [], errors);
  const manifest = governance.manifest;
  if (!HASH.test(governance.governance_manifest_hash ?? "")) issue(errors, "PRESTATE_GOVERNANCE_MANIFEST_HASH_INVALID", "/preState/governance/governance_manifest_hash", "invalid hash");
  if (!exactObject(manifest, "/preState/governance/manifest", ["schema_version", "proposal_class", "valid_from_height", "expires_at_height", "chambers", "seats"], ["$schema"], errors)) {
    return { policyByChamber: new Map(), seatByKey: new Map() };
  }
  if (Object.hasOwn(manifest, "$schema") && typeof manifest.$schema !== "string") issue(errors, "PRESTATE_SCHEMA_REFERENCE_INVALID", "/preState/governance/manifest/$schema", "must be a string when present");
  if (manifest.schema_version !== "somavera.preactivation-governance.v1") issue(errors, "PRESTATE_GOVERNANCE_VERSION_INVALID", "/preState/governance/manifest/schema_version", "unsupported manifest version");
  if (manifest.proposal_class !== "G2") issue(errors, "PRESTATE_PROPOSAL_CLASS_INVALID", "/preState/governance/manifest/proposal_class", "token activation requires G2");
  if (!isSafeNonnegativeInteger(manifest.valid_from_height) || !isSafePositiveInteger(manifest.expires_at_height) || manifest.valid_from_height > preState?.height || manifest.expires_at_height < core.activation_height) {
    issue(errors, "PRESTATE_GOVERNANCE_WINDOW_INVALID", "/preState/governance/manifest", "manifest is not active across the activation transition");
  }
  let derivedHash = null;
  try {
    derivedHash = preactivationGovernanceManifestHash(manifest);
  } catch {
    issue(errors, "PRESTATE_GOVERNANCE_MANIFEST_CANONICALIZATION_FAILED", "/preState/governance/manifest", "cannot canonicalize manifest");
  }
  if (derivedHash !== governance.governance_manifest_hash) issue(errors, "PRESTATE_GOVERNANCE_MANIFEST_HASH_MISMATCH", "/preState/governance/governance_manifest_hash", "does not commit the active semantic manifest core");
  if (core.preactivation_governance_manifest_hash !== governance.governance_manifest_hash) issue(errors, "ACTIVATION_GOVERNANCE_MANIFEST_MISMATCH", "/activation_core/preactivation_governance_manifest_hash", "does not bind the active pre-state governance manifest");

  const policyByChamber = new Map();
  if (!Array.isArray(manifest.chambers)) {
    issue(errors, "PRESTATE_CHAMBER_POLICY_ARRAY_REQUIRED", "/preState/governance/manifest/chambers", "must be an array");
  } else {
    if (manifest.chambers.length !== TOKEN_CHAMBERS.length) issue(errors, "PRESTATE_CHAMBER_POLICY_COUNT_INVALID", "/preState/governance/manifest/chambers", "must contain exactly the three constitutional chambers");
    manifest.chambers.forEach((policy, index) => {
      const at = "/preState/governance/manifest/chambers/" + index;
      if (!exactObject(policy, at, ["chamber", "quorum_basis_points", "approval_basis_points"], [], errors)) return;
      if (!TOKEN_CHAMBERS.includes(policy.chamber)) {
        issue(errors, "PRESTATE_CHAMBER_CLASS_INVALID", at + "/chamber", "unknown chamber class");
        return;
      }
      if (policyByChamber.has(policy.chamber)) {
        issue(errors, "PRESTATE_CHAMBER_POLICY_DUPLICATE", at + "/chamber", "chamber occurs more than once");
        return;
      }
      if (!Number.isSafeInteger(policy.quorum_basis_points) || policy.quorum_basis_points < 7500 || policy.quorum_basis_points > 10000 || !Number.isSafeInteger(policy.approval_basis_points) || policy.approval_basis_points < 7500 || policy.approval_basis_points > 10000) {
        issue(errors, "PRESTATE_THRESHOLD_INVALID", at, "token activation requires quorum and approval >= 7500 basis points");
      }
      policyByChamber.set(policy.chamber, policy);
    });
  }
  for (const chamber of TOKEN_CHAMBERS) {
    if (!policyByChamber.has(chamber)) issue(errors, "PRESTATE_CHAMBER_POLICY_MISSING", "/preState/governance/manifest/chambers", "missing " + chamber);
  }

  const seatByKey = new Map();
  const controllerKeys = new Map();
  const organizationKeys = new Map();
  if (!Array.isArray(manifest.seats)) {
    issue(errors, "PRESTATE_SEAT_ARRAY_REQUIRED", "/preState/governance/manifest/seats", "must be an array");
  } else {
    if (manifest.seats.length < 12 || manifest.seats.length > 300) issue(errors, "PRESTATE_SEAT_COUNT_INVALID", "/preState/governance/manifest/seats", "must contain from 12 through 300 seats");
    manifest.seats.forEach((seat, index) => {
      const at = "/preState/governance/manifest/seats/" + index;
      if (!exactObject(seat, at, ["chamber", "key_id", "public_key", "voting_weight", "active", "controller_id", "organization_id"], [], errors)) return;
      if (!TOKEN_CHAMBERS.includes(seat.chamber) || typeof seat.key_id !== "string" || seat.key_id.length < 3 || seat.key_id.length > 512 || !isCanonicalBase64(seat.public_key, 32) || !isGrain(seat.voting_weight) || BigInt(seat.voting_weight) === 0n || seat.active !== true || typeof seat.controller_id !== "string" || seat.controller_id.length < 3 || seat.controller_id.length > 256 || typeof seat.organization_id !== "string" || seat.organization_id.length < 3 || seat.organization_id.length > 256) {
        issue(errors, "PRESTATE_SEAT_INVALID", at, "seat must be active and have a valid chamber, key, public key, controller, organization, and positive weight");
        return;
      }
      if (seatByKey.has(seat.key_id)) {
        issue(errors, "PRESTATE_SEAT_KEY_DUPLICATE", at + "/key_id", "key occurs more than once");
        return;
      }
      if (controllerKeys.has(seat.controller_id)) issue(errors, "PRESTATE_CONTROLLER_REUSED", at + "/controller_id", "one controller cannot occupy more than one seat");
      else controllerKeys.set(seat.controller_id, seat.key_id);
      if (organizationKeys.has(seat.organization_id)) issue(errors, "PRESTATE_ORGANIZATION_REUSED", at + "/organization_id", "one organization cannot occupy more than one seat");
      else organizationKeys.set(seat.organization_id, seat.key_id);
      seatByKey.set(seat.key_id, seat);
    });
  }
  for (const chamber of TOKEN_CHAMBERS) {
    const seats = [...seatByKey.values()].filter((seat) => seat.chamber === chamber);
    const controllerCount = new Set(seats.map((seat) => seat.controller_id)).size;
    const organizationCount = new Set(seats.map((seat) => seat.organization_id)).size;
    if (seats.length < 4 || controllerCount < 4 || organizationCount < 4) issue(errors, "PRESTATE_CHAMBER_INDEPENDENCE_INSUFFICIENT", "/preState/governance/manifest/seats", chamber + " requires at least four independently controlled seats");
  }
  return { policyByChamber, seatByKey };
}

function preStateErrors(preState, errors) {
  if (!exactObject(preState, "/preState", [
    "state_view",
    "height",
    "network_lineage_id",
    "origin_hash",
    "governance",
    "token",
    "economic_state"
  ], [], errors)) return;
  if (preState.state_view !== "somavera.token-activation-prestate.v1") issue(errors, "PRESTATE_VIEW_INVALID", "/preState/state_view", "unsupported activation pre-state view");
  if (!isSafeNonnegativeInteger(preState.height)) issue(errors, "PRESTATE_HEIGHT_INVALID", "/preState/height", "must be a nonnegative safe integer");
  if (!NETWORK_LINEAGE.test(preState.network_lineage_id ?? "")) issue(errors, "PRESTATE_NETWORK_INVALID", "/preState/network_lineage_id", "invalid network lineage ID");
  if (!HASH.test(preState.origin_hash ?? "")) issue(errors, "PRESTATE_ORIGIN_INVALID", "/preState/origin_hash", "invalid origin hash");

  const token = preState.token;
  if (exactObject(token, "/preState/token", [
    "activated",
    "activation_core_hash",
    "asset_lineage_id",
    "genesis_supply_grain",
    "live_supply_grain",
    "lifetime_minted_grain",
    "lifetime_burned_grain"
  ], [], errors)) {
    if (token.activated !== false || token.activation_core_hash !== null || token.asset_lineage_id !== null || token.genesis_supply_grain !== "0" || token.live_supply_grain !== "0" || token.lifetime_minted_grain !== "0" || token.lifetime_burned_grain !== "0") {
      issue(errors, "PRESTATE_TOKEN_NOT_ZERO", "/preState/token", "token must be inactive, lineage-free, and have all supply counters at zero");
    }
  }

  const economicState = preState.economic_state;
  if (exactObject(economicState, "/preState/economic_state", PREACTIVATION_ECONOMIC_FIELDS, [], errors)) {
    for (const field of PREACTIVATION_ECONOMIC_FIELDS) {
      if (!Array.isArray(economicState[field]) || economicState[field].length !== 0) {
        issue(errors, "PRESTATE_ECONOMIC_STATE_NONZERO", "/preState/economic_state/" + field, "preactivation economic collections must be declared and empty");
      }
    }
  }
}

function signatureBytes(value) {
  if (!isCanonicalBase64(value, 64)) return null;
  return Buffer.from(value, "base64");
}

function verifyRatification(publicKeyBase64, message, signature) {
  try {
    const raw = Buffer.from(publicKeyBase64, "base64");
    const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
    return verify(null, Buffer.from(message, "utf8"), key, signature);
  } catch {
    return false;
  }
}

export function activationCoreHash(core) {
  return createHash("sha256")
    .update("somavera:token-activation-core:v1\n", "utf8")
    .update(canonicalize(core), "utf8")
    .digest("hex");
}

export function activationAssetLineageId(originHash, coreHash) {
  const digest = createHash("sha256")
    .update("somavera:asset-lineage:v1\n", "utf8")
    .update(Buffer.from(originHash, "hex"))
    .update(Buffer.from(coreHash, "hex"))
    .digest("hex");
  return "vera:rpa:v1:" + digest;
}

export function tokenRatificationMessage(manifest) {
  return "somavera:token-ratification:v1\n" + canonicalize({
    schema_version: manifest.schema_version,
    activation_core_hash: manifest.activation_core_hash,
    asset_lineage_id: manifest.asset_lineage_id
  });
}

export function validateTokenActivationTransition({ manifest, preState, transition }) {
  const errors = [];
  if (!exactObject(manifest, "", ["schema_version", "activation_core", "activation_core_hash", "asset_lineage_id", "ratification_signatures"], ["$schema"], errors)) return { ok: false, errors };
  if (manifest.schema_version !== "vera.token-activation.v1") issue(errors, "SCHEMA_VERSION_INVALID", "/schema_version", "unsupported version");
  coreShapeErrors(manifest.activation_core, errors);
  const core = object(manifest.activation_core) ? manifest.activation_core : {};

  let derivedCoreHash = null;
  try {
    derivedCoreHash = activationCoreHash(core);
  } catch {
    issue(errors, "CORE_CANONICALIZATION_FAILED", "/activation_core", "cannot canonicalize core");
  }
  if (derivedCoreHash !== manifest.activation_core_hash) issue(errors, "ACTIVATION_CORE_HASH_MISMATCH", "/activation_core_hash", "does not match activation_core");
  if (!HASH.test(manifest.activation_core_hash ?? "")) issue(errors, "ACTIVATION_CORE_HASH_INVALID", "/activation_core_hash", "invalid hash");
  const derivedLineage = derivedCoreHash && HASH.test(core.origin_hash ?? "") ? activationAssetLineageId(core.origin_hash, derivedCoreHash) : null;
  if (derivedLineage !== manifest.asset_lineage_id) issue(errors, "ASSET_LINEAGE_MISMATCH", "/asset_lineage_id", "does not match core");

  preStateErrors(preState, errors);
  if (core.network_lineage_id !== preState?.network_lineage_id) issue(errors, "PRESTATE_NETWORK_MISMATCH", "/activation_core/network_lineage_id", "does not match pre-state");
  if (core.origin_hash !== preState?.origin_hash) issue(errors, "PRESTATE_ORIGIN_MISMATCH", "/activation_core/origin_hash", "does not match pre-state");
  if (!isSafePositiveInteger(transition?.height) || transition.height !== core.activation_height || transition.height !== preState?.height + 1) issue(errors, "TRANSITION_HEIGHT_MISMATCH", "/activation_core/activation_height", "must equal the next applied height");
  if (!isTimestamp(transition?.consensus_time) || !isTimestamp(core.activation_time) || Date.parse(transition.consensus_time) < Date.parse(core.activation_time)) issue(errors, "TRANSITION_TIME_TOO_EARLY", "/activation_core/activation_time", "consensus time has not reached activation time");

  const governance = object(preState?.governance) ? preState.governance : null;
  const { policyByChamber, seatByKey } = governanceErrors(governance, core, preState, errors);
  const signatures = Array.isArray(manifest.ratification_signatures) ? manifest.ratification_signatures : [];
  if (!Array.isArray(manifest.ratification_signatures)) issue(errors, "SIGNATURE_ARRAY_REQUIRED", "/ratification_signatures", "must be an array");
  if (signatures.length < TOKEN_CHAMBERS.length || signatures.length > 1000) issue(errors, "SIGNATURE_COUNT_INVALID", "/ratification_signatures", "signature count is outside bounds");
  const signedWeight = new Map(TOKEN_CHAMBERS.map((chamber) => [chamber, 0n]));
  const seenKeys = new Set();
  let message = null;
  try {
    message = tokenRatificationMessage(manifest);
  } catch {
    issue(errors, "RATIFICATION_MESSAGE_INVALID", "/ratification_signatures", "cannot build signing message");
  }
  signatures.forEach((signature, index) => {
    const at = "/ratification_signatures/" + index;
    if (!exactObject(signature, at, ["chamber", "key_id", "suite", "value"], [], errors)) return;
    if (!TOKEN_CHAMBERS.includes(signature.chamber)) {
      issue(errors, "SIGNATURE_CHAMBER_INVALID", at + "/chamber", "unknown chamber");
      return;
    }
    if (signature.suite !== "Ed25519-v1") issue(errors, "SIGNATURE_SUITE_INVALID", at + "/suite", "unsupported suite");
    if (seenKeys.has(signature.key_id)) {
      issue(errors, "DUPLICATE_SIGNER_KEY", at + "/key_id", "a key can count only once across every chamber");
      return;
    }
    seenKeys.add(signature.key_id);
    const seat = seatByKey.get(signature.key_id);
    if (!seat) {
      issue(errors, "SIGNER_NOT_IN_PRESTATE", at + "/key_id", "key is absent from the active governance manifest");
      return;
    }
    if (seat.chamber !== signature.chamber) {
      issue(errors, "SIGNER_CHAMBER_MISMATCH", at + "/chamber", "claimed chamber differs from pre-state seat");
      return;
    }
    const bytes = signatureBytes(signature.value);
    if (!bytes || !message || !verifyRatification(seat.public_key, message, bytes)) {
      issue(errors, "SIGNATURE_INVALID", at + "/value", "Ed25519 verification failed");
      return;
    }
    signedWeight.set(signature.chamber, (signedWeight.get(signature.chamber) ?? 0n) + BigInt(seat.voting_weight));
  });

  for (const chamber of TOKEN_CHAMBERS) {
    const policy = policyByChamber.get(chamber);
    if (!policy) continue;
    const eligible = [...seatByKey.values()].filter((seat) => seat.chamber === chamber).reduce((sum, seat) => sum + BigInt(seat.voting_weight), 0n);
    const signed = signedWeight.get(chamber) ?? 0n;
    if (signed === 0n) issue(errors, "CHAMBER_SIGNATURE_MISSING", "/ratification_signatures", "no valid approval from " + chamber);
    if (eligible === 0n || !Number.isSafeInteger(policy.quorum_basis_points) || !Number.isSafeInteger(policy.approval_basis_points)) continue;
    if (signed * 10000n < eligible * BigInt(policy.quorum_basis_points)) issue(errors, "CHAMBER_QUORUM_NOT_MET", "/ratification_signatures", chamber + " quorum not met");
    if (signed * 10000n < eligible * BigInt(policy.approval_basis_points)) issue(errors, "CHAMBER_APPROVAL_NOT_MET", "/ratification_signatures", chamber + " approval threshold not met");
  }
  return { ok: errors.length === 0, errors };
}

export class TokenActivationValidationError extends Error {
  constructor(errors) {
    super("token activation rejected: " + errors.map((entry) => entry.code).join(", "));
    this.name = "TokenActivationValidationError";
    this.errors = errors;
  }
}

export function applyTokenActivationTransition(input) {
  const result = validateTokenActivationTransition(input);
  if (!result.ok) throw new TokenActivationValidationError(result.errors);
  const nextState = structuredClone(input.preState);
  nextState.height = input.transition.height;
  nextState.token = {
    activated: true,
    activation_core_hash: input.manifest.activation_core_hash,
    asset_lineage_id: input.manifest.asset_lineage_id,
    genesis_supply_grain: "0",
    live_supply_grain: "0",
    lifetime_minted_grain: "0",
    lifetime_burned_grain: "0"
  };
  return nextState;
}
