import { readdir, readFile } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./lib/canonicalize.mjs";
import { listCapsuleFiles } from "./lib/capsule-files.mjs";
import { validateSchemaSubset } from "./lib/schema-subset.mjs";
import {
  activationAssetLineageId,
  activationCoreHash,
  applyTokenActivationTransition,
  preactivationGovernanceManifestHash,
  tokenRatificationMessage,
  validateTokenActivationTransition
} from "./lib/token-activation.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
let checks = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
  checks += 1;
}

async function json(relative) {
  return JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
}

for (const folder of ["schemas", "examples", "conformance"]) {
  const names = await readdir(path.join(root, folder));
  for (const name of names.filter((entry) => entry.endsWith(".json"))) {
    await json(folder + "/" + name);
    checks += 1;
  }
}

const schemaNames = (await readdir(path.join(root, "schemas"))).filter((entry) => entry.endsWith(".schema.json"));
for (const name of schemaNames) {
  const schema = await json("schemas/" + name);
  assert(schema.$schema === "https://json-schema.org/draft/2020-12/schema", name + " does not declare JSON Schema draft 2020-12");
  assert(typeof schema.$id === "string", name + " has no schema ID");
}

const exampleNames = (await readdir(path.join(root, "examples"))).filter((entry) => entry.endsWith(".json"));
for (const name of exampleNames) {
  const example = await json("examples/" + name);
  assert(typeof example.$schema === "string", name + " does not name its schema");
  const schema = await json("schemas/" + path.basename(example.$schema));
  const errors = validateSchemaSubset(schema, example);
  assert(errors.length === 0, name + " fails schema subset validation:\n" + errors.join("\n"));
}

const vectors = await json("conformance/canonicalization-v1.json");
for (const vector of vectors.vectors) {
  const canonical = canonicalize(vector.input);
  assert(canonical === vector.canonical, vector.name + " canonical bytes differ");
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  assert(digest === vector.sha256, vector.name + " hash differs");
}

for (const invalid of [-0, Number.NaN, Number.POSITIVE_INFINITY, 9007199254740992]) {
  let rejected = false;
  try { canonicalize(invalid); } catch { rejected = true; }
  assert(rejected, "canonicalizer accepted forbidden number");
}

const ed = await json("conformance/ed25519-rfc8032-v1.json");
const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
const rfcPublicKey = createPublicKey({
  key: Buffer.concat([spkiPrefix, Buffer.from(ed.public_key_hex, "hex")]),
  format: "der",
  type: "spki"
});
assert(verify(null, Buffer.from(ed.message_hex, "hex"), rfcPublicKey, Buffer.from(ed.signature_hex, "hex")), "RFC 8032 Ed25519 vector failed");

const activation = await json("examples/token-activation.example.json");
function splitTotal(entries) {
  return entries.reduce((sum, entry) => sum + entry.basis_points, 0);
}
assert(splitTotal(activation.activation_core.epoch_allocation) === 10000, "epoch allocation must total 10000 basis points");
assert(activation.activation_core.fee_policy.service_price_to_provider_basis_points === 10000, "service price must remain with provider escrow");
assert(splitTotal(activation.activation_core.fee_policy.network_fee) === 10000, "network fee split must total 10000 basis points");
assert(activation.activation_core.token.denom === "grain", "smallest unit must be grain");
const ceilings = activation.activation_core.issuance.cumulative_ceilings;
for (let index = 1; index < ceilings.length; index += 1) {
  assert(ceilings[index].elapsed_year > ceilings[index - 1].elapsed_year, "issuance years must increase");
  assert(BigInt(ceilings[index].max_grain) > BigInt(ceilings[index - 1].max_grain), "issuance ceilings must increase");
}
assert(activation.activation_core.token.genesis_supply_grain === "0", "activation genesis supply must be zero");
assert(activation.activation_core.issuance.lifetime_mint_ceiling_grain === "1000000000000000000", "lifetime mint ceiling mismatch");
assert(activation.activation_core.issuance.tail_supply_basis === "live_supply_at_anniversary", "tail supply basis mismatch");
assert(BigInt(ceilings.at(-1).max_grain) <= BigInt(activation.activation_core.issuance.lifetime_mint_ceiling_grain), "scheduled issuance exceeds lifetime ceiling");

const genesis = await json("examples/network-genesis.example.json");
assert(genesis.context_epoch === 0, "genesis context epoch must be zero");
assert(genesis.token.activated === false, "initial genesis must be tokenless");
assert(genesis.token.asset_lineage_id === null, "initial genesis asset lineage must be null");
assert(genesis.token.genesis_supply_grain === "0", "initial genesis supply must be zero");
assert(new Set(genesis.external_anchors).size === genesis.external_anchors.length, "genesis anchors must be unique");
const genesisRoles = genesis.ratification_signatures.map((entry) => entry.role);
assert(new Set(genesisRoles).size === genesisRoles.length, "genesis chamber roles must not repeat");
assert(new Set(genesisRoles).size === 3, "genesis must carry all three chamber roles");

const checkpoint = await json("examples/checkpoint.example.json");
assert(BigInt(checkpoint.live_supply_grain) === BigInt(checkpoint.lifetime_minted_grain) - BigInt(checkpoint.lifetime_burned_grain), "checkpoint supply counters do not reconcile");
const anchorKeys = checkpoint.external_anchors.map((entry) => entry.uri + "\n" + entry.reference);
assert(new Set(anchorKeys).size === anchorKeys.length, "checkpoint anchors must be unique by URI and reference");

const recovery = await json("examples/recovery-certificate.example.json");
assert(recovery.old_network_lineage_id === recovery.new_network_lineage_id, "exact recovery must preserve network lineage");
assert(recovery.old_execution_context_id !== recovery.new_execution_context_id, "exact recovery must change execution context");
assert(recovery.new_context_epoch === recovery.old_context_epoch + 1, "exact recovery must increment context epoch once");
assert(recovery.old_asset_lineage_id === recovery.new_asset_lineage_id, "exact recovery must preserve asset lineage or null");

const receipt = await json("examples/service-receipt.example.json");
assert(new Set(receipt.signatures.map((entry) => entry.role)).has("provider"), "service receipt requires a provider signature");

const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
function testSigner(seedByte, chamber, suffix, seatIndex) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.alloc(32, seedByte)]),
    format: "der",
    type: "pkcs8"
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return {
    chamber,
    key_id: "did:key:token-test-" + suffix + "#key-1",
    controller_id: "controller-token-test-" + suffix,
    organization_id: "organization-token-test-" + suffix,
    seatIndex,
    privateKey,
    public_key: publicDer.subarray(-32).toString("base64")
  };
}

const tokenSigners = [
  ...Array.from({ length: 4 }, (_, index) => testSigner(index + 1, "economic", "economic-" + (index + 1), index)),
  ...Array.from({ length: 4 }, (_, index) => testSigner(index + 5, "operator_contributor", "operator-" + (index + 1), index)),
  ...Array.from({ length: 4 }, (_, index) => testSigner(index + 9, "public_data_rights", "public-" + (index + 1), index))
];

const emptyEconomicState = () => ({
  balances: [],
  bonds: [],
  escrows: [],
  fee_pools: [],
  governed_pools: [],
  pending_mints: [],
  pending_burns: [],
  consumed_issuance_receipts: []
});

function buildTokenFixture() {
  const core = structuredClone(activation.activation_core);
  const activeSigners = tokenSigners.filter((entry) => entry.seatIndex < 3);
  const seats = tokenSigners.map((entry) => ({
    chamber: entry.chamber,
    key_id: entry.key_id,
    public_key: entry.public_key,
    voting_weight: "1",
    active: true,
    controller_id: entry.controller_id,
    organization_id: entry.organization_id
  }));
  const governanceManifest = {
    $schema: "../schemas/preactivation-governance.schema.json",
    schema_version: "somavera.preactivation-governance.v1",
    proposal_class: "G2",
    valid_from_height: 0,
    expires_at_height: 15000000,
    chambers: [
      { chamber: "economic", quorum_basis_points: 7500, approval_basis_points: 7500 },
      { chamber: "operator_contributor", quorum_basis_points: 7500, approval_basis_points: 7500 },
      { chamber: "public_data_rights", quorum_basis_points: 7500, approval_basis_points: 7500 }
    ],
    seats
  };
  const governanceManifestHash = preactivationGovernanceManifestHash(governanceManifest);
  core.preactivation_governance_manifest_hash = governanceManifestHash;
  const manifest = {
    schema_version: "vera.token-activation.v1",
    activation_core: core,
    activation_core_hash: activationCoreHash(core),
    asset_lineage_id: "",
    ratification_signatures: []
  };
  manifest.asset_lineage_id = activationAssetLineageId(core.origin_hash, manifest.activation_core_hash);
  const message = tokenRatificationMessage(manifest);
  manifest.ratification_signatures = activeSigners.map((entry) => ({
    chamber: entry.chamber,
    key_id: entry.key_id,
    suite: "Ed25519-v1",
    value: sign(null, Buffer.from(message, "utf8"), entry.privateKey).toString("base64")
  }));
  return {
    manifest,
    preState: {
      state_view: "somavera.token-activation-prestate.v1",
      height: core.activation_height - 1,
      network_lineage_id: core.network_lineage_id,
      origin_hash: core.origin_hash,
      governance: { governance_manifest_hash: governanceManifestHash, manifest: governanceManifest },
      token: {
        activated: false,
        activation_core_hash: null,
        asset_lineage_id: null,
        genesis_supply_grain: "0",
        live_supply_grain: "0",
        lifetime_minted_grain: "0",
        lifetime_burned_grain: "0"
      },
      economic_state: emptyEconomicState()
    },
    transition: { height: core.activation_height, consensus_time: core.activation_time }
  };
}

function expectTokenRejection(name, mutate, requiredCodes) {
  const fixture = buildTokenFixture();
  mutate(fixture);
  const result = validateTokenActivationTransition(fixture);
  assert(!result.ok, name + " was accepted");
  const codes = new Set(result.errors.map((entry) => entry.code));
  for (const code of requiredCodes) assert(codes.has(code), name + " did not report " + code + "; got " + [...codes].join(", "));
}

const validActivation = buildTokenFixture();
const validResult = validateTokenActivationTransition(validActivation);
assert(validResult.ok, "valid token activation failed: " + validResult.errors.map((entry) => entry.code).join(", "));
assert(validActivation.preState.governance.manifest.$schema === "../schemas/preactivation-governance.schema.json", "local schema reference must be accepted");
const governanceWithoutSchema = structuredClone(validActivation.preState.governance.manifest);
delete governanceWithoutSchema.$schema;
assert(
  preactivationGovernanceManifestHash(validActivation.preState.governance.manifest) === preactivationGovernanceManifestHash(governanceWithoutSchema),
  "$schema transport locator changed authenticated governance identity"
);
const governanceSemanticMutation = structuredClone(governanceWithoutSchema);
governanceSemanticMutation.expires_at_height += 1;
assert(
  preactivationGovernanceManifestHash(governanceSemanticMutation) !== preactivationGovernanceManifestHash(governanceWithoutSchema),
  "semantic governance mutation did not change authenticated identity"
);
assert(validActivation.preState.governance.manifest.seats.length === 12, "valid activation must use twelve bootstrap seats");
for (const chamber of ["economic", "operator_contributor", "public_data_rights"]) {
  const seats = validActivation.preState.governance.manifest.seats.filter((entry) => entry.chamber === chamber);
  assert(seats.length === 4, chamber + " must have four bootstrap seats");
  assert(new Set(seats.map((entry) => entry.controller_id)).size === 4, chamber + " controllers must be independent");
  assert(new Set(seats.map((entry) => entry.organization_id)).size === 4, chamber + " organizations must be independent");
}
const activatedState = applyTokenActivationTransition(validActivation);
assert(activatedState.token.activated === true, "activation did not set token active");
assert(activatedState.token.live_supply_grain === "0" && activatedState.token.lifetime_minted_grain === "0", "activation created supply");
assert(Object.values(activatedState.economic_state).every((entries) => Array.isArray(entries) && entries.length === 0), "activation created or preserved economic inventory");

expectTokenRejection("governance manifest mutation", (fixture) => { fixture.preState.governance.manifest.chambers[0].quorum_basis_points = 8000; }, ["PRESTATE_GOVERNANCE_MANIFEST_HASH_MISMATCH"]);
expectTokenRejection("invalid chamber class", (fixture) => { fixture.preState.governance.manifest.chambers[0].chamber = "founder"; }, ["PRESTATE_CHAMBER_CLASS_INVALID"]);
expectTokenRejection("activation quorum below schema minimum", (fixture) => { fixture.preState.governance.manifest.chambers[0].quorum_basis_points = 7499; }, ["PRESTATE_THRESHOLD_INVALID"]);
expectTokenRejection("non-string schema reference", (fixture) => { fixture.preState.governance.manifest.$schema = 1; }, ["PRESTATE_SCHEMA_REFERENCE_INVALID"]);
expectTokenRejection("too few governance seats", (fixture) => { fixture.preState.governance.manifest.seats.pop(); }, ["PRESTATE_SEAT_COUNT_INVALID", "PRESTATE_CHAMBER_INDEPENDENCE_INSUFFICIENT"]);
expectTokenRejection("missing controller", (fixture) => { delete fixture.preState.governance.manifest.seats[0].controller_id; }, ["SHAPE_REQUIRED_FIELD", "PRESTATE_SEAT_INVALID"]);
expectTokenRejection("missing organization", (fixture) => { delete fixture.preState.governance.manifest.seats[0].organization_id; }, ["SHAPE_REQUIRED_FIELD", "PRESTATE_SEAT_INVALID"]);
expectTokenRejection("oversized key identifier", (fixture) => { fixture.preState.governance.manifest.seats[0].key_id = "k".repeat(513); }, ["PRESTATE_SEAT_INVALID"]);
expectTokenRejection("oversized controller identifier", (fixture) => { fixture.preState.governance.manifest.seats[0].controller_id = "c".repeat(257); }, ["PRESTATE_SEAT_INVALID"]);
expectTokenRejection("oversized organization identifier", (fixture) => { fixture.preState.governance.manifest.seats[0].organization_id = "o".repeat(257); }, ["PRESTATE_SEAT_INVALID"]);
expectTokenRejection("controller occupies two seats", (fixture) => { fixture.preState.governance.manifest.seats[1].controller_id = fixture.preState.governance.manifest.seats[0].controller_id; }, ["PRESTATE_CONTROLLER_REUSED", "PRESTATE_CHAMBER_INDEPENDENCE_INSUFFICIENT"]);
expectTokenRejection("organization occupies two seats", (fixture) => { fixture.preState.governance.manifest.seats[1].organization_id = fixture.preState.governance.manifest.seats[0].organization_id; }, ["PRESTATE_ORGANIZATION_REUSED", "PRESTATE_CHAMBER_INDEPENDENCE_INSUFFICIENT"]);
expectTokenRejection("duplicate signer", (fixture) => { fixture.manifest.ratification_signatures.push(structuredClone(fixture.manifest.ratification_signatures[0])); }, ["DUPLICATE_SIGNER_KEY"]);
expectTokenRejection("duplicate allocation recipient", (fixture) => { fixture.manifest.activation_core.epoch_allocation[1].recipient = fixture.manifest.activation_core.epoch_allocation[0].recipient; }, ["SPLIT_RECIPIENT_DUPLICATE"]);
expectTokenRejection("allocation total", (fixture) => { fixture.manifest.activation_core.epoch_allocation[0].basis_points -= 1; }, ["SPLIT_TOTAL_INVALID"]);
expectTokenRejection("noncanonical anchor", (fixture) => { fixture.manifest.activation_core.issuance.cumulative_ceilings[0].max_grain = "01"; }, ["CEILING_MAX_INVALID"]);
expectTokenRejection("duplicate anchor year", (fixture) => { fixture.manifest.activation_core.issuance.cumulative_ceilings[1].elapsed_year = 1; }, ["CEILING_YEARS_NOT_STRICT"]);
expectTokenRejection("decreasing anchor", (fixture) => { fixture.manifest.activation_core.issuance.cumulative_ceilings[2].max_grain = "170000000000000000"; }, ["CEILING_MAX_NOT_STRICT"]);
expectTokenRejection("anchor above lifetime", (fixture) => { fixture.manifest.activation_core.issuance.cumulative_ceilings[4].max_grain = "1000000000000000001"; }, ["CEILING_ABOVE_LIFETIME"]);
expectTokenRejection("invalid tail basis", (fixture) => { fixture.manifest.activation_core.issuance.tail_supply_basis = "circulating_supply"; }, ["TAIL_SUPPLY_BASIS_INVALID"]);
expectTokenRejection("invalid signature role", (fixture) => { fixture.manifest.ratification_signatures[0].chamber = "founder"; }, ["SIGNATURE_CHAMBER_INVALID"]);
expectTokenRejection("nonzero pre-state supply", (fixture) => { fixture.preState.token.live_supply_grain = "1"; }, ["PRESTATE_TOKEN_NOT_ZERO"]);
expectTokenRejection("pre-existing asset lineage", (fixture) => { fixture.preState.token.asset_lineage_id = "vera:rpa:v1:" + "a".repeat(64); }, ["PRESTATE_TOKEN_NOT_ZERO"]);
expectTokenRejection("pre-existing activation hash", (fixture) => { fixture.preState.token.activation_core_hash = "a".repeat(64); }, ["PRESTATE_TOKEN_NOT_ZERO"]);
for (const field of Object.keys(emptyEconomicState())) {
  expectTokenRejection("pre-existing economic state " + field, (fixture) => { fixture.preState.economic_state[field].push({ test_only: true }); }, ["PRESTATE_ECONOMIC_STATE_NONZERO"]);
}
expectTokenRejection("undeclared economic collection", (fixture) => { fixture.preState.economic_state.liquidity_pools = []; }, ["SHAPE_UNKNOWN_FIELD"]);
expectTokenRejection("undeclared top-level economic field", (fixture) => { fixture.preState.treasury_balance_grain = "0"; }, ["SHAPE_UNKNOWN_FIELD"]);
expectTokenRejection("undeclared token field", (fixture) => { fixture.preState.token.premine_grain = "0"; }, ["SHAPE_UNKNOWN_FIELD"]);

const lowQuorum = buildTokenFixture();
const economicSignatureIndex = lowQuorum.manifest.ratification_signatures.findIndex((entry) => entry.chamber === "economic");
lowQuorum.manifest.ratification_signatures.splice(economicSignatureIndex, 1);
const lowQuorumResult = validateTokenActivationTransition(lowQuorum);
assert(!lowQuorumResult.ok, "sub-quorum chamber was accepted");
const lowQuorumCodes = new Set(lowQuorumResult.errors.map((entry) => entry.code));
assert(lowQuorumCodes.has("CHAMBER_QUORUM_NOT_MET"), "sub-quorum chamber did not report quorum failure");
assert(lowQuorumCodes.has("CHAMBER_APPROVAL_NOT_MET"), "sub-quorum chamber did not report approval failure");

const failedApply = buildTokenFixture();
failedApply.preState.economic_state.balances.push({ account: "did:key:test", grain: "1" });
const preApplyState = canonicalize(failedApply.preState);
let applyRejected = false;
try { applyTokenActivationTransition(failedApply); } catch { applyRejected = true; }
assert(applyRejected, "apply accepted nonzero preactivation economic state");
assert(canonicalize(failedApply.preState) === preApplyState, "failed activation mutated pre-state");

const capsuleFiles = await listCapsuleFiles(root);
const forbiddenFile = capsuleFiles.find((entry) => {
  const lower = entry.toLowerCase();
  return lower.endsWith(".pem") || lower.endsWith(".key") || lower.endsWith(".p12") || lower.endsWith(".sqlite") || lower.includes("/secrets/") || lower.includes("/private/");
});
assert(!forbiddenFile, "forbidden private/runtime file in capsule: " + forbiddenFile);

const privateKeyMarker = "-----BEGIN PRIVATE" + " KEY-----";
for (const file of capsuleFiles) {
  const text = await readFile(path.join(root, ...file.split("/")), "utf8").catch(() => "");
  assert(!text.includes(privateKeyMarker), "private-key PEM marker in " + file);
}

console.log("Conformance checks passed: " + checks);
console.log("Note: shape parsing is not full JSON Schema validation.");
