import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
let checks = 0;

function assert(condition, message) {
  if (!condition) throw new Error(message);
  checks += 1;
}

async function json(relative) {
  return JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
}

function code(errors, value) {
  if (!errors.includes(value)) errors.push(value);
}

function seconds(value) {
  return Date.parse(value) / 1000;
}

function manifestHash(domain, manifest) {
  const core = Object.fromEntries(Object.entries(manifest).filter(([key]) => key !== "$schema"));
  return createHash("sha256")
    .update(domain + "\n", "utf8")
    .update(canonicalize(core), "utf8")
    .digest("hex");
}

function safeManifestHash(domain, manifest, errors) {
  try {
    return manifestHash(domain, manifest);
  } catch {
    code(errors, "AUTHORITY_MANIFEST_CANONICALIZATION_FAILED");
    return null;
  }
}

function validateBootstrap(manifest) {
  const errors = [];
  const expected = new Set(["economic", "operator_contributor", "public_data_rights"]);
  const policies = new Map();
  for (const policy of manifest.chambers) {
    if (!expected.has(policy.chamber) || policies.has(policy.chamber)) code(errors, "BOOTSTRAP_CHAMBER_SET_INVALID");
    policies.set(policy.chamber, policy);
    if (policy.quorum_basis_points < 7500 || policy.approval_basis_points < 7500) code(errors, "BOOTSTRAP_THRESHOLD_TOO_LOW");
  }
  if (policies.size !== expected.size) code(errors, "BOOTSTRAP_CHAMBER_SET_INVALID");
  if (!(manifest.valid_from_height === 0 && manifest.expires_at_height > manifest.valid_from_height)) code(errors, "BOOTSTRAP_VALIDITY_INVALID");
  const keys = new Set();
  const publicKeys = new Set();
  const controllers = new Set();
  const controllerChambers = new Map();
  for (const seat of manifest.seats) {
    if (keys.has(seat.key_id)) code(errors, "BOOTSTRAP_KEY_DUPLICATE");
    if (publicKeys.has(seat.public_key)) code(errors, "BOOTSTRAP_PUBLIC_KEY_DUPLICATE");
    if (controllers.has(seat.controller_id)) code(errors, "BOOTSTRAP_CONTROLLER_REUSED");
    const prior = controllerChambers.get(seat.controller_id);
    if (prior && prior !== seat.chamber) code(errors, "BOOTSTRAP_CONTROLLER_CROSS_CHAMBER");
    keys.add(seat.key_id);
    publicKeys.add(seat.public_key);
    controllers.add(seat.controller_id);
    controllerChambers.set(seat.controller_id, seat.chamber);
  }
  for (const chamber of expected) {
    const seats = manifest.seats.filter((seat) => seat.chamber === chamber && seat.active);
    if (seats.length < 4 || new Set(seats.map((seat) => seat.organization_id)).size < 4) code(errors, "BOOTSTRAP_INDEPENDENCE_INSUFFICIENT");
  }
  return errors;
}

function validateRecoveryAuthority(manifest, height) {
  const errors = [];
  if (manifest.threshold_count > manifest.guardians.length || manifest.threshold_count < 3) code(errors, "RECOVERY_THRESHOLD_INVALID");
  if (!(manifest.valid_from_height <= height && height < manifest.expires_at_height)) code(errors, "RECOVERY_AUTHORITY_NOT_ACTIVE");
  const active = manifest.guardians.filter((guardian) => guardian.active && guardian.valid_from_height <= height && height < guardian.expires_at_height);
  const controllerCount = new Set(active.map((entry) => entry.controller_id)).size;
  const organizationCount = new Set(active.map((entry) => entry.organization_id)).size;
  const jurisdictionCount = new Set(active.map((entry) => entry.jurisdiction)).size;
  if (controllerCount !== active.length) code(errors, "RECOVERY_CONTROLLER_REUSED");
  if (controllerCount < manifest.minimum_distinct_controllers || organizationCount < manifest.minimum_distinct_organizations || jurisdictionCount < manifest.minimum_distinct_jurisdictions) {
    code(errors, "RECOVERY_AUTHORITY_INDEPENDENCE_INSUFFICIENT");
  }
  if (manifest.controller_reuse_allowed || manifest.self_extension_allowed || manifest.successor_target_keys_may_authorize) code(errors, "RECOVERY_AUTHORITY_LIMIT_INVALID");
  return errors;
}

function validatePackage(pkg, checkpoint, governance, recoveryAuthority) {
  const errors = [];
  const governanceHash = safeManifestHash("somavera:preactivation-governance-manifest:v1", governance, errors);
  const recoveryAuthorityHash = safeManifestHash("somavera:recovery-authority-manifest:v1", recoveryAuthority, errors);
  for (const field of ["network_lineage_id", "execution_context_id", "context_epoch", "checkpoint_id", "height", "block_hash", "app_hash", "public_state_root"]) {
    if (pkg.checkpoint[field] !== checkpoint[field]) code(errors, "PACKAGE_CHECKPOINT_MISMATCH");
  }
  const snapshot = pkg.authority_snapshot;
  if (snapshot.source !== "reproduced_checkpoint_pre_state") code(errors, "AUTHORITY_SNAPSHOT_SOURCE_MISMATCH");
  if (snapshot.checkpoint_id !== checkpoint.checkpoint_id || snapshot.height !== checkpoint.height || snapshot.public_state_root !== checkpoint.public_state_root) code(errors, "AUTHORITY_SNAPSHOT_CHECKPOINT_MISMATCH");
  if (snapshot.governance_manifest_hash !== checkpoint.governance_manifest_hash) code(errors, "AUTHORITY_GOVERNANCE_CHECKPOINT_MISMATCH");
  if (snapshot.recovery_authority_manifest_hash !== checkpoint.recovery_authority_manifest_hash) code(errors, "AUTHORITY_RECOVERY_CHECKPOINT_MISMATCH");
  if (snapshot.validator_set_hash !== checkpoint.validator_set_hash) code(errors, "AUTHORITY_VALIDATOR_SET_MISMATCH");
  if (snapshot.key_history_hash !== checkpoint.key_history_hash) code(errors, "AUTHORITY_KEY_HISTORY_MISMATCH");
  if (snapshot.governance_manifest_hash !== governanceHash) code(errors, "AUTHORITY_GOVERNANCE_MANIFEST_MISMATCH");
  if (snapshot.recovery_authority_manifest_hash !== recoveryAuthorityHash) code(errors, "AUTHORITY_RECOVERY_MANIFEST_MISMATCH");
  if (pkg.recovery_claims.root_alone_sufficient !== false) code(errors, "ROOT_ALONE_FALSE_REQUIRED");
  if (pkg.state_chunk_count !== pkg.state_chunks.length) code(errors, "STATE_CHUNK_COUNT_MISMATCH");
  if (pkg.replay.chunk_count !== pkg.replay.chunks.length) code(errors, "REPLAY_CHUNK_COUNT_MISMATCH");
  pkg.state_chunks.forEach((chunk, index) => {
    if (chunk.order !== index) code(errors, "STATE_CHUNK_ORDER_INVALID");
  });
  pkg.replay.chunks.forEach((chunk, index) => {
    if (chunk.order !== index) code(errors, "REPLAY_CHUNK_ORDER_INVALID");
    const priorHeight = index === 0 ? pkg.replay.base.height : pkg.replay.chunks[index - 1].last_height;
    const priorRoot = index === 0 ? pkg.replay.base.state_root : pkg.replay.chunks[index - 1].post_state_root;
    if (chunk.first_height !== priorHeight + 1 || chunk.last_height < chunk.first_height) code(errors, "REPLAY_HEIGHT_CONTINUITY_INVALID");
    if (chunk.pre_state_root !== priorRoot) code(errors, "REPLAY_ROOT_CONTINUITY_INVALID");
  });
  const lastReplay = pkg.replay.chunks.at(-1);
  if (lastReplay?.last_height !== pkg.checkpoint.height || lastReplay?.post_state_root !== pkg.checkpoint.public_state_root) code(errors, "REPLAY_TERMINUS_MISMATCH");
  if (new Set([...pkg.state_chunks, ...pkg.replay.chunks].map((entry) => entry.path)).size !== pkg.state_chunks.length + pkg.replay.chunks.length) code(errors, "CHUNK_PATH_DUPLICATE");
  if (pkg.checkpoint.checkpoint_id !== checkpoint.checkpoint_id || pkg.checkpoint.height !== checkpoint.height || pkg.checkpoint.public_state_root !== checkpoint.public_state_root || pkg.checkpoint.app_hash !== checkpoint.app_hash) code(errors, "PACKAGE_CHECKPOINT_MISMATCH");

  const locationById = new Map(pkg.availability.locations.map((entry) => [entry.location_id, entry]));
  if (new Set(pkg.availability.locations.map((entry) => entry.organization_id)).size < pkg.availability.minimum_independent_locations) code(errors, "LOCATION_INDEPENDENCE_INSUFFICIENT");
  for (const [kind, chunks] of [["state", pkg.state_chunks], ["replay", pkg.replay.chunks]]) {
    for (const chunk of chunks) {
      const receipts = pkg.availability.fetch_receipts.filter((entry) => entry.kind === kind && entry.order === chunk.order && entry.success);
      for (const receipt of receipts) {
        if (!locationById.has(receipt.location_id)) code(errors, "FETCH_LOCATION_UNKNOWN");
        if (receipt.observed_sha256 !== chunk.sha256) code(errors, "FETCH_HASH_MISMATCH");
        if (receipt.observed_byte_length !== chunk.byte_length) code(errors, "FETCH_SIZE_MISMATCH");
      }
      if (new Set(receipts.map((entry) => entry.location_id)).size < pkg.availability.required_successful_fetches_per_chunk) code(errors, "CHUNK_LOCATION_AVAILABILITY_INSUFFICIENT");
      if (new Set(receipts.map((entry) => entry.fetcher_controller_id)).size < pkg.availability.minimum_distinct_fetch_controllers) code(errors, "CHUNK_FETCH_CONTROLLER_INSUFFICIENT");
      if (new Set(receipts.map((entry) => entry.fetcher_organization_id)).size < pkg.availability.minimum_distinct_fetch_controllers) code(errors, "CHUNK_FETCH_ORGANIZATION_INSUFFICIENT");
    }
  }
  const reproductions = pkg.reproduction_results;
  if (new Set(reproductions.map((entry) => entry.implementation_id)).size < 2 || new Set(reproductions.map((entry) => entry.controller_id)).size < 2 || new Set(reproductions.map((entry) => entry.organization_id)).size < 2) code(errors, "REPRODUCTION_INDEPENDENCE_INSUFFICIENT");
  for (const result of reproductions) {
    if (result.checkpoint_id !== checkpoint.checkpoint_id || result.reproduced_height !== checkpoint.height || result.reproduced_public_state_root !== checkpoint.public_state_root || result.reproduced_app_hash !== checkpoint.app_hash) code(errors, "REPRODUCTION_RESULT_MISMATCH");
    if (result.reproduced_governance_manifest_hash !== snapshot.governance_manifest_hash || result.reproduced_recovery_authority_manifest_hash !== snapshot.recovery_authority_manifest_hash || result.reproduced_validator_set_hash !== snapshot.validator_set_hash || result.reproduced_key_history_hash !== snapshot.key_history_hash) {
      code(errors, "REPRODUCTION_AUTHORITY_SNAPSHOT_MISMATCH");
    }
  }
  return errors;
}

function validateDeathEvidence(evidence, policy, checkpoint, pkg) {
  const errors = [];
  if (evidence.death_policy_id !== policy.policy_id) code(errors, "DEATH_POLICY_BINDING_MISMATCH");
  if (evidence.candidate_checkpoint.checkpoint_id !== checkpoint.checkpoint_id || evidence.candidate_checkpoint.state_package_id !== pkg.package_id) code(errors, "DEATH_CHECKPOINT_BINDING_MISMATCH");
  const w = evidence.windows;
  if (seconds(w.discovery_ended_at) - seconds(w.discovery_started_at) < policy.time_bounds.discovery_window_seconds) code(errors, "DISCOVERY_WINDOW_TOO_SHORT");
  if (seconds(w.observation_ended_at) - seconds(w.observation_started_at) < policy.time_bounds.continuous_observation_seconds) code(errors, "OBSERVATION_WINDOW_TOO_SHORT");
  if (seconds(w.hold_down_ended_at) - seconds(w.hold_down_started_at) < policy.time_bounds.hold_down_seconds) code(errors, "HOLD_DOWN_TOO_SHORT");
  if (!(seconds(w.discovery_ended_at) <= seconds(w.observation_started_at) && seconds(w.observation_ended_at) <= seconds(w.hold_down_started_at) && seconds(w.hold_down_ended_at) <= seconds(evidence.evaluated_at))) code(errors, "DEATH_WINDOW_ORDER_INVALID");
  if (seconds(evidence.newest_obtainable_finality.finalized_at) + policy.time_bounds.finalization_freshness_seconds > seconds(w.observation_started_at)) code(errors, "FINALITY_NOT_STALE_AT_OBSERVATION_START");
  if (seconds(evidence.evaluated_at) - seconds(evidence.newest_obtainable_finality.observed_at) > policy.time_bounds.finality_observation_max_age_seconds) code(errors, "FINALITY_OBSERVATION_STALE");

  const reports = evidence.observer_reports;
  const requirements = policy.observer_requirements;
  if (reports.length < requirements.minimum_independent_observers || new Set(reports.map((entry) => entry.controller_id)).size < requirements.minimum_distinct_controllers || new Set(reports.map((entry) => entry.organization_id)).size < requirements.minimum_distinct_organizations || new Set(reports.map((entry) => entry.jurisdiction)).size < requirements.minimum_distinct_jurisdictions || new Set(reports.map((entry) => entry.network_path_id)).size < requirements.minimum_distinct_network_paths) code(errors, "OBSERVER_INDEPENDENCE_INSUFFICIENT");
  for (const report of reports) {
    if (seconds(report.observed_from) > seconds(w.observation_started_at) || seconds(report.observed_through) < seconds(w.hold_down_ended_at)) code(errors, "OBSERVER_WINDOW_INCOMPLETE");
    if (report.maximum_observed_clock_skew_seconds > policy.time_bounds.maximum_clock_skew_seconds) code(errors, "OBSERVER_CLOCK_SKEW_EXCEEDED");
    if (seconds(report.report_signed_at) - seconds(report.newest_valid_finality.observed_at) > policy.time_bounds.finality_observation_max_age_seconds) code(errors, "FINALITY_OBSERVATION_STALE");
    if (seconds(report.search_result.searched_through) < seconds(evidence.evaluated_at)) code(errors, "CONFLICT_SEARCH_INCOMPLETE");
    if (report.search_result.fresh_finality_found) code(errors, "FRESH_FINALITY_RESETS_DEATH_WINDOW");
    if (report.search_result.conflicting_finality_found || report.search_result.competing_succession_found) code(errors, "CONFLICTING_FINALITY_ABORT");
  }
  if (evidence.late_finality_proofs.length > 0) code(errors, "LATE_FRESH_FINALITY_ABORT");
  if (evidence.conflicting_proofs.length > 0) code(errors, "CONFLICTING_FINALITY_ABORT");
  if (evidence.result !== "predicate_satisfied") code(errors, "DEATH_PREDICATE_NOT_SATISFIED");
  if (!evidence.limitations.bounded_policy_only || evidence.limitations.absolute_death_proven || evidence.limitations.hidden_partition_excluded || evidence.limitations.universal_social_adoption_forced) code(errors, "DEATH_LIMITATION_OVERCLAIM");
  return errors;
}

function signedWeightBasisPoints(manifest, chamber, signatures) {
  const seats = manifest.seats.filter((seat) => seat.chamber === chamber && seat.active);
  const total = seats.reduce((sum, seat) => sum + BigInt(seat.voting_weight), 0n);
  const signed = new Set(signatures.map((entry) => entry.key_id));
  const approved = seats.filter((seat) => signed.has(seat.key_id)).reduce((sum, seat) => sum + BigInt(seat.voting_weight), 0n);
  return total === 0n ? 0 : Number(approved * 10000n / total);
}

function validateCertificate(certificate, checkpoint, pkg, evidence, policy, governance, recoveryAuthority) {
  const errors = [];
  if (certificate.mode !== "exact_continuity") code(errors, "RECOVERY_MODE_INVALID");
  if (certificate.old_network_lineage_id !== certificate.new_network_lineage_id || certificate.old_execution_context_id === certificate.new_execution_context_id || certificate.new_context_epoch !== certificate.old_context_epoch + 1) code(errors, "CONTINUITY_ID_INVARIANT_INVALID");
  if (certificate.old_asset_lineage_id !== certificate.new_asset_lineage_id) code(errors, "ASSET_LINEAGE_CHANGED");
  if (certificate.last_checkpoint_id !== checkpoint.checkpoint_id || certificate.last_checkpoint_height !== checkpoint.height || certificate.checkpoint_state_package_id !== pkg.package_id || certificate.imported_state_root !== checkpoint.public_state_root) code(errors, "RECOVERY_STATE_PACKAGE_BINDING_MISMATCH");
  if (certificate.death_policy_id !== policy.policy_id || certificate.death_evidence_id !== evidence.evidence_id) code(errors, "RECOVERY_DEATH_BINDING_MISMATCH");
  for (const field of ["governance_manifest_hash", "recovery_authority_manifest_hash", "validator_set_hash", "key_history_hash"]) {
    if (certificate.pre_state_authority[field] !== pkg.authority_snapshot[field]) code(errors, "PRESTATE_AUTHORITY_BINDING_MISMATCH");
  }
  const preStateAuthority = certificate.pre_state_authority;
  const governanceHash = safeManifestHash("somavera:preactivation-governance-manifest:v1", governance, errors);
  const recoveryAuthorityHash = safeManifestHash("somavera:recovery-authority-manifest:v1", recoveryAuthority, errors);
  if (preStateAuthority.source !== "reproduced_checkpoint_pre_state") code(errors, "CERTIFICATE_PRESTATE_AUTHORITY_MISMATCH");
  if (preStateAuthority.checkpoint_id !== checkpoint.checkpoint_id || preStateAuthority.height !== checkpoint.height || preStateAuthority.public_state_root !== checkpoint.public_state_root) code(errors, "CERTIFICATE_PRESTATE_AUTHORITY_MISMATCH");
  if (preStateAuthority.governance_manifest_hash !== governanceHash || preStateAuthority.recovery_authority_manifest_hash !== recoveryAuthorityHash) code(errors, "CERTIFICATE_PRESTATE_AUTHORITY_MISMATCH");
  if (preStateAuthority.validator_set_hash !== checkpoint.validator_set_hash || preStateAuthority.key_history_hash !== checkpoint.key_history_hash) code(errors, "CERTIFICATE_PRESTATE_AUTHORITY_MISMATCH");
  if (seconds(certificate.challenge_ends_at) - seconds(certificate.challenge_started_at) < policy.time_bounds.challenge_seconds || seconds(certificate.activation_not_before) < seconds(certificate.challenge_ends_at) || seconds(certificate.conflict_abort_status.checked_through) < seconds(certificate.activation_not_before)) code(errors, "RECOVERY_CHALLENGE_WINDOW_INVALID");
  if (certificate.conflict_abort_status.fresh_finality_detected || certificate.conflict_abort_status.conflicting_finality_detected || certificate.conflict_abort_status.competing_succession_detected) code(errors, "RECOVERY_CONFLICT_ABORT_REQUIRED");

  const targetKeys = new Set(certificate.successor_target_keys.map((entry) => entry.key_id));
  const signerKeys = new Set();
  const guardians = new Map(recoveryAuthority.guardians.map((entry) => [entry.key_id, entry]));
  const seats = new Map(governance.seats.map((entry) => [entry.key_id, entry]));
  const guardianSigners = [];
  const chamberSigners = { economic: [], operator_contributor: [], public_data_rights: [] };
  for (const signature of certificate.ratification_signatures) {
    if (signerKeys.has(signature.key_id)) code(errors, "RECOVERY_SIGNER_DUPLICATE");
    signerKeys.add(signature.key_id);
    if (targetKeys.has(signature.key_id)) code(errors, "SUCCESSOR_KEY_SELF_AUTHORIZATION");
    if (signature.role === "recovery_guardian") {
      const guardian = guardians.get(signature.key_id);
      if (!guardian || guardian.controller_id !== signature.controller_id || signature.authority_manifest_hash !== certificate.pre_state_authority.recovery_authority_manifest_hash) code(errors, "SIGNER_NOT_PRESTATE_AUTHORIZED");
      else guardianSigners.push(signature);
    } else {
      const chamber = signature.role.replace(/_chamber$/, "");
      const seat = seats.get(signature.key_id);
      if (!seat || seat.chamber !== chamber || seat.controller_id !== signature.controller_id || signature.authority_manifest_hash !== certificate.pre_state_authority.governance_manifest_hash) code(errors, "SIGNER_NOT_PRESTATE_AUTHORIZED");
      else chamberSigners[chamber]?.push(signature);
    }
  }
  if (guardianSigners.length < recoveryAuthority.threshold_count || new Set(guardianSigners.map((entry) => entry.controller_id)).size < recoveryAuthority.threshold_count) code(errors, "RECOVERY_GUARDIAN_THRESHOLD_NOT_MET");
  for (const policyEntry of governance.chambers) {
    const basisPoints = signedWeightBasisPoints(governance, policyEntry.chamber, chamberSigners[policyEntry.chamber] ?? []);
    if (basisPoints < policyEntry.quorum_basis_points || basisPoints < policyEntry.approval_basis_points) code(errors, "RECOVERY_CHAMBER_THRESHOLD_NOT_MET");
  }
  return errors;
}

function mutateFixture(name, fixture) {
  if (name === "remove_state_chunk") fixture.pkg.state_chunks.pop();
  if (name === "remove_replay_chunk") fixture.pkg.replay.chunks.pop();
  if (name === "swap_state_chunks") fixture.pkg.state_chunks.reverse();
  if (name === "corrupt_fetch_hash") fixture.pkg.availability.fetch_receipts[0].observed_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  if (name === "self_authorize_successor_key") {
    const target = fixture.certificate.successor_target_keys[0];
    fixture.certificate.ratification_signatures[0].key_id = target.key_id;
    fixture.certificate.ratification_signatures[0].controller_id = "controller-successor-validator-1";
  }
  if (name === "remove_guardian_signature") {
    const index = fixture.certificate.ratification_signatures.findIndex((entry) => entry.role === "recovery_guardian");
    fixture.certificate.ratification_signatures.splice(index, 1);
  }
  if (name === "stale_finality_observation") fixture.evidence.observer_reports[0].newest_valid_finality.observed_at = "2028-01-01T00:00:00Z";
  if (name === "late_fresh_finality") fixture.evidence.late_finality_proofs.push({ proof: structuredClone(fixture.evidence.newest_obtainable_finality), received_at: "2028-08-05T00:00:00Z" });
  if (name === "conflicting_finality") fixture.evidence.observer_reports[0].search_result.conflicting_finality_found = true;
  if (name === "mismatched_validator_set") fixture.pkg.authority_snapshot.validator_set_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  if (name === "substituted_governance_manifest") fixture.governance.seats[0].controller_id += "-substituted";
  if (name === "substituted_recovery_manifest") fixture.recoveryAuthority.guardians[0].controller_id += "-substituted";
  if (name === "joint_authority_substitution") {
    const malicious = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    fixture.pkg.authority_snapshot.governance_manifest_hash = malicious;
    fixture.certificate.pre_state_authority.governance_manifest_hash = malicious;
    for (const result of fixture.pkg.reproduction_results) result.reproduced_governance_manifest_hash = malicious;
    for (const signature of fixture.certificate.ratification_signatures) if (signature.role !== "recovery_guardian") signature.authority_manifest_hash = malicious;
  }
}

const [genesis, checkpoint, governance, recoveryAuthority, pkg, policy, evidence, certificate, vectors] = await Promise.all([
  json("examples/network-genesis.example.json"),
  json("examples/checkpoint.example.json"),
  json("examples/preactivation-governance.example.json"),
  json("examples/recovery-authority.example.json"),
  json("examples/checkpoint-state-package.example.json"),
  json("examples/recovery-death-policy.example.json"),
  json("examples/recovery-death-evidence.example.json"),
  json("examples/recovery-certificate.example.json"),
  json("conformance/recovery-adversarial-v1.json")
]);

assert(validateBootstrap(governance).length === 0, "valid bootstrap authority manifest failed");
assert(validateRecoveryAuthority(recoveryAuthority, checkpoint.height).length === 0, "valid recovery authority manifest failed");
const governanceManifestHash = manifestHash("somavera:preactivation-governance-manifest:v1", governance);
const recoveryAuthorityManifestHash = manifestHash("somavera:recovery-authority-manifest:v1", recoveryAuthority);
assert(genesis.recovery_policy.old_network_death_policy_hash === policy.policy_id, "genesis does not bind the death policy ID");
assert(genesis.governance.governance_manifest_hash === governanceManifestHash, "genesis does not bind exact governance manifest bytes");
assert(genesis.recovery_policy.guardian_manifest_hash === recoveryAuthorityManifestHash, "genesis does not bind exact recovery authority bytes");
assert(checkpoint.governance_manifest_hash === governanceManifestHash && checkpoint.recovery_authority_manifest_hash === recoveryAuthorityManifestHash, "checkpoint authority hashes do not match exact manifests");
assert(checkpoint.asset_lineage_id === null && checkpoint.live_supply_grain === "0" && genesis.token.activated === false, "recovery fixtures must remain token-disabled");

const validPackageErrors = validatePackage(pkg, checkpoint, governance, recoveryAuthority);
assert(validPackageErrors.length === 0, "valid checkpoint package failed: " + validPackageErrors.join(", "));
const validDeathErrors = validateDeathEvidence(evidence, policy, checkpoint, pkg);
assert(validDeathErrors.length === 0, "valid death evidence failed: " + validDeathErrors.join(", "));
const validCertificateErrors = validateCertificate(certificate, checkpoint, pkg, evidence, policy, governance, recoveryAuthority);
assert(validCertificateErrors.length === 0, "valid recovery certificate failed: " + validCertificateErrors.join(", "));

for (const vector of vectors.cases) {
  const fixture = {
    pkg: structuredClone(pkg),
    evidence: structuredClone(evidence),
    certificate: structuredClone(certificate),
    governance: structuredClone(governance),
    recoveryAuthority: structuredClone(recoveryAuthority)
  };
  mutateFixture(vector.mutation, fixture);
  const errors = [
    ...validatePackage(fixture.pkg, checkpoint, fixture.governance, fixture.recoveryAuthority),
    ...validateDeathEvidence(fixture.evidence, policy, checkpoint, fixture.pkg),
    ...validateCertificate(fixture.certificate, checkpoint, fixture.pkg, fixture.evidence, policy, fixture.governance, fixture.recoveryAuthority)
  ];
  for (const expected of vector.expected_codes) assert(errors.includes(expected), vector.name + " did not report " + expected + "; got " + errors.join(", "));
}

console.log("Recovery machine-contract checks passed: " + checks);
console.log("Draft hash profiles and real ratification signatures remain unratified; fixtures are non-live and token-disabled.");
