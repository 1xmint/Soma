import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
let checks = 0;
const assert = (condition, message) => { if (!condition) throw new Error(message); checks += 1; };
const json = async (relative) => JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
const omit = (value, names) => Object.fromEntries(Object.entries(value).filter(([key]) => !names.includes(key)));
const digest = (domain, value) => createHash("sha256").update(domain + "\n", "utf8").update(canonicalize(value), "utf8").digest("hex");

const vectors = await json("conformance/recovery-domain-v1.json");
const governance = await json("examples/" + vectors.fixtures.governance);
const authority = await json("examples/" + vectors.fixtures.recovery_authority);
const policy = await json("examples/" + vectors.fixtures.death_policy);
const evidence = await json("examples/" + vectors.fixtures.death_evidence);
const pkg = await json("examples/" + vectors.fixtures.state_package);
const certificate = await json("examples/" + vectors.fixtures.recovery_certificate);
const receipt = pkg.availability.fetch_receipts[0];
const reproduction = pkg.reproduction_results[0];
const publisher = pkg.publisher_signatures[0];
const observer = evidence.observer_reports[0];
const ratification = certificate.ratification_signatures[0];

const derive = {
  governance: (v) => digest("somavera:preactivation-governance-manifest:v1", omit(v, ["$schema"])),
  authority: (v) => digest("somavera:recovery-authority-manifest:v1", omit(v, ["$schema"])),
  policy: (v) => digest("somavera:recovery-death-policy:v1", omit(v, ["$schema", "policy_id"])),
  observer: (v) => digest("somavera:recovery-observer-report:v1", omit(v, ["signature"])),
  evidence: (v) => digest("somavera:recovery-death-evidence:v1", omit(v, ["$schema", "schema_version", "evidence_id"])),
  receipt: (v) => digest("somavera:checkpoint-state-fetch-receipt:v1", omit(v, ["signature"])),
  reproduction: (v) => digest("somavera:checkpoint-state-reproduction-result:v1", omit(v, ["signature"])),
  package: (v) => digest("somavera:checkpoint-state-package:v1", omit(v, ["$schema", "schema_version", "package_id", "publisher_signatures"])),
  certificate: (v) => digest("somavera:recovery-certificate:v1", omit(v, ["$schema", "schema_version", "certificate_id", "ratification_signatures"]))
};

const packageId = derive.package(pkg);
const certificateId = derive.certificate(certificate);
const actual = {
  preactivation_governance_manifest_hash: derive.governance(governance),
  recovery_authority_manifest_hash: derive.authority(authority),
  recovery_death_policy_id: derive.policy(policy),
  observer_report_hash: derive.observer(observer),
  recovery_death_evidence_id: derive.evidence(evidence),
  fetch_receipt_hash: derive.receipt(receipt),
  reproduction_result_hash: derive.reproduction(reproduction),
  checkpoint_state_package_id: packageId,
  package_publisher_signature_message_hash: digest("somavera:checkpoint-state-package-publisher-signature:v1", { package_id: packageId, role: publisher.role, key_id: publisher.key_id, suite: publisher.suite }),
  recovery_certificate_id: certificateId,
  recovery_ratification_signature_message_hash: digest("somavera:recovery-ratification-signature:v1", { certificate_id: certificateId, role: ratification.role, authority_source: ratification.authority_source, authority_manifest_hash: ratification.authority_manifest_hash, key_id: ratification.key_id, controller_id: ratification.controller_id, suite: ratification.suite })
};

if (process.argv.includes("--print-expected")) {
  console.log(JSON.stringify(actual, null, 2));
  process.exit(0);
}

for (const [name, expected] of Object.entries(vectors.expected)) {
  assert(actual[name] === expected, name + " differs: expected " + expected + ", got " + actual[name]);
}

function excludedUnchanged(name, derivation, source, mutate) {
  const changed = structuredClone(source);
  mutate(changed);
  assert(derivation(source) === derivation(changed), name + " incorrectly includes an excluded field");
}
function includedChanges(name, derivation, source, mutate) {
  const changed = structuredClone(source);
  mutate(changed);
  assert(derivation(source) !== derivation(changed), name + " failed to bind an included field");
}

excludedUnchanged("governance $schema", derive.governance, governance, (v) => { v.$schema = "urn:changed"; });
includedChanges("governance validity", derive.governance, governance, (v) => { v.expires_at_height += 1; });
excludedUnchanged("authority $schema", derive.authority, authority, (v) => { v.$schema = "urn:changed"; });
includedChanges("authority validity", derive.authority, authority, (v) => { v.expires_at_height += 1; });
excludedUnchanged("policy ID", derive.policy, policy, (v) => { v.policy_id = "f".repeat(64); });
includedChanges("policy time bound", derive.policy, policy, (v) => { v.time_bounds.hold_down_seconds += 1; });
excludedUnchanged("observer signature", derive.observer, observer, (v) => { v.signature = "B".repeat(88); });
includedChanges("observer transcript", derive.observer, observer, (v) => { v.transcript_hash = "f".repeat(64); });
excludedUnchanged("evidence ID/version", derive.evidence, evidence, (v) => { v.evidence_id = "f".repeat(64); v.schema_version = "ignored.by.v1.domain"; });
includedChanges("evidence evaluation", derive.evidence, evidence, (v) => { v.evaluated_at = "2028-08-06T00:00:00Z"; });
excludedUnchanged("fetch signature", derive.receipt, receipt, (v) => { v.signature = "B".repeat(88); });
includedChanges("fetch transcript", derive.receipt, receipt, (v) => { v.transcript_hash = "f".repeat(64); });
excludedUnchanged("reproduction signature", derive.reproduction, reproduction, (v) => { v.signature = "B".repeat(88); });
includedChanges("reproduction transcript", derive.reproduction, reproduction, (v) => { v.transcript_hash = "f".repeat(64); });
excludedUnchanged("package ID/signatures", derive.package, pkg, (v) => { v.package_id = "f".repeat(64); v.publisher_signatures[0].value = "B".repeat(88); });
includedChanges("package encoding", derive.package, pkg, (v) => { v.encoding.compression = v.encoding.compression === "none" ? "zstd-deterministic-v1" : "none"; });
includedChanges("package inner receipt signature", derive.package, pkg, (v) => { v.availability.fetch_receipts[0].signature = "B".repeat(88); });
excludedUnchanged("certificate ID/signatures", derive.certificate, certificate, (v) => { v.certificate_id = "f".repeat(64); v.ratification_signatures[0].value = "B".repeat(88); });
includedChanges("certificate governance decision", derive.certificate, certificate, (v) => { v.governance_decision_hash = "f".repeat(64); });

const publisherChangedRole = digest("somavera:checkpoint-state-package-publisher-signature:v1", { package_id: packageId, role: publisher.role === "archive_operator" ? "independent_recovery_auditor" : "archive_operator", key_id: publisher.key_id, suite: publisher.suite });
assert(publisherChangedRole !== actual.package_publisher_signature_message_hash, "publisher signature does not bind role");
const ratificationChangedRole = digest("somavera:recovery-ratification-signature:v1", { certificate_id: certificateId, role: ratification.role === "recovery_guardian" ? "economic_chamber" : "recovery_guardian", authority_source: ratification.authority_source, authority_manifest_hash: ratification.authority_manifest_hash, key_id: ratification.key_id, controller_id: ratification.controller_id, suite: ratification.suite });
assert(ratificationChangedRole !== actual.recovery_ratification_signature_message_hash, "recovery ratification signature does not bind role");

console.log("Recovery identifier-domain checks passed: " + checks);
