import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  economicSimulationReportHash,
  economicSimulationSuiteHash,
  runEconomicSimulation,
  validateEconomicSimulationSuite
} from "./economic-simulation.mjs";
import { canonicalize } from "./canonicalize.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const readJson = async (relative) =>
  JSON.parse(await readFile(path.join(root, ...relative.split("/")), "utf8"));
const suite = await readJson("examples/economic-simulation-suite.example.json");
const expected = await readJson("examples/economic-simulation-report.example.json");
let checks = 0;
const assert = (condition, message) => {
  if (!condition) throw new Error(`economic simulation conformance failed: ${message}`);
  checks += 1;
};

const report = runEconomicSimulation(suite);
assert(canonicalize(report) === canonicalize(expected), "generated report differs from the committed report");
assert(report.report_hash === economicSimulationReportHash(report), "report hash does not recompute");
assert(report.suite_hash === economicSimulationSuiteHash(suite), "suite hash does not recompute");
assert(report.activation_decision === "reject_activation", "synthetic corpus did not reject activation");
assert(report.global_reasons.includes("SYNTHETIC_UNATTESTED_CORPUS"), "synthetic status was not reported");
assert(report.profile_results.every((entry) => entry.decision === "reject_activation"), "a profile claimed activation eligibility");

const reordered = structuredClone(suite);
reordered.profiles.reverse();
const reorderedReport = runEconomicSimulation(reordered);
assert(
  reorderedReport.profile_results.map((entry) => entry.profile_id).join("\n") ===
    report.profile_results.map((entry) => entry.profile_id).join("\n"),
  "report profile order is not canonical"
);
assert(reorderedReport.suite_hash !== report.suite_hash, "suite hash hid an input array-order change");

const missingCoverage = structuredClone(suite);
missingCoverage.scenarios = missingCoverage.scenarios.filter(
  (entry) => !entry.coverage_tags.includes("ambiguous_double_spend")
);
const missingReport = runEconomicSimulation(missingCoverage);
assert(missingReport.coverage.missing_tags.includes("ambiguous_double_spend"), "missing coverage was not reported");
assert(missingReport.global_reasons.includes("REQUIRED_COVERAGE_MISSING"), "missing coverage did not block activation");

for (const mutate of [
  (value) => { value.profiles[3].network_fee_grain_per_service_unit = "1"; },
  (value) => { value.scenarios[0].validator_controller_shares_basis_points[0] -= 1; },
  (value) => { value.scenarios[0].service_units = "01"; },
  (value) => { value.profiles[0].external_security_budget_quote_microunits_per_period = "1"; },
  (value) => { value.required_coverage.pop(); }
]) {
  const invalid = structuredClone(suite);
  mutate(invalid);
  let rejected = false;
  try {
    validateEconomicSimulationSuite(invalid);
  } catch {
    rejected = true;
  }
  assert(rejected, "semantic mutation was accepted");
}

console.log(`Economic simulation checks passed: ${checks}; activation remains rejected.`);
