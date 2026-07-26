import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.mjs";

const SUITE_DOMAIN = "somavera:economic-simulation-suite:v1\n";
const REPORT_DOMAIN = "somavera:economic-simulation-report:v1\n";
const REQUIRED_PROFILES = [
  "capped-no-tail",
  "fee-only-native",
  "lower-cap-adaptive",
  "no-native-token-control",
  "scenario-a"
];
const REQUIRED_COVERAGE = [
  "accounting_load", "ambiguous_double_spend", "bootstrap_sunset", "bridge_failure",
  "cartel_30_percent", "cartel_50_percent", "cartel_67_percent", "challenger_griefing",
  "demand_at_capacity", "demand_excess", "demand_low", "exact_succession",
  "issuance_empty", "issuance_full", "liquidity_withdrawal", "major_venue_failure",
  "oracle_failure", "paymaster_failure", "price_down_95_percent", "price_down_99_percent",
  "price_near_zero", "price_up_100x", "price_up_10x", "reciprocal_jobs",
  "stablecoin_failure", "sybil_procurement", "validator_cost_profile_1",
  "validator_cost_profile_2", "validator_cost_profile_3", "validator_cost_profile_4",
  "validator_cost_profile_5", "verifier_bribery", "zero_liquidity"
].sort();
const lexical = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function sha256(domain, value) {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalize(value), "utf8")
    .digest("hex");
}

function without(value, names) {
  return Object.fromEntries(
    Object.entries(value).filter(([name]) => !names.has(name))
  );
}

function uint(value, path) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${path} must be a canonical unsigned integer string`);
  }
  return BigInt(value);
}

function unique(values, path) {
  if (new Set(values).size !== values.length) {
    throw new Error(`${path} contains a duplicate`);
  }
}

function exactShareTotal(shares, path) {
  const total = shares.reduce((sum, value) => sum + value, 0);
  if (total !== 10000) throw new Error(`${path} must total 10000 basis points`);
}

function suiteCore(suite) {
  return without(suite, new Set(["$schema"]));
}

function reportCore(report) {
  return without(report, new Set(["$schema", "report_hash"]));
}

export function economicSimulationSuiteHash(suite) {
  return sha256(SUITE_DOMAIN, suiteCore(suite));
}

export function economicSimulationReportHash(report) {
  return sha256(REPORT_DOMAIN, reportCore(report));
}

export function validateEconomicSimulationSuite(suite) {
  if (suite?.schema_version !== "somavera.economic-simulation-suite.v1") {
    throw new Error("unsupported simulation suite schema");
  }
  if (suite.engine_profile !== "somavera-economic-simulator-integer-v1") {
    throw new Error("unsupported simulation engine profile");
  }

  unique(suite.required_coverage, "required_coverage");
  unique(suite.profiles.map((entry) => entry.profile_id), "profiles.profile_id");
  unique(suite.scenarios.map((entry) => entry.scenario_id), "scenarios.scenario_id");
  const declaredCoverage = [...suite.required_coverage].sort();
  if (canonicalize(declaredCoverage) !== canonicalize(REQUIRED_COVERAGE)) {
    throw new Error("required_coverage does not equal the mandatory engine coverage set");
  }
  const declaredProfiles = suite.profiles.map((entry) => entry.profile_id);
  for (const profileId of REQUIRED_PROFILES) {
    if (!declaredProfiles.includes(profileId)) throw new Error(`missing required comparison profile ${profileId}`);
  }

  for (const profile of suite.profiles) {
    const fee = uint(profile.network_fee_grain_per_service_unit, `${profile.profile_id}.network_fee`);
    const issuance = uint(profile.validator_issuance_grain_per_period, `${profile.profile_id}.validator_issuance`);
    const externalBudget = uint(
      profile.external_security_budget_quote_microunits_per_period,
      `${profile.profile_id}.external_security_budget`
    );
    const bond = uint(profile.native_bond_requirement_grain, `${profile.profile_id}.native_bond`);
    if (profile.architecture === "no_native_token") {
      if (profile.token_decimals !== 0 || fee !== 0n || issuance !== 0n || bond !== 0n ||
          profile.validator_fee_share_basis_points !== 0) {
        throw new Error(`${profile.profile_id} no-native profile contains native-token parameters`);
      }
    } else if (externalBudget !== 0n) {
      throw new Error(`${profile.profile_id} native profile hides an external security subsidy`);
    }
  }

  const observedTags = new Set();
  for (const scenario of suite.scenarios) {
    unique(scenario.coverage_tags, `${scenario.scenario_id}.coverage_tags`);
    scenario.coverage_tags.forEach((tag) => observedTags.add(tag));
    const serviceUnits = uint(scenario.service_units, `${scenario.scenario_id}.service_units`);
    const serviceValue = uint(
      scenario.service_value_quote_microunits_per_unit,
      `${scenario.scenario_id}.service_value`
    );
    const validatorCost = uint(
      scenario.validator_operating_cost_quote_microunits,
      `${scenario.scenario_id}.validator_cost`
    );
    uint(
      scenario.token_price_quote_microunits_per_whole_token,
      `${scenario.scenario_id}.token_price`
    );
    const capacity = uint(scenario.safe_service_capacity_units, `${scenario.scenario_id}.capacity`);
    if (serviceUnits === 0n || serviceValue === 0n || validatorCost === 0n || capacity === 0n) {
      throw new Error(`${scenario.scenario_id} uses a zero denominator or zero workload`);
    }
    exactShareTotal(
      scenario.validator_controller_shares_basis_points,
      `${scenario.scenario_id}.validator_controller_shares`
    );
    exactShareTotal(
      scenario.host_controller_shares_basis_points,
      `${scenario.scenario_id}.host_controller_shares`
    );
  }

  return {
    observedTags,
    missingTags: [...new Set(suite.required_coverage.filter((tag) => !observedTags.has(tag)))].sort()
  };
}

function scenarioResult(profile, scenario, limits) {
  const serviceUnits = BigInt(scenario.service_units);
  const serviceValue = BigInt(scenario.service_value_quote_microunits_per_unit);
  const tokenPrice = BigInt(scenario.token_price_quote_microunits_per_whole_token);
  const validatorCost = BigInt(scenario.validator_operating_cost_quote_microunits);
  const scale = 10n ** BigInt(profile.token_decimals);
  const isNative = profile.architecture === "native_token";

  const feeQuote = isNative
    ? BigInt(profile.network_fee_grain_per_service_unit) * serviceUnits * tokenPrice / scale
    : 0n;
  const claimedIssuance = isNative
    ? BigInt(profile.validator_issuance_grain_per_period) *
      BigInt(scenario.issuance_claim_basis_points) / 10000n
    : 0n;
  const issuanceQuote = isNative ? claimedIssuance * tokenPrice / scale : 0n;
  const validatorFeeQuote = feeQuote * BigInt(profile.validator_fee_share_basis_points) / 10000n;
  const validatorBudget = isNative
    ? validatorFeeQuote + issuanceQuote
    : BigInt(profile.external_security_budget_quote_microunits_per_period);
  const costCoverage = validatorBudget * 10000n / validatorCost;
  const serviceValueTotal = serviceValue * serviceUnits;
  const feeBurden = feeQuote * 10000n / serviceValueTotal;
  const nativeFeeInaccessible = isNative &&
    BigInt(profile.network_fee_grain_per_service_unit) > 0n &&
    !scenario.direct_native_fee_access &&
    !(scenario.paymaster_available && scenario.external_liquidity_available);
  const nativeSecurityBudgetUnrealizable = isNative && validatorBudget > 0n &&
    !scenario.external_liquidity_available;
  const externalSecurityBudgetUnrealizable = !isNative && validatorBudget > 0n &&
    !scenario.external_settlement_available;

  const failures = new Set();
  if (costCoverage < BigInt(limits.minimum_validator_cost_coverage_basis_points)) {
    failures.add("VALIDATOR_COST_COVERAGE_LOW");
  }
  if (feeBurden > BigInt(limits.maximum_fee_burden_basis_points)) {
    failures.add("FEE_BURDEN_HIGH");
  }
  if (nativeFeeInaccessible) failures.add("NATIVE_FEE_ACCESS_UNAVAILABLE");
  if (nativeSecurityBudgetUnrealizable) failures.add("TOKEN_SECURITY_BUDGET_NOT_REALIZABLE");
  if (externalSecurityBudgetUnrealizable) failures.add("EXTERNAL_SECURITY_SETTLEMENT_UNAVAILABLE");
  if (Math.max(...scenario.validator_controller_shares_basis_points) >
      limits.maximum_validator_controller_share_basis_points) {
    failures.add("VALIDATOR_CONTROLLER_CONCENTRATION");
  }
  if (Math.max(...scenario.host_controller_shares_basis_points) >
      limits.maximum_host_controller_share_basis_points) {
    failures.add("HOST_CONTROLLER_CONCENTRATION");
  }
  if (scenario.hostile_validator_power_basis_points >= 3334) {
    failures.add("HOSTILE_VALIDATOR_THRESHOLD");
  }
  if (scenario.hostile_host_share_basis_points >
      limits.maximum_host_controller_share_basis_points) {
    failures.add("HOSTILE_HOST_THRESHOLD");
  }
  if (scenario.sybil_claim_share_basis_points >
      limits.maximum_sybil_claim_share_basis_points) {
    failures.add("SYBIL_CLAIM_SHARE_HIGH");
  }
  if (BigInt(scenario.service_units) > BigInt(scenario.safe_service_capacity_units)) {
    failures.add("SERVICE_CAPACITY_EXCEEDED");
  }
  if (scenario.bootstrap_status === "sunset_missed") {
    failures.add("BOOTSTRAP_SUNSET_MISSED");
  }
  if (scenario.succession_status === "ambiguous_double_spend") {
    failures.add("AMBIGUOUS_SUCCESSION");
  }
  if (profile.public_intelligence_requires_native_token ||
      profile.identity_consent_export_or_exit_requires_native_token) {
    failures.add("SOVEREIGN_RIGHTS_REQUIRE_NATIVE_TOKEN");
  }

  return {
    costCoverage,
    feeBurden,
    nativeFeeInaccessible,
    failures: [...failures].sort()
  };
}

export function runEconomicSimulation(suite) {
  const validation = validateEconomicSimulationSuite(suite);
  const profiles = [...suite.profiles].sort((a, b) => lexical(a.profile_id, b.profile_id));
  const scenarios = [...suite.scenarios].sort((a, b) => lexical(a.scenario_id, b.scenario_id));
  const profileResults = [];

  for (const profile of profiles) {
    const results = scenarios.map((scenario) => scenarioResult(profile, scenario, suite.limits));
    const allFailures = new Set(results.flatMap((entry) => entry.failures));
    profileResults.push({
      profile_id: profile.profile_id,
      scenario_count: scenarios.length,
      failed_scenario_count: results.filter((entry) => entry.failures.length > 0).length,
      minimum_validator_cost_coverage_basis_points:
        results.reduce(
          (minimum, entry) => entry.costCoverage < minimum ? entry.costCoverage : minimum,
          results[0].costCoverage
        ).toString(),
      maximum_fee_burden_basis_points:
        results.reduce(
          (maximum, entry) => entry.feeBurden > maximum ? entry.feeBurden : maximum,
          results[0].feeBurden
        ).toString(),
      native_fee_inaccessible_scenario_count:
        results.filter((entry) => entry.nativeFeeInaccessible).length,
      failure_codes: [...allFailures].sort(),
      decision: "reject_activation"
    });
  }

  const evidence = suite.activation_evidence;
  const globalReasons = new Set();
  if (suite.corpus_status !== "empirical_independently_attested") {
    globalReasons.add("SYNTHETIC_UNATTESTED_CORPUS");
  }
  if (evidence.launch_gates !== "passed") globalReasons.add("LAUNCH_GATES_NOT_PASSED");
  for (const [field, value] of Object.entries(evidence)) {
    if (field !== "launch_gates" && value === null) {
      globalReasons.add(`MISSING_${field.toUpperCase()}`);
    }
  }
  if (validation.missingTags.length > 0) globalReasons.add("REQUIRED_COVERAGE_MISSING");
  if (profileResults.some((entry) => entry.failed_scenario_count > 0)) {
    globalReasons.add("PROFILE_SCENARIO_FAILURES");
  }

  const report = {
    $schema: "../schemas/economic-simulation-report.schema.json",
    schema_version: "somavera.economic-simulation-report.v1",
    engine_profile: suite.engine_profile,
    suite_hash: economicSimulationSuiteHash(suite),
    corpus_status: suite.corpus_status,
    quote_unit_id: suite.quote_unit_id,
    coverage: {
      required_count: suite.required_coverage.length,
      observed_count: validation.observedTags.size,
      missing_tags: validation.missingTags
    },
    profile_results: profileResults,
    engine_conformance: "pass",
    activation_decision: "reject_activation",
    global_reasons: [...globalReasons].sort(),
    report_hash: ""
  };
  report.report_hash = economicSimulationReportHash(report);
  return report;
}
