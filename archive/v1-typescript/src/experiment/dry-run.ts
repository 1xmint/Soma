/**
 * Dry-run script — test each provider with 3 probes before the full experiment.
 * Prints raw temporal data so we can verify real streaming is working.
 */

import { config } from "dotenv";
import { streamFromProvider } from "./providers.js";
import { extractAllSignals } from "./signals.js";
import type { ProviderName } from "./configs.js";

config();

interface ProviderTest {
  name: string;
  provider: ProviderName;
  model: string;
}

const PROVIDERS: ProviderTest[] = [
  { name: "Groq (Llama 3.3 70B)", provider: "groq", model: "llama-3.3-70b-versatile" },
  { name: "Mistral (Small)", provider: "mistral", model: "mistral-small-latest" },
  { name: "OpenRouter (DeepSeek V3)", provider: "openrouter", model: "deepseek/deepseek-v3.2-20251201" },
  { name: "Anthropic (Haiku)", provider: "anthropic", model: "claude-haiku-4-5-20251001" },
  { name: "OpenAI (GPT-4o Mini)", provider: "openai", model: "gpt-4o-mini" },
];

const TEST_PROBES = [
  { id: "rapid-1", prompt: "What is 2+2?", category: "rapid_fire" },
  { id: "normal-1", prompt: "Explain what a hash function is in two sentences.", category: "normal" },
  { id: "ambiguity-1", prompt: "Should I learn Rust or Go?", category: "ambiguity" },
];

const SYSTEM_PROMPT = "You are a helpful assistant.";

async function testProvider(test: ProviderTest): Promise<boolean> {
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  PROVIDER: ${test.name}`);
  console.log(`  Model: ${test.model}`);
  console.log(`${"═".repeat(60)}`);

  let allGood = true;

  for (const probe of TEST_PROBES) {
    console.log(`\n  ── Probe: ${probe.id} ("${probe.prompt.slice(0, 50)}") ──`);

    try {
      const response = await streamFromProvider(
        test.provider,
        test.model,
        SYSTEM_PROMPT,
        probe.prompt
      );

      const signals = extractAllSignals(response.text, response.trace, probe.category);

      // Raw trace data
      const trace = response.trace;
      const intervalCount = trace.tokenTimestamps.length > 1
        ? trace.tokenTimestamps.length - 1
        : 0;

      console.log(`\n  Response (first 200 chars): "${response.text.slice(0, 200)}"`);
      console.log(`\n  RAW TRACE:`);
      console.log(`    Token count:       ${trace.tokens.length}`);
      console.log(`    startTime:         ${trace.startTime.toFixed(2)}ms`);
      console.log(`    firstTokenTime:    ${trace.firstTokenTime?.toFixed(2) ?? "NULL"}`);
      console.log(`    endTime:           ${trace.endTime.toFixed(2)}ms`);
      console.log(`    Timestamps array:  ${trace.tokenTimestamps.length} entries`);

      // Show first 10 raw timestamps
      const first10 = trace.tokenTimestamps.slice(0, 10).map((t) => t.toFixed(2));
      console.log(`    First 10 timestamps: [${first10.join(", ")}]`);

      // Show first 10 inter-token intervals
      const intervals: number[] = [];
      for (let i = 1; i < trace.tokenTimestamps.length; i++) {
        intervals.push(trace.tokenTimestamps[i] - trace.tokenTimestamps[i - 1]);
      }
      const first10intervals = intervals.slice(0, 10).map((v) => v.toFixed(2));
      console.log(`    First 10 intervals:  [${first10intervals.join(", ")}]ms`);

      console.log(`\n  EXTRACTED TEMPORAL SIGNALS:`);
      console.log(`    timeToFirstToken:      ${signals.temporal.timeToFirstToken.toFixed(2)}ms`);
      console.log(`    meanInterval:          ${signals.temporal.meanInterval.toFixed(2)}ms`);
      console.log(`    stdInterval:           ${signals.temporal.stdInterval.toFixed(2)}ms`);
      console.log(`    medianInterval:        ${signals.temporal.medianInterval.toFixed(2)}ms`);
      console.log(`    burstiness:            ${signals.temporal.burstiness.toFixed(2)}`);
      console.log(`    totalStreamingDuration:${signals.temporal.totalStreamingDuration.toFixed(2)}ms`);
      console.log(`    tokenCount:            ${signals.temporal.tokenCount}`);
      console.log(`    intervalArrayLength:   ${signals.temporal.interTokenIntervals.length}`);

      console.log(`\n  Provider meta: ${JSON.stringify(response.providerMeta)}`);

      // Validation checks
      const issues: string[] = [];
      if (trace.firstTokenTime === null) issues.push("firstTokenTime is NULL");
      if (trace.tokens.length === 0) issues.push("zero tokens");
      if (trace.tokenTimestamps.length === 0) issues.push("zero timestamps");
      if (trace.tokenTimestamps.length !== trace.tokens.length) {
        issues.push(`timestamp/token mismatch: ${trace.tokenTimestamps.length} vs ${trace.tokens.length}`);
      }
      if (intervalCount === 0) issues.push("no inter-token intervals (only 1 token?)");
      if (intervals.length > 0 && intervals.every((v) => v === 0)) {
        issues.push("ALL intervals are 0ms — streaming may not be real");
      }
      if (signals.temporal.meanInterval === 0 && trace.tokens.length > 1) {
        issues.push("meanInterval is 0 with multiple tokens — suspicious");
      }

      if (issues.length > 0) {
        console.log(`\n  ⚠️  ISSUES: ${issues.join("; ")}`);
        allGood = false;
      } else {
        console.log(`\n  ✅ CLEAN — real streaming data confirmed`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`\n  ❌ ERROR: ${msg}`);
      allGood = false;
    }
  }

  return allGood;
}

async function main(): Promise<void> {
  const providerArg = process.argv[2];

  let providers: ProviderTest[];
  if (providerArg) {
    const match = PROVIDERS.find((p) => p.provider === providerArg);
    if (!match) {
      console.error(`Unknown provider: ${providerArg}. Options: ${PROVIDERS.map((p) => p.provider).join(", ")}`);
      process.exit(1);
    }
    providers = [match];
  } else {
    providers = PROVIDERS;
  }

  console.log("\n🧬 Soma Dry Run — Verifying streaming data capture\n");

  const results: Array<{ name: string; ok: boolean }> = [];

  for (const p of providers) {
    const ok = await testProvider(p);
    results.push({ name: p.name, ok });
  }

  console.log(`\n\n${"═".repeat(60)}`);
  console.log("  DRY RUN SUMMARY");
  console.log(`${"═".repeat(60)}`);
  for (const r of results) {
    console.log(`  ${r.ok ? "✅" : "❌"} ${r.name}`);
  }

  const allPassed = results.every((r) => r.ok);
  if (allPassed) {
    console.log(`\n  All providers returning clean streaming data.`);
    console.log(`  Safe to run full experiment: pnpm run experiment\n`);
  } else {
    console.log(`\n  ⚠️  Some providers have issues. Fix before full run.\n`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Dry run failed:", err);
  process.exit(1);
});
