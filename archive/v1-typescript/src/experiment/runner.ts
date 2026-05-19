/**
 * Experiment runner — the main orchestrator for Phase 0.
 *
 * Sends every probe to every agent genome, captures streaming responses,
 * extracts phenotypic signals, and saves raw results to disk.
 * Like a field biologist cataloging species: systematic, patient, thorough.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { config } from "dotenv";
import { AGENT_CONFIGS, type AgentConfig } from "./configs.js";
import { ALL_PROBES, type Probe } from "./probes.js";
import { extractAllSignals, type PhenotypicSignals } from "./signals.js";
import { streamFromProvider, streamThroughProxy, resetKeyPool, type StreamingResponse } from "./providers.js";

// Load .env before anything touches process.env
config();

// --- Types ---

export interface ExperimentResult {
  agentId: string;
  probeId: string;
  probeCategory: string;
  responseText: string;
  signals: PhenotypicSignals;
  trace: {
    tokenCount: number;
    startTime: number;
    endTime: number;
    firstTokenTime: number | null;
    /** Raw inter-token intervals (ms) — keeping these for analysis. */
    interTokenIntervals: number[];
  };
  providerMeta: Record<string, unknown>;
  timestamp: number;
  error: string | null;
}

export interface ExperimentRun {
  startedAt: string;
  completedAt: string;
  agentCount: number;
  probeCount: number;
  results: ExperimentResult[];
  errors: Array<{ agentId: string; probeId: string; error: string }>;
}

// --- Runner ---

async function sendProbe(
  agent: AgentConfig,
  probe: Probe
): Promise<ExperimentResult> {
  const startTimestamp = Date.now();

  try {
    let response: StreamingResponse;

    if (agent.isProxy) {
      // Proxy attack: route through simulated network hop
      response = await streamThroughProxy(agent.systemPrompt, probe.prompt);
    } else {
      response = await streamFromProvider(
        agent.provider,
        agent.model,
        agent.systemPrompt,
        probe.prompt
      );
    }

    const signals = extractAllSignals(
      response.text,
      response.trace,
      probe.category
    );

    return {
      agentId: agent.id,
      probeId: probe.id,
      probeCategory: probe.category,
      responseText: response.text,
      signals,
      trace: {
        tokenCount: response.trace.tokens.length,
        startTime: response.trace.startTime,
        endTime: response.trace.endTime,
        firstTokenTime: response.trace.firstTokenTime,
        interTokenIntervals: signals.temporal.interTokenIntervals,
      },
      providerMeta: response.providerMeta,
      timestamp: startTimestamp,
      error: null,
    };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    return {
      agentId: agent.id,
      probeId: probe.id,
      probeCategory: probe.category,
      responseText: "",
      signals: emptySignals(),
      trace: {
        tokenCount: 0,
        startTime: 0,
        endTime: 0,
        firstTokenTime: null,
        interTokenIntervals: [],
      },
      providerMeta: {},
      timestamp: startTimestamp,
      error: errorMessage,
    };
  }
}

function emptySignals(): PhenotypicSignals {
  return {
    cognitive: {
      hedgeCount: 0, certaintyCount: 0, disclaimerCount: 0,
      questionsBack: 0, empathyMarkers: 0, hedgeToCertaintyRatio: 0,
    },
    structural: {
      charCount: 0, wordCount: 0, lineCount: 0, paragraphCount: 0,
      bulletLines: 0, numberedListLines: 0, headerLines: 0, codeBlocks: 0,
      boldCount: 0, listToContentRatio: 0, openingPattern: "direct",
      closingPattern: "statement", avgWordLength: 0, avgSentenceLength: 0,
    },
    temporal: {
      timeToFirstToken: 0, interTokenIntervals: [], meanInterval: 0,
      stdInterval: 0, medianInterval: 0, burstiness: 0,
      totalStreamingDuration: 0, tokenCount: 0,
    },
    error: {
      containsRefusal: false, uncertaintyAdmissions: 0, assertiveWhenWrong: 0,
      attemptedImpossible: false, selfCorrections: 0, confidenceRatio: 0,
    },
  };
}

/** Delay helper for rate limiting. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runExperiment(): Promise<void> {
  const startedAt = new Date().toISOString();

  // --- Filters ---
  // --provider=ollama   — only agents on this provider
  // --agents=id1,id2    — only these agent IDs
  // --limit=30          — max probes per agent (takes from each category proportionally)
  // --category=normal   — only probes from this category
  const providerArg = process.argv.find(a => a.startsWith("--provider="))?.split("=")[1];
  const agentsArg = process.argv.find(a => a.startsWith("--agents="))?.split("=")[1];
  const limitArg = process.argv.find(a => a.startsWith("--limit="))?.split("=")[1];
  const categoryArg = process.argv.find(a => a.startsWith("--category="))?.split("=")[1];

  let filteredAgents = AGENT_CONFIGS;
  if (providerArg) {
    filteredAgents = filteredAgents.filter(a => a.provider === providerArg);
  }
  if (agentsArg) {
    const agentIds = new Set(agentsArg.split(","));
    filteredAgents = filteredAgents.filter(a => agentIds.has(a.id));
  }

  if (filteredAgents.length === 0) {
    console.error(`No agents matched filters (provider=${providerArg ?? "any"}, agents=${agentsArg ?? "all"})`);
    process.exit(1);
  }

  // Filter and limit probes
  let probes = categoryArg
    ? ALL_PROBES.filter(p => p.category === categoryArg)
    : [...ALL_PROBES];

  const probeLimit = limitArg ? parseInt(limitArg, 10) : probes.length;
  if (probeLimit < probes.length) {
    // Take proportionally from each category to maintain diversity
    const categories = [...new Set(probes.map(p => p.category))];
    const perCategory = Math.max(1, Math.floor(probeLimit / categories.length));
    const limited: typeof probes = [];
    for (const cat of categories) {
      const catProbes = probes.filter(p => p.category === cat);
      limited.push(...catProbes.slice(0, perCategory));
      if (limited.length >= probeLimit) break;
    }
    probes = limited.slice(0, probeLimit);
  }

  const total = filteredAgents.length * probes.length;
  console.log(`\n  Soma Sense Experiment`);
  if (providerArg) console.log(`  Provider filter: ${providerArg}`);
  if (agentsArg) console.log(`  Agent filter: ${agentsArg}`);
  if (limitArg) console.log(`  Probe limit: ${probeLimit} per agent`);
  if (categoryArg) console.log(`  Category filter: ${categoryArg}`);
  console.log(`  ${filteredAgents.length} agents x ${probes.length} probes = ${total} observations`);
  console.log(`  Started: ${startedAt}\n`);

  const results: ExperimentResult[] = [];
  const errors: Array<{ agentId: string; probeId: string; error: string }> = [];
  let completed = 0;
  let agentIndex = 0;

  for (const agent of filteredAgents) {
    agentIndex++;
    const agentProgress = `[agent ${agentIndex}/${filteredAgents.length}]`;
    console.log(`\n${"─".repeat(60)}`);
    console.log(`  ${agentProgress} ${agent.label}`);
    console.log(`  provider: ${agent.provider}  model: ${agent.model}`);
    console.log(`${"─".repeat(60)}`);

    let agentErrors = 0;
    let agentSuccess = 0;
    const agentStart = Date.now();

    for (const probe of probes) {
      completed++;
      const progress = `[${completed}/${total}]`;

      try {
        const result = await sendProbe(agent, probe);
        results.push(result);

        if (result.error) {
          agentErrors++;
          console.log(`  ${progress} FAIL ${probe.id} — ${result.error}`);
          errors.push({ agentId: agent.id, probeId: probe.id, error: result.error });
        } else {
          agentSuccess++;
          const tokens = result.trace.tokenCount;
          const duration = result.signals.temporal.totalStreamingDuration.toFixed(0);
          console.log(`  ${progress} OK   ${probe.id} (${probe.category}) ${tokens}tok ${duration}ms`);
        }
      } catch (err) {
        agentErrors++;
        const errorMessage = err instanceof Error ? err.message : String(err);
        console.log(`  ${progress} FAIL ${probe.id} — ${errorMessage}`);
        errors.push({ agentId: agent.id, probeId: probe.id, error: errorMessage });
      }

      // Rate limit delay — per-provider to respect free tier limits
      // Google: 15 RPM = 4s between calls
      // Groq/OpenRouter: 30 RPM free tier = 2s safe margin
      // Others: 500ms default
      const delayMs = agent.provider === "google" ? 4500
        : (agent.provider === "groq" || agent.provider === "openrouter") ? 2000
        : agent.provider === "ollama" ? 100
        : 500;
      await delay(delayMs);
    }

    const agentDuration = ((Date.now() - agentStart) / 1000).toFixed(1);
    console.log(`  => ${agent.id}: ${agentSuccess} ok, ${agentErrors} errors, ${agentDuration}s`);

    // Reset key exhaustion between agents — a key that was 429'd may be fine now
    resetKeyPool();
  }

  const completedAt = new Date().toISOString();

  const run: ExperimentRun = {
    startedAt,
    completedAt,
    agentCount: filteredAgents.length,
    probeCount: probes.length,
    results,
    errors,
  };

  // Save results
  const resultsDir = "results/raw";
  if (!existsSync(resultsDir)) {
    await mkdir(resultsDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const suffix = providerArg ? `-${providerArg}` : "";
  const outputPath = `${resultsDir}/experiment-${timestamp}${suffix}.json`;
  await writeFile(outputPath, JSON.stringify(run, null, 2));

  // Summary
  const successCount = results.filter((r) => !r.error).length;
  console.log(`\n${"═".repeat(50)}`);
  console.log(`  Experiment complete`);
  console.log(`  Successes: ${successCount}/${total}`);
  console.log(`  Errors: ${errors.length}`);
  console.log(`  Results saved: ${outputPath}`);
  console.log(`${"═".repeat(50)}\n`);

  if (errors.length > 0) {
    console.log(`  Errors by agent:`);
    const errorsByAgent = new Map<string, number>();
    for (const e of errors) {
      errorsByAgent.set(e.agentId, (errorsByAgent.get(e.agentId) ?? 0) + 1);
    }
    for (const [agentId, count] of errorsByAgent) {
      console.log(`    ${agentId}: ${count} errors`);
    }
  }
}

// --- Entry Point ---

runExperiment().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error("Experiment failed:", err);
  process.exit(1);
});
