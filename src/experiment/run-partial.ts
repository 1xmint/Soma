/**
 * Partial experiment runner — runs specific agents and merges with existing results.
 * Usage: npx tsx src/experiment/run-partial.ts <agent-id> [agent-id...]
 * If --merge <file> is passed, merges new results into that file.
 */

import { writeFile, readFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { config } from "dotenv";
import { AGENT_CONFIGS, type AgentConfig } from "./configs.js";
import { ALL_PROBES } from "./probes.js";
import { extractAllSignals, type PhenotypicSignals } from "./signals.js";
import { streamFromProvider, streamThroughProxy, type StreamingResponse } from "./providers.js";
import type { ExperimentResult, ExperimentRun } from "./runner.js";

config();

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function sendProbe(
  agent: AgentConfig,
  probe: { id: string; prompt: string; category: string }
): Promise<ExperimentResult> {
  const startTimestamp = Date.now();
  try {
    let response: StreamingResponse;
    if (agent.isProxy) {
      response = await streamThroughProxy(agent.systemPrompt, probe.prompt);
    } else {
      response = await streamFromProvider(agent.provider, agent.model, agent.systemPrompt, probe.prompt);
    }
    const signals = extractAllSignals(response.text, response.trace, probe.category);
    return {
      agentId: agent.id, probeId: probe.id, probeCategory: probe.category,
      responseText: response.text, signals,
      trace: {
        tokenCount: response.trace.tokens.length,
        startTime: response.trace.startTime, endTime: response.trace.endTime,
        firstTokenTime: response.trace.firstTokenTime,
        interTokenIntervals: signals.temporal.interTokenIntervals,
      },
      providerMeta: response.providerMeta, timestamp: startTimestamp, error: null,
    };
  } catch (err) {
    return {
      agentId: agent.id, probeId: probe.id, probeCategory: probe.category,
      responseText: "", signals: emptySignals(),
      trace: { tokenCount: 0, startTime: 0, endTime: 0, firstTokenTime: null, interTokenIntervals: [] },
      providerMeta: {}, timestamp: startTimestamp,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let mergeFile: string | null = null;
  const agentIds: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--merge" && args[i + 1]) {
      mergeFile = args[++i];
    } else {
      agentIds.push(args[i]);
    }
  }

  if (agentIds.length === 0) {
    console.error("Usage: npx tsx src/experiment/run-partial.ts <agent-id> [agent-id...] [--merge <file>]");
    console.error("Available agents:", AGENT_CONFIGS.map((c) => c.id).join(", "));
    process.exit(1);
  }

  const agents = agentIds.map((id) => {
    const agent = AGENT_CONFIGS.find((c) => c.id === id);
    if (!agent) { console.error(`Unknown agent: ${id}`); process.exit(1); }
    return agent;
  });

  const total = agents.length * ALL_PROBES.length;
  console.log(`\n  Soma Partial Run — ${agents.length} agents × ${ALL_PROBES.length} probes = ${total} observations\n`);

  const results: ExperimentResult[] = [];
  const errors: Array<{ agentId: string; probeId: string; error: string }> = [];
  let completed = 0;

  for (const agent of agents) {
    console.log(`\n── Agent: ${agent.label} (${agent.id}) ──`);
    for (const probe of ALL_PROBES) {
      completed++;
      const progress = `[${completed}/${total}]`;
      const result = await sendProbe(agent, probe);
      results.push(result);
      if (result.error) {
        console.log(`  ${progress} ❌ ${probe.id} — ${result.error}`);
        errors.push({ agentId: agent.id, probeId: probe.id, error: result.error });
      } else {
        const tokens = result.trace.tokenCount;
        const duration = result.signals.temporal.totalStreamingDuration.toFixed(0);
        console.log(`  ${progress} ✓ ${probe.id} (${probe.category}) — ${tokens} tokens, ${duration}ms`);
      }
      await delay(200);
    }
  }

  const successCount = results.filter((r) => !r.error).length;
  console.log(`\n  Partial run complete: ${successCount}/${total} successes, ${errors.length} errors`);

  // Merge with existing results if specified
  if (mergeFile && existsSync(mergeFile)) {
    console.log(`\n  Merging with ${mergeFile}...`);
    const existing: ExperimentRun = JSON.parse(await readFile(mergeFile, "utf-8"));

    // Remove old results for these agents (replace with fresh data)
    const newAgentIds = new Set(agentIds);
    const kept = existing.results.filter((r) => !newAgentIds.has(r.agentId));
    const keptErrors = existing.errors.filter((e) => !newAgentIds.has(e.agentId));

    const merged: ExperimentRun = {
      startedAt: existing.startedAt,
      completedAt: new Date().toISOString(),
      agentCount: new Set([...kept.map((r) => r.agentId), ...results.map((r) => r.agentId)]).size,
      probeCount: existing.probeCount,
      results: [...kept, ...results],
      errors: [...keptErrors, ...errors],
    };

    await writeFile(mergeFile, JSON.stringify(merged, null, 2));
    const totalValid = merged.results.filter((r) => !r.error).length;
    console.log(`  Merged: ${totalValid} valid results from ${merged.agentCount} agents`);
    console.log(`  Saved: ${mergeFile}\n`);
  } else {
    // Save as new file
    const dir = "results/raw";
    if (!existsSync(dir)) await mkdir(dir, { recursive: true });
    const run: ExperimentRun = {
      startedAt: new Date().toISOString(), completedAt: new Date().toISOString(),
      agentCount: agents.length, probeCount: ALL_PROBES.length,
      results, errors,
    };
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const path = `${dir}/experiment-partial-${ts}.json`;
    await writeFile(path, JSON.stringify(run, null, 2));
    console.log(`  Saved: ${path}\n`);
  }
}

main().catch((err) => { console.error("Partial run failed:", err); process.exit(1); });
