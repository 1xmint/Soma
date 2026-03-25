/**
 * Agent-level phenotype experiment.
 *
 * Same LLM (Haiku), four different agent architectures.
 * Can Soma tell them apart from behavioral signals alone?
 *
 * This bridges Phase 0 (LLM-level phenotype) to Phase 1 (agent-level).
 * If it works, Soma can identify not just what model runs, but how
 * it's configured — which is what matters in production.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { config } from "dotenv";
import { ALL_PROBES } from "../probes.js";
import { extractAllSignals, type PhenotypicSignals, type StreamingTrace } from "../signals.js";
import { runBare } from "./bare.js";
import { runRag } from "./rag.js";
import { runToolUse } from "./tool-use.js";
import { runChain } from "./chain.js";
import type { AgentResponse } from "./base.js";
import type { ExperimentResult, ExperimentRun } from "../runner.js";

config();

interface AgentDef {
  id: string;
  label: string;
  run: (prompt: string) => Promise<AgentResponse>;
}

const AGENTS: AgentDef[] = [
  { id: "haiku-bare", label: "Haiku Bare (no tools, no context)", run: runBare },
  { id: "haiku-rag", label: "Haiku RAG (local document retrieval)", run: runRag },
  { id: "haiku-tools", label: "Haiku Tool-Use (calculator, strings)", run: runToolUse },
  { id: "haiku-chain", label: "Haiku Chain (plan → execute)", run: runChain },
];

function emptySignals(): PhenotypicSignals {
  return {
    cognitive: { hedgeCount: 0, certaintyCount: 0, disclaimerCount: 0, questionsBack: 0, empathyMarkers: 0, hedgeToCertaintyRatio: 0 },
    structural: { charCount: 0, wordCount: 0, lineCount: 0, paragraphCount: 0, bulletLines: 0, numberedListLines: 0, headerLines: 0, codeBlocks: 0, boldCount: 0, listToContentRatio: 0, openingPattern: "direct", closingPattern: "statement", avgWordLength: 0, avgSentenceLength: 0 },
    temporal: { timeToFirstToken: 0, interTokenIntervals: [], meanInterval: 0, stdInterval: 0, medianInterval: 0, burstiness: 0, totalStreamingDuration: 0, tokenCount: 0 },
    error: { containsRefusal: false, uncertaintyAdmissions: 0, assertiveWhenWrong: 0, attemptedImpossible: false, selfCorrections: 0, confidenceRatio: 0 },
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  const total = AGENTS.length * ALL_PROBES.length;
  console.log(`\n  Soma Agent-Level Phenotype Experiment`);
  console.log(`  ${AGENTS.length} agent architectures × ${ALL_PROBES.length} probes = ${total} observations`);
  console.log(`  Base LLM: Claude Haiku 4.5 (constant across all agents)\n`);

  const results: ExperimentResult[] = [];
  const errors: Array<{ agentId: string; probeId: string; error: string }> = [];
  let completed = 0;

  for (const agent of AGENTS) {
    console.log(`\n── Agent: ${agent.label} (${agent.id}) ──`);

    for (const probe of ALL_PROBES) {
      completed++;
      const progress = `[${completed}/${total}]`;
      const timestamp = Date.now();

      try {
        const response = await agent.run(probe.prompt);
        const signals = extractAllSignals(response.text, response.trace, probe.category);

        results.push({
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
          providerMeta: { agentType: agent.id, baseLLM: "claude-haiku-4-5" },
          timestamp,
          error: null,
        });

        const tokens = response.trace.tokens.length;
        const duration = signals.temporal.totalStreamingDuration.toFixed(0);
        console.log(`  ${progress} ✓ ${probe.id} (${probe.category}) — ${tokens} tokens, ${duration}ms`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.log(`  ${progress} ❌ ${probe.id} — ${msg}`);
        errors.push({ agentId: agent.id, probeId: probe.id, error: msg });
        results.push({
          agentId: agent.id, probeId: probe.id, probeCategory: probe.category,
          responseText: "", signals: emptySignals(),
          trace: { tokenCount: 0, startTime: 0, endTime: 0, firstTokenTime: null, interTokenIntervals: [] },
          providerMeta: {}, timestamp, error: msg,
        });
      }

      await delay(200);
    }
  }

  const completedAt = new Date().toISOString();
  const run: ExperimentRun = {
    startedAt, completedAt,
    agentCount: AGENTS.length,
    probeCount: ALL_PROBES.length,
    results, errors,
  };

  const dir = "results/raw/agent-experiment";
  if (!existsSync(dir)) await mkdir(dir, { recursive: true });

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = `${dir}/agent-experiment-${ts}.json`;
  await writeFile(outputPath, JSON.stringify(run, null, 2));

  const successCount = results.filter((r) => !r.error).length;
  console.log(`\n${"═".repeat(50)}`);
  console.log(`  Agent experiment complete`);
  console.log(`  Successes: ${successCount}/${total}`);
  console.log(`  Errors: ${errors.length}`);
  console.log(`  Results saved: ${outputPath}`);
  console.log(`${"═".repeat(50)}\n`);

  if (errors.length > 0) {
    const byAgent = new Map<string, number>();
    for (const e of errors) byAgent.set(e.agentId, (byAgent.get(e.agentId) ?? 0) + 1);
    for (const [id, count] of byAgent) console.log(`    ${id}: ${count} errors`);
  }
}

main().catch((err) => { console.error("Agent experiment failed:", err); process.exit(1); });
