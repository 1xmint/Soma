/**
 * Merge per-provider experiment results and run full Phase 2 analysis.
 *
 * Merges all experiment-*.json files from results/raw/ into one dataset,
 * then runs classification with all 10 senses combined and individually.
 *
 * Usage: pnpm run analyze:full
 */

import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { signalsToFeatureVector, FEATURE_NAMES } from "./signals.js";
import { extractVocabularySignals } from "../sensorium/senses/index.js";
import { AGENT_CONFIGS } from "./configs.js";
import type { ExperimentRun, ExperimentResult } from "./runner.js";

const log = (msg: string) => { process.stdout.write(msg + "\n"); };

// ═══════════════════════════════════════════════════════════════════════════
// Random Forest (from analyze.ts — self-contained)
// ═══════════════════════════════════════════════════════════════════════════

interface TreeNode { featureIndex: number; threshold: number; left: TreeNode | LeafNode; right: TreeNode | LeafNode; }
interface LeafNode { label: string; count: number; }
interface Sample { features: number[]; label: string; }

function isLeaf(node: TreeNode | LeafNode): node is LeafNode { return "label" in node; }

function giniImpurity(labels: string[]): number {
  if (labels.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const l of labels) counts.set(l, (counts.get(l) ?? 0) + 1);
  let impurity = 1;
  for (const count of counts.values()) { const p = count / labels.length; impurity -= p * p; }
  return impurity;
}

function findBestSplit(samples: Sample[], featureIndices: number[]) {
  const parentGini = giniImpurity(samples.map(s => s.label));
  let bestGain = 0, bestFeature = -1, bestThreshold = 0;
  for (const fi of featureIndices) {
    const values = [...new Set(samples.map(s => s.features[fi]))].sort((a, b) => a - b);
    for (let i = 0; i < values.length - 1; i++) {
      const threshold = (values[i] + values[i + 1]) / 2;
      const leftLabels: string[] = [], rightLabels: string[] = [];
      for (const s of samples) {
        if (s.features[fi] <= threshold) leftLabels.push(s.label);
        else rightLabels.push(s.label);
      }
      if (leftLabels.length === 0 || rightLabels.length === 0) continue;
      const gain = parentGini - (leftLabels.length / samples.length) * giniImpurity(leftLabels)
        - (rightLabels.length / samples.length) * giniImpurity(rightLabels);
      if (gain > bestGain) { bestGain = gain; bestFeature = fi; bestThreshold = threshold; }
    }
  }
  return bestFeature === -1 ? null : { featureIndex: bestFeature, threshold: bestThreshold, gain: bestGain };
}

function majorityLabel(samples: Sample[]): string {
  const counts = new Map<string, number>();
  for (const s of samples) counts.set(s.label, (counts.get(s.label) ?? 0) + 1);
  let best = "", bestCount = 0;
  for (const [label, count] of counts) if (count > bestCount) { best = label; bestCount = count; }
  return best;
}

function buildTree(samples: Sample[], featureIndices: number[], maxDepth: number, minSamples: number): TreeNode | LeafNode {
  const uniqueLabels = new Set(samples.map(s => s.label));
  if (uniqueLabels.size === 1) return { label: samples[0].label, count: samples.length };
  if (samples.length < minSamples || maxDepth <= 0) return { label: majorityLabel(samples), count: samples.length };
  const split = findBestSplit(samples, featureIndices);
  if (!split || split.gain < 1e-7) return { label: majorityLabel(samples), count: samples.length };
  const left: Sample[] = [], right: Sample[] = [];
  for (const s of samples) { if (s.features[split.featureIndex] <= split.threshold) left.push(s); else right.push(s); }
  return { featureIndex: split.featureIndex, threshold: split.threshold,
    left: buildTree(left, featureIndices, maxDepth - 1, minSamples),
    right: buildTree(right, featureIndices, maxDepth - 1, minSamples) };
}

function predictTree(node: TreeNode | LeafNode, features: number[]): string {
  if (isLeaf(node)) return node.label;
  return features[node.featureIndex] <= node.threshold ? predictTree(node.left, features) : predictTree(node.right, features);
}

function bootstrapSample(samples: Sample[]): Sample[] {
  const result: Sample[] = [];
  for (let i = 0; i < samples.length; i++) result.push(samples[Math.floor(Math.random() * samples.length)]);
  return result;
}

function randomFeatureSubset(totalFeatures: number): number[] {
  const k = Math.max(1, Math.floor(Math.sqrt(totalFeatures)));
  const indices = Array.from({ length: totalFeatures }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [indices[i], indices[j]] = [indices[j], indices[i]]; }
  return indices.slice(0, k);
}

function trainForest(samples: Sample[], numTrees = 100, maxDepth = 15, minSamples = 2) {
  const trees: (TreeNode | LeafNode)[] = [];
  for (let i = 0; i < numTrees; i++) {
    trees.push(buildTree(bootstrapSample(samples), randomFeatureSubset(samples[0].features.length), maxDepth, minSamples));
  }
  return trees;
}

function predictForest(trees: (TreeNode | LeafNode)[], features: number[]): string {
  const votes = new Map<string, number>();
  for (const tree of trees) { const p = predictTree(tree, features); votes.set(p, (votes.get(p) ?? 0) + 1); }
  let best = "", bestCount = 0;
  for (const [label, count] of votes) if (count > bestCount) { best = label; bestCount = count; }
  return best;
}

function stratifiedKFold(samples: Sample[], k: number) {
  const byLabel = new Map<string, Sample[]>();
  for (const s of samples) { const arr = byLabel.get(s.label) ?? []; arr.push(s); byLabel.set(s.label, arr); }
  for (const group of byLabel.values()) for (let i = group.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [group[i], group[j]] = [group[j], group[i]]; }
  const folds: Sample[][] = Array.from({ length: k }, () => []);
  for (const group of byLabel.values()) for (let i = 0; i < group.length; i++) folds[i % k].push(group[i]);
  return folds.map((_, i) => ({ test: folds[i], train: folds.filter((_, j) => j !== i).flat() }));
}

function computeImportance(trees: (TreeNode | LeafNode)[], testSamples: Sample[], featureNames: string[]) {
  let baseCorrect = 0;
  for (const s of testSamples) if (predictForest(trees, s.features) === s.label) baseCorrect++;
  const baseAcc = baseCorrect / testSamples.length;
  const importances: Array<{ feature: string; importance: number }> = [];
  for (let fi = 0; fi < featureNames.length; fi++) {
    const shuffled = testSamples.map(s => ({ ...s, features: [...s.features] }));
    const values = shuffled.map(s => s.features[fi]);
    for (let i = values.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [values[i], values[j]] = [values[j], values[i]]; }
    for (let i = 0; i < shuffled.length; i++) shuffled[i].features[fi] = values[i];
    let permCorrect = 0;
    for (const s of shuffled) if (predictForest(trees, s.features) === s.label) permCorrect++;
    importances.push({ feature: featureNames[fi], importance: baseAcc - permCorrect / testSamples.length });
  }
  return importances.sort((a, b) => b.importance - a.importance);
}

// ═══════════════════════════════════════════════════════════════════════════
// Classification Runner
// ═══════════════════════════════════════════════════════════════════════════

interface Report { name: string; accuracy: number; folds: number[]; sampleCount: number; classCount: number;
  topFeatures: Array<{ feature: string; importance: number }>; }

function classify(name: string, samples: Sample[], featureNames: string[], kFolds = 5, numTrees = 100): Report {
  if (samples.length < 10 || new Set(samples.map(s => s.label)).size < 2) {
    return { name, accuracy: 0, folds: [], sampleCount: samples.length, classCount: new Set(samples.map(s => s.label)).size, topFeatures: [] };
  }
  const folds = stratifiedKFold(samples, kFolds);
  const allPreds: Array<{ actual: string; predicted: string }> = [];
  const foldAccs: number[] = [];
  let lastTrees: (TreeNode | LeafNode)[] = [];
  let lastTest: Sample[] = [];
  for (const { train, test } of folds) {
    const trees = trainForest(train, numTrees);
    let correct = 0;
    for (const s of test) { const p = predictForest(trees, s.features); allPreds.push({ actual: s.label, predicted: p }); if (p === s.label) correct++; }
    foldAccs.push(test.length > 0 ? correct / test.length : 0);
    lastTrees = trees; lastTest = test;
  }
  const acc = allPreds.filter(p => p.actual === p.predicted).length / allPreds.length;
  const topFeatures = lastTrees.length > 0 ? computeImportance(lastTrees, lastTest, featureNames).slice(0, 10) : [];
  return { name, accuracy: acc, folds: foldAccs, sampleCount: samples.length, classCount: new Set(samples.map(s => s.label)).size, topFeatures };
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature Index Ranges
// ═══════════════════════════════════════════════════════════════════════════

const COGNITIVE_IDX    = [0, 1, 2, 3, 4, 5];
const STRUCTURAL_IDX   = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
const TEMPORAL_IDX     = [21, 22, 23, 24, 25, 26, 27];
const ERROR_IDX        = [28, 29, 30, 31, 32, 33];
const VOCABULARY_IDX   = Array.from({ length: 10 }, (_, i) => 34 + i);  // 34-43
const TOPOLOGY_IDX     = Array.from({ length: 9 },  (_, i) => 44 + i);  // 44-52
const CAPBOUNDARY_IDX  = Array.from({ length: 8 },  (_, i) => 53 + i);  // 53-60
const TOOLINTERACT_IDX = Array.from({ length: 6 },  (_, i) => 61 + i);  // 61-66
const ADVERSARIAL_IDX  = Array.from({ length: 8 },  (_, i) => 67 + i);  // 67-74
const CONTEXTUTIL_IDX  = Array.from({ length: 5 },  (_, i) => 75 + i);  // 75-79

function selectFeatures(features: number[], indices: number[]): number[] { return indices.map(i => features[i]); }
function selectNames(indices: number[]): string[] { return indices.map(i => FEATURE_NAMES[i] ?? `f${i}`); }

// ═══════════════════════════════════════════════════════════════════════════
// Merge & Load
// ═══════════════════════════════════════════════════════════════════════════

async function loadAndMerge(): Promise<ExperimentResult[]> {
  const dir = "results/raw";
  const files = (await readdir(dir)).filter(f => /^experiment-2026-03-26.*\.json$/.test(f)).sort();
  log(`  Found ${files.length} experiment files to merge:`);

  const allResults: ExperimentResult[] = [];
  const seenKeys = new Set<string>();

  for (const file of files) {
    const raw = await readFile(`${dir}/${file}`, "utf-8");
    const run = JSON.parse(raw) as ExperimentRun;
    const valid = run.results.filter(r => !r.error);
    let added = 0;
    for (const r of valid) {
      const key = `${r.agentId}|${r.probeId}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        allResults.push(r);
        added++;
      }
    }
    log(`    ${file}: ${valid.length} valid, ${added} new (${run.results.length - valid.length} errors)`);
  }

  log(`  Total merged: ${allResults.length} unique observations`);
  return allResults;
}

function toSamples(results: ExperimentResult[], labelFn: (r: ExperimentResult) => string | null, indices?: number[]): Sample[] {
  const samples: Sample[] = [];
  for (const r of results) {
    if (r.error) continue;
    const label = labelFn(r);
    if (label === null) continue;
    if (!r.signals.vocabulary && r.responseText) r.signals.vocabulary = extractVocabularySignals(r.responseText);
    const all = signalsToFeatureVector(r.signals);
    samples.push({ features: indices ? selectFeatures(all, indices) : all, label });
  }
  return samples;
}

// ═══════════════════════════════════════════════════════════════════════════
// Report Formatting
// ═══════════════════════════════════════════════════════════════════════════

function fmtReport(r: Report): string {
  const foldStr = r.folds.map(a => `${(a * 100).toFixed(1)}%`).join(", ");
  let out = `\n  ${r.name}\n  ${"─".repeat(r.name.length)}\n`;
  out += `  Accuracy: ${(r.accuracy * 100).toFixed(1)}%  |  ${r.sampleCount} samples, ${r.classCount} classes\n`;
  if (r.folds.length > 0) out += `  Folds: ${foldStr}\n`;
  if (r.topFeatures.length > 0) {
    out += `  Top features:\n`;
    for (const f of r.topFeatures.slice(0, 5)) {
      out += `    ${f.feature.padEnd(30)} ${(f.importance * 100).toFixed(1).padStart(6)}%\n`;
    }
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  log("\n╔══════════════════════════════════════════════════════════╗");
  log("║     SOMA PHASE 2 — FULL ANALYSIS (10-SENSE GESTALT)    ║");
  log("╚══════════════════════════════════════════════════════════╝\n");

  const results = await loadAndMerge();
  const agentMap = new Map(AGENT_CONFIGS.map(c => [c.id, c]));

  // Count per agent
  const perAgent = new Map<string, number>();
  for (const r of results) perAgent.set(r.agentId, (perAgent.get(r.agentId) ?? 0) + 1);
  log("\n  Observations per agent:");
  for (const [id, count] of [...perAgent.entries()].sort((a, b) => b[1] - a[1])) {
    const config = agentMap.get(id);
    log(`    ${id.padEnd(22)} ${String(count).padStart(4)}  (${config?.provider ?? "?"})`);
  }

  // ── 1. GESTALT: All features combined ──
  log("\n\n══════════════════════════════════════════════════════════");
  log("  SECTION 1: GESTALT GENOME CLASSIFICATION");
  log("══════════════════════════════════════════════════════════");

  const genomeSamples = toSamples(results, r => r.agentId);
  const gestalt = classify("All 10 Senses Combined (Gestalt)", genomeSamples, FEATURE_NAMES);
  log(fmtReport(gestalt));

  // ── 2. Per-channel (original 4) ──
  log("\n══════════════════════════════════════════════════════════");
  log("  SECTION 2: ORIGINAL 4 CHANNELS (Phase 0 Baseline)");
  log("══════════════════════════════════════════════════════════");

  const phase0Indices = [...COGNITIVE_IDX, ...STRUCTURAL_IDX, ...TEMPORAL_IDX, ...ERROR_IDX];
  const phase0Samples = toSamples(results, r => r.agentId, phase0Indices);
  const phase0 = classify("Phase 0 Channels Only (cognitive+structural+temporal+error)", phase0Samples, selectNames(phase0Indices));
  log(fmtReport(phase0));

  const cogR = classify("Cognitive Only", toSamples(results, r => r.agentId, COGNITIVE_IDX), selectNames(COGNITIVE_IDX));
  const strR = classify("Structural Only", toSamples(results, r => r.agentId, STRUCTURAL_IDX), selectNames(STRUCTURAL_IDX));
  const tmpR = classify("Temporal Only", toSamples(results, r => r.agentId, TEMPORAL_IDX), selectNames(TEMPORAL_IDX));
  const errR = classify("Error Only", toSamples(results, r => r.agentId, ERROR_IDX), selectNames(ERROR_IDX));
  log(fmtReport(cogR));
  log(fmtReport(strR));
  log(fmtReport(tmpR));
  log(fmtReport(errR));

  // ── 3. Per-sense (new 6 senses) ──
  log("\n══════════════════════════════════════════════════════════");
  log("  SECTION 3: 6 NEW SENSES (Phase 2)");
  log("══════════════════════════════════════════════════════════");

  const vocR = classify("Sense 1: Vocabulary Fingerprint", toSamples(results, r => r.agentId, VOCABULARY_IDX), selectNames(VOCABULARY_IDX));
  const topR = classify("Sense 2: Response Topology", toSamples(results, r => r.agentId, TOPOLOGY_IDX), selectNames(TOPOLOGY_IDX));
  const capR = classify("Sense 3: Capability Boundary", toSamples(results, r => r.agentId, CAPBOUNDARY_IDX), selectNames(CAPBOUNDARY_IDX));
  const tolR = classify("Sense 4: Tool Interaction", toSamples(results, r => r.agentId, TOOLINTERACT_IDX), selectNames(TOOLINTERACT_IDX));
  const advR = classify("Sense 5: Adversarial Resilience", toSamples(results, r => r.agentId, ADVERSARIAL_IDX), selectNames(ADVERSARIAL_IDX));
  const ctxR = classify("Sense 8: Context Utilization", toSamples(results, r => r.agentId, CONTEXTUTIL_IDX), selectNames(CONTEXTUTIL_IDX));
  log(fmtReport(vocR));
  log(fmtReport(topR));
  log(fmtReport(capR));
  log(fmtReport(tolR));
  log(fmtReport(advR));
  log(fmtReport(ctxR));

  // ── 4. Model Family Classification ──
  log("\n══════════════════════════════════════════════════════════");
  log("  SECTION 4: MODEL FAMILY CLASSIFICATION");
  log("══════════════════════════════════════════════════════════");

  const famSamples = toSamples(results, r => agentMap.get(r.agentId)?.family ?? null);
  const famR = classify("Model Family (Llama vs Claude vs GPT vs ...)", famSamples, FEATURE_NAMES);
  log(fmtReport(famR));

  // ── 5. Epigenetic Detection ──
  log("\n══════════════════════════════════════════════════════════");
  log("  SECTION 5: EPIGENETIC DETECTION");
  log("══════════════════════════════════════════════════════════");

  const epiIds = new Set(["llama3-70b", "llama3-70b-formal", "llama3-70b-chaotic"]);
  const epiSamples = toSamples(results, r => epiIds.has(r.agentId) ? r.agentId : null);
  if (epiSamples.length >= 15) {
    const epiR = classify("Epigenetic (Same Model, Different Prompt)", epiSamples, FEATURE_NAMES);
    log(fmtReport(epiR));
  } else {
    log(`\n  Insufficient data (${epiSamples.length} samples). Need formal/chaotic variants.`);
  }

  // ── 6. Proxy Detection ──
  log("\n══════════════════════════════════════════════════════════");
  log("  SECTION 6: PROXY DETECTION");
  log("══════════════════════════════════════════════════════════");

  const proxyIds = new Set(["llama3-70b", "proxy-llama3-70b"]);
  const proxySamples = toSamples(results, r => proxyIds.has(r.agentId) ? r.agentId : null);
  if (proxySamples.length >= 10) {
    const proxyR = classify("Proxy Detection (All Features)", proxySamples, FEATURE_NAMES);
    const proxyTmpR = classify("Proxy Detection (Temporal Only)", toSamples(results, r => proxyIds.has(r.agentId) ? r.agentId : null, TEMPORAL_IDX), selectNames(TEMPORAL_IDX));
    log(fmtReport(proxyR));
    log(fmtReport(proxyTmpR));
  } else {
    log(`\n  Insufficient proxy data (${proxySamples.length} samples).`);
  }

  // ── FINAL VERDICT ──
  log("\n╔══════════════════════════════════════════════════════════╗");
  log("║                   FINAL VERDICT                        ║");
  log("╠══════════════════════════════════════════════════════════╣");
  log(`║  Gestalt (10 senses):     ${(gestalt.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║  Phase 0 baseline (4ch):  ${(phase0.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║  Improvement:             ${((gestalt.accuracy - phase0.accuracy) * 100).toFixed(1).padStart(5)}pp                      ║`);
  log("╠══════════════════════════════════════════════════════════╣");
  log(`║  Model Family:            ${(famR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log("╠══════════════════════════════════════════════════════════╣");
  log("║  Per-Channel:                                          ║");
  log(`║    Cognitive:             ${(cogR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    Structural:            ${(strR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    Temporal:              ${(tmpR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    Error:                 ${(errR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log("║  Per-Sense:                                            ║");
  log(`║    S1 Vocabulary:         ${(vocR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    S2 Topology:           ${(topR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    S3 Capability:         ${(capR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    S4 Tool Interaction:   ${(tolR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    S5 Adversarial:        ${(advR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log(`║    S8 Context Util:       ${(ctxR.accuracy * 100).toFixed(1).padStart(5)}%                      ║`);
  log("╠══════════════════════════════════════════════════════════╣");
  log(`║  Total observations:      ${String(results.length).padStart(5)}                      ║`);
  log(`║  Unique agents:           ${String(perAgent.size).padStart(5)}                      ║`);
  log("╚══════════════════════════════════════════════════════════╝");

  // Save report
  const analysisDir = "results/analysis";
  if (!existsSync(analysisDir)) await mkdir(analysisDir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");

  const summary = {
    timestamp: new Date().toISOString(),
    totalObservations: results.length,
    uniqueAgents: perAgent.size,
    gestaltAccuracy: gestalt.accuracy,
    phase0Accuracy: phase0.accuracy,
    improvement: gestalt.accuracy - phase0.accuracy,
    familyAccuracy: famR.accuracy,
    channels: { cognitive: cogR.accuracy, structural: strR.accuracy, temporal: tmpR.accuracy, error: errR.accuracy },
    senses: { vocabulary: vocR.accuracy, topology: topR.accuracy, capability: capR.accuracy, toolInteraction: tolR.accuracy, adversarial: advR.accuracy, contextUtil: ctxR.accuracy },
    topFeatures: gestalt.topFeatures,
    perAgent: Object.fromEntries(perAgent),
  };

  await writeFile(`${analysisDir}/phase2-summary-${ts}.json`, JSON.stringify(summary, null, 2));
  log(`\n  Summary saved: ${analysisDir}/phase2-summary-${ts}.json`);

  process.exit(0);
}

main().catch(err => { console.error("Analysis failed:", err); process.exit(1); });
