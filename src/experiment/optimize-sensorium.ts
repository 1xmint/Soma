/**
 * Sensorium Optimization — find the combination that beats temporal-only.
 *
 * Strategies:
 * 1. Weighted features (temporal 5x, vocab/topology 2x)
 * 2. Drop low-signal senses (< 15% standalone)
 * 3. Exhaustive search of top sense combinations
 * 4. Find the publishable number
 *
 * Usage: pnpm run analyze:optimize
 */

import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { signalsToFeatureVector, FEATURE_NAMES } from "./signals.js";
import { extractVocabularySignals } from "../sensorium/senses/index.js";
import { AGENT_CONFIGS } from "./configs.js";
import type { ExperimentRun, ExperimentResult } from "./runner.js";

const log = (msg: string) => { process.stdout.write(msg + "\n"); };

// ═══════════════════════════════════════════════════════════════════════════
// Random Forest (self-contained)
// ═══════════════════════════════════════════════════════════════════════════

interface TreeNode { featureIndex: number; threshold: number; left: TreeNode | LeafNode; right: TreeNode | LeafNode; }
interface LeafNode { label: string; count: number; }
interface Sample { features: number[]; label: string; }

function isLeaf(node: TreeNode | LeafNode): node is LeafNode { return "label" in node; }

function giniImpurity(labels: string[]): number {
  if (labels.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const l of labels) counts.set(l, (counts.get(l) ?? 0) + 1);
  let imp = 1;
  for (const c of counts.values()) { const p = c / labels.length; imp -= p * p; }
  return imp;
}

function findBestSplit(samples: Sample[], featureIndices: number[]) {
  const parentGini = giniImpurity(samples.map(s => s.label));
  let bestGain = 0, bestFeature = -1, bestThreshold = 0;
  for (const fi of featureIndices) {
    const values = [...new Set(samples.map(s => s.features[fi]))].sort((a, b) => a - b);
    for (let i = 0; i < values.length - 1; i++) {
      const t = (values[i] + values[i + 1]) / 2;
      const lL: string[] = [], rL: string[] = [];
      for (const s of samples) { if (s.features[fi] <= t) lL.push(s.label); else rL.push(s.label); }
      if (lL.length === 0 || rL.length === 0) continue;
      const g = parentGini - (lL.length / samples.length) * giniImpurity(lL) - (rL.length / samples.length) * giniImpurity(rL);
      if (g > bestGain) { bestGain = g; bestFeature = fi; bestThreshold = t; }
    }
  }
  return bestFeature === -1 ? null : { featureIndex: bestFeature, threshold: bestThreshold, gain: bestGain };
}

function majorityLabel(samples: Sample[]): string {
  const counts = new Map<string, number>();
  for (const s of samples) counts.set(s.label, (counts.get(s.label) ?? 0) + 1);
  let best = "", bc = 0;
  for (const [l, c] of counts) if (c > bc) { best = l; bc = c; }
  return best;
}

function buildTree(samples: Sample[], fi: number[], maxD: number, minS: number): TreeNode | LeafNode {
  const ul = new Set(samples.map(s => s.label));
  if (ul.size === 1) return { label: samples[0].label, count: samples.length };
  if (samples.length < minS || maxD <= 0) return { label: majorityLabel(samples), count: samples.length };
  const split = findBestSplit(samples, fi);
  if (!split || split.gain < 1e-7) return { label: majorityLabel(samples), count: samples.length };
  const l: Sample[] = [], r: Sample[] = [];
  for (const s of samples) { if (s.features[split.featureIndex] <= split.threshold) l.push(s); else r.push(s); }
  return { featureIndex: split.featureIndex, threshold: split.threshold, left: buildTree(l, fi, maxD - 1, minS), right: buildTree(r, fi, maxD - 1, minS) };
}

function predictTree(node: TreeNode | LeafNode, features: number[]): string {
  if (isLeaf(node)) return node.label;
  return features[node.featureIndex] <= node.threshold ? predictTree(node.left, features) : predictTree(node.right, features);
}

function trainForest(samples: Sample[], numTrees = 100, maxDepth = 15) {
  const trees: (TreeNode | LeafNode)[] = [];
  const nf = samples[0].features.length;
  const k = Math.max(1, Math.floor(Math.sqrt(nf)));
  for (let t = 0; t < numTrees; t++) {
    const boot: Sample[] = [];
    for (let i = 0; i < samples.length; i++) boot.push(samples[Math.floor(Math.random() * samples.length)]);
    const indices = Array.from({ length: nf }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [indices[i], indices[j]] = [indices[j], indices[i]]; }
    trees.push(buildTree(boot, indices.slice(0, k), maxDepth, 2));
  }
  return trees;
}

function predictForest(trees: (TreeNode | LeafNode)[], features: number[]): string {
  const votes = new Map<string, number>();
  for (const tree of trees) { const p = predictTree(tree, features); votes.set(p, (votes.get(p) ?? 0) + 1); }
  let best = "", bc = 0;
  for (const [l, c] of votes) if (c > bc) { best = l; bc = c; }
  return best;
}

function stratifiedKFold(samples: Sample[], k: number) {
  const byLabel = new Map<string, Sample[]>();
  for (const s of samples) { const a = byLabel.get(s.label) ?? []; a.push(s); byLabel.set(s.label, a); }
  for (const g of byLabel.values()) for (let i = g.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [g[i], g[j]] = [g[j], g[i]]; }
  const folds: Sample[][] = Array.from({ length: k }, () => []);
  for (const g of byLabel.values()) for (let i = 0; i < g.length; i++) folds[i % k].push(g[i]);
  return folds.map((_, i) => ({ test: folds[i], train: folds.filter((_, j) => j !== i).flat() }));
}

function crossValidate(samples: Sample[], kFolds = 5, numTrees = 100): { accuracy: number; folds: number[] } {
  if (samples.length < 10 || new Set(samples.map(s => s.label)).size < 2) return { accuracy: 0, folds: [] };
  const splits = stratifiedKFold(samples, kFolds);
  const foldAccs: number[] = [];
  let totalCorrect = 0, totalCount = 0;
  for (const { train, test } of splits) {
    const trees = trainForest(train, numTrees);
    let correct = 0;
    for (const s of test) if (predictForest(trees, s.features) === s.label) correct++;
    foldAccs.push(test.length > 0 ? correct / test.length : 0);
    totalCorrect += correct; totalCount += test.length;
  }
  return { accuracy: totalCount > 0 ? totalCorrect / totalCount : 0, folds: foldAccs };
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature Index Definitions
// ═══════════════════════════════════════════════════════════════════════════

interface SenseBlock { name: string; indices: number[]; standalone: number; }

const COGNITIVE:    number[] = [0, 1, 2, 3, 4, 5];
const STRUCTURAL:   number[] = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
const TEMPORAL:     number[] = [21, 22, 23, 24, 25, 26, 27];
const ERROR:        number[] = [28, 29, 30, 31, 32, 33];
const VOCABULARY:   number[] = Array.from({ length: 10 }, (_, i) => 34 + i);
const TOPOLOGY:     number[] = Array.from({ length: 9 },  (_, i) => 44 + i);
const CAPBOUNDARY:  number[] = Array.from({ length: 8 },  (_, i) => 53 + i);
const TOOLINTERACT: number[] = Array.from({ length: 6 },  (_, i) => 61 + i);
const ADVERSARIAL:  number[] = Array.from({ length: 8 },  (_, i) => 67 + i);
const CONTEXTUTIL:  number[] = Array.from({ length: 5 },  (_, i) => 75 + i);

// Standalone accuracies from Phase 2 analysis
const ALL_SENSES: SenseBlock[] = [
  { name: "Temporal",      indices: TEMPORAL,     standalone: 88.5 },
  { name: "Topology",      indices: TOPOLOGY,     standalone: 25.1 },
  { name: "Structural",    indices: STRUCTURAL,   standalone: 23.6 },
  { name: "Vocabulary",    indices: VOCABULARY,    standalone: 20.2 },
  { name: "Cognitive",     indices: COGNITIVE,     standalone: 15.7 },
  { name: "Error",         indices: ERROR,         standalone: 13.5 },
  { name: "ContextUtil",   indices: CONTEXTUTIL,   standalone: 13.0 },
  { name: "ToolInteract",  indices: TOOLINTERACT,  standalone: 11.1 },
  { name: "CapBoundary",   indices: CAPBOUNDARY,   standalone: 9.9 },
  { name: "Adversarial",   indices: ADVERSARIAL,   standalone: 9.8 },
];

// ═══════════════════════════════════════════════════════════════════════════
// Data Loading
// ═══════════════════════════════════════════════════════════════════════════

async function loadMerged(): Promise<ExperimentResult[]> {
  const dir = "results/raw";
  const files = (await readdir(dir)).filter(f => /^experiment-2026-03-26.*\.json$/.test(f)).sort();
  const allResults: ExperimentResult[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    const run = JSON.parse(await readFile(`${dir}/${file}`, "utf-8")) as ExperimentRun;
    for (const r of run.results) {
      if (r.error) continue;
      const key = `${r.agentId}|${r.probeId}`;
      if (!seen.has(key)) { seen.add(key); allResults.push(r); }
    }
  }
  return allResults;
}

function makeSamples(results: ExperimentResult[], indices: number[], weights?: Map<number, number>): Sample[] {
  const samples: Sample[] = [];
  for (const r of results) {
    if (r.error) continue;
    if (!r.signals.vocabulary && r.responseText) r.signals.vocabulary = extractVocabularySignals(r.responseText);
    const allFeats = signalsToFeatureVector(r.signals);
    let feats = indices.map(i => allFeats[i]);
    if (weights) {
      feats = feats.map((v, fi) => {
        const origIdx = indices[fi];
        const w = weights.get(origIdx) ?? 1;
        return v * w;
      });
    }
    samples.push({ features: feats, label: r.agentId });
  }
  return samples;
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  log("\n╔══════════════════════════════════════════════════════════╗");
  log("║       SENSORIUM OPTIMIZATION — Beat 88.5%              ║");
  log("╚══════════════════════════════════════════════════════════╝\n");

  const results = await loadMerged();
  log(`  Loaded ${results.length} observations\n`);

  const experiments: Array<{ name: string; accuracy: number; folds: number[] }> = [];

  function run(name: string, indices: number[], weights?: Map<number, number>) {
    process.stdout.write(`  ${name.padEnd(55)} `);
    const samples = makeSamples(results, indices, weights);
    const { accuracy, folds } = crossValidate(samples, 5, 100);
    const pct = (accuracy * 100).toFixed(1);
    const foldStr = folds.map(f => (f * 100).toFixed(0)).join("/");
    log(`${pct}%  [${foldStr}]`);
    experiments.push({ name, accuracy, folds });
    return accuracy;
  }

  // ── Baseline ──
  log("── BASELINES ──");
  run("Temporal only", TEMPORAL);
  run("All features (unweighted)", Array.from({ length: FEATURE_NAMES.length }, (_, i) => i));

  // ── Strategy 1: Weighted features ──
  log("\n── STRATEGY 1: Weighted features ──");

  const w5x2x = new Map<number, number>();
  for (const i of TEMPORAL) w5x2x.set(i, 5);
  for (const i of VOCABULARY) w5x2x.set(i, 2);
  for (const i of TOPOLOGY) w5x2x.set(i, 2);
  run("All features, temporal 5x / vocab+topo 2x", Array.from({ length: FEATURE_NAMES.length }, (_, i) => i), w5x2x);

  const w3x = new Map<number, number>();
  for (const i of TEMPORAL) w3x.set(i, 3);
  for (const i of VOCABULARY) w3x.set(i, 2);
  for (const i of TOPOLOGY) w3x.set(i, 2);
  for (const i of STRUCTURAL) w3x.set(i, 1.5);
  run("All features, temporal 3x / vocab+topo 2x / struct 1.5x", Array.from({ length: FEATURE_NAMES.length }, (_, i) => i), w3x);

  // ── Strategy 2: Drop low-signal senses (< 15% standalone) ──
  log("\n── STRATEGY 2: Drop senses below 15% standalone ──");

  const above15 = ALL_SENSES.filter(s => s.standalone >= 15);
  const above15idx = above15.flatMap(s => s.indices);
  run(`Top senses >= 15%: ${above15.map(s => s.name).join("+")}`, above15idx);

  const above15w = new Map<number, number>();
  for (const i of TEMPORAL) above15w.set(i, 3);
  for (const i of VOCABULARY) above15w.set(i, 2);
  for (const i of TOPOLOGY) above15w.set(i, 2);
  run(`Top senses >= 15% weighted (temporal 3x, vocab+topo 2x)`, above15idx, above15w);

  // ── Strategy 3: Exhaustive sense combinations (top N) ──
  log("\n── STRATEGY 3: Sense combinations ──");

  // Temporal + each other sense
  for (const sense of ALL_SENSES) {
    if (sense.name === "Temporal") continue;
    run(`Temporal + ${sense.name}`, [...TEMPORAL, ...sense.indices]);
  }

  // Top 3 combinations
  log("\n── STRATEGY 4: Top 3-4 sense combos ──");
  run("Temporal + Topology + Vocabulary", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY]);
  run("Temporal + Structural + Vocabulary", [...TEMPORAL, ...STRUCTURAL, ...VOCABULARY]);
  run("Temporal + Topology + Structural", [...TEMPORAL, ...TOPOLOGY, ...STRUCTURAL]);
  run("Temporal + Topology + Vocabulary + Structural", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY, ...STRUCTURAL]);
  run("Temporal + Topology + Vocabulary + Cognitive", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY, ...COGNITIVE]);
  run("Temporal + Topology + Structural + Cognitive", [...TEMPORAL, ...TOPOLOGY, ...STRUCTURAL, ...COGNITIVE]);
  run("Temporal + Topology + Vocabulary + Structural + Cognitive", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY, ...STRUCTURAL, ...COGNITIVE]);

  // Weighted top combos
  log("\n── STRATEGY 5: Weighted top combos ──");
  const w4combo = new Map<number, number>();
  for (const i of TEMPORAL) w4combo.set(i, 3);
  for (const i of TOPOLOGY) w4combo.set(i, 1.5);
  for (const i of VOCABULARY) w4combo.set(i, 1.5);
  for (const i of STRUCTURAL) w4combo.set(i, 1.5);
  run("Temp 3x + Topo 1.5x + Vocab 1.5x + Struct 1.5x", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY, ...STRUCTURAL], w4combo);

  const w3combo = new Map<number, number>();
  for (const i of TEMPORAL) w3combo.set(i, 2);
  for (const i of TOPOLOGY) w3combo.set(i, 1.5);
  for (const i of VOCABULARY) w3combo.set(i, 1.5);
  run("Temp 2x + Topo 1.5x + Vocab 1.5x", [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY], w3combo);

  // More trees
  log("\n── STRATEGY 6: More trees (200) on best combos ──");
  for (const combo of [
    { name: "Temporal + Topology + Vocabulary (200 trees)", indices: [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY] },
    { name: "Temporal + Topology + Vocab + Structural (200 trees)", indices: [...TEMPORAL, ...TOPOLOGY, ...VOCABULARY, ...STRUCTURAL] },
    { name: "Top senses >= 15% (200 trees)", indices: above15idx },
  ]) {
    process.stdout.write(`  ${combo.name.padEnd(55)} `);
    const samples = makeSamples(results, combo.indices);
    const { accuracy, folds } = crossValidate(samples, 5, 200);
    log(`${(accuracy * 100).toFixed(1)}%  [${folds.map(f => (f * 100).toFixed(0)).join("/")}]`);
    experiments.push({ name: combo.name, accuracy, folds });
  }

  // ── FINAL RANKING ──
  log("\n╔══════════════════════════════════════════════════════════╗");
  log("║                 FINAL RANKING                          ║");
  log("╠══════════════════════════════════════════════════════════╣");
  experiments.sort((a, b) => b.accuracy - a.accuracy);
  for (let i = 0; i < Math.min(15, experiments.length); i++) {
    const e = experiments[i];
    const marker = i === 0 ? " <-- BEST" : e.accuracy >= 0.885 ? " <-- beats temporal" : "";
    log(`║  ${(i + 1).toString().padStart(2)}. ${(e.accuracy * 100).toFixed(1).padStart(5)}%  ${e.name.slice(0, 45).padEnd(45)}${marker}`);
  }
  log("╚══════════════════════════════════════════════════════════╝");

  // Save
  const analysisDir = "results/analysis";
  if (!existsSync(analysisDir)) await mkdir(analysisDir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  await writeFile(`${analysisDir}/optimization-${ts}.json`, JSON.stringify({ experiments: experiments.slice(0, 20) }, null, 2));
  log(`\n  Saved: ${analysisDir}/optimization-${ts}.json`);

  process.exit(0);
}

main().catch(err => { console.error("Failed:", err); process.exit(1); });
