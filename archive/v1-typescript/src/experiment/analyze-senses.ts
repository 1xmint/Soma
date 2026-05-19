/**
 * Sense Experiment Analysis — focused 3-sense classification.
 *
 * Uses the weighted 3-sense sensorium (temporal 5x, topology 2x, vocabulary 1x)
 * to classify agents from experiment data.
 *
 * Reports:
 * 1. Classification accuracy (local, cloud, combined)
 * 2. Per-sense accuracy (temporal alone, topology alone, vocabulary alone)
 * 3. Deployment identity proof (same model on different platforms)
 * 4. Atlas validation (reference profile classification)
 * 5. Conditional timing surface contribution
 *
 * Usage:
 *   npx tsx src/experiment/analyze-senses.ts results/raw/experiment-*.json
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extractTemporalSignals, temporalToFeatureVector, TEMPORAL_FEATURE_NAMES } from "../sensorium/senses/temporal.js";
import { extractTopologySignals, topologyToFeatureVector, TOPOLOGY_FEATURE_NAMES } from "../sensorium/senses/index.js";
import { extractVocabularySignals, vocabularyToFeatureVector, VOCABULARY_FEATURE_NAMES } from "../sensorium/senses/index.js";
import { PhenotypeAtlas, type SenseFeatures } from "../sensorium/atlas.js";
import { fromStreamingTrace } from "../sensorium/stream-capture.js";
import type { ExperimentRun, ExperimentResult } from "./runner.js";

// ─── ML Infrastructure (reused from analyze.ts) ──────────────────────────────

interface Sample { features: number[]; label: string; }
interface TreeNode { featureIndex: number; threshold: number; left: TreeNode | LeafNode; right: TreeNode | LeafNode; }
interface LeafNode { label: string; count: number; }

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
      for (const s of samples) { if (s.features[fi] <= threshold) leftLabels.push(s.label); else rightLabels.push(s.label); }
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
  for (const [l, c] of counts) { if (c > bestCount) { best = l; bestCount = c; } }
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
  return { featureIndex: split.featureIndex, threshold: split.threshold, left: buildTree(left, featureIndices, maxDepth - 1, minSamples), right: buildTree(right, featureIndices, maxDepth - 1, minSamples) };
}

function predictTree(node: TreeNode | LeafNode, features: number[]): string {
  if (isLeaf(node)) return node.label;
  return features[node.featureIndex] <= node.threshold ? predictTree(node.left, features) : predictTree(node.right, features);
}

function bootstrapSample(samples: Sample[]): Sample[] {
  const n = samples.length;
  return Array.from({ length: n }, () => samples[Math.floor(Math.random() * n)]);
}

function randomFeatureSubset(total: number): number[] {
  const k = Math.max(1, Math.floor(Math.sqrt(total)));
  const indices = Array.from({ length: total }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [indices[i], indices[j]] = [indices[j], indices[i]]; }
  return indices.slice(0, k);
}

function trainForest(samples: Sample[], numTrees = 50, maxDepth = 15, minSamples = 2) {
  const trees: (TreeNode | LeafNode)[] = [];
  const totalFeatures = samples[0].features.length;
  for (let i = 0; i < numTrees; i++) {
    trees.push(buildTree(bootstrapSample(samples), randomFeatureSubset(totalFeatures), maxDepth, minSamples));
  }
  return { trees };
}

function predictForest(forest: { trees: (TreeNode | LeafNode)[] }, features: number[]): string {
  const votes = new Map<string, number>();
  for (const tree of forest.trees) { const p = predictTree(tree, features); votes.set(p, (votes.get(p) ?? 0) + 1); }
  let best = "", bestCount = 0;
  for (const [l, c] of votes) { if (c > bestCount) { best = l; bestCount = c; } }
  return best;
}

function stratifiedKFold(samples: Sample[], k: number) {
  const byLabel = new Map<string, Sample[]>();
  for (const s of samples) { const arr = byLabel.get(s.label) ?? []; arr.push(s); byLabel.set(s.label, arr); }
  for (const group of byLabel.values()) { for (let i = group.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [group[i], group[j]] = [group[j], group[i]]; } }
  const folds: Sample[][] = Array.from({ length: k }, () => []);
  for (const group of byLabel.values()) { for (let i = 0; i < group.length; i++) folds[i % k].push(group[i]); }
  return folds.map((_, i) => ({ train: folds.filter((_, j) => j !== i).flat(), test: folds[i] }));
}

function crossValidate(samples: Sample[], k = 5): { accuracy: number; predictions: Array<{ actual: string; predicted: string }> } {
  const folds = stratifiedKFold(samples, k);
  const allPreds: Array<{ actual: string; predicted: string }> = [];
  for (const { train, test } of folds) {
    if (train.length === 0 || test.length === 0) continue;
    const forest = trainForest(train);
    for (const s of test) allPreds.push({ actual: s.label, predicted: predictForest(forest, s.features) });
  }
  const correct = allPreds.filter(p => p.actual === p.predicted).length;
  return { accuracy: allPreds.length > 0 ? correct / allPreds.length : 0, predictions: allPreds };
}

// ─── Feature Extraction ──────────────────────────────────────────────────────

interface SenseExtraction {
  agentId: string;
  temporal: number[];
  topology: number[];
  vocabulary: number[];
  combined: number[];  // weighted: temporal features 5x, topology 2x, vocabulary 1x
  senseFeatures: SenseFeatures;
}

function extractSenseFeatures(result: ExperimentResult): SenseExtraction | null {
  if (result.error || !result.responseText) return null;

  // Reconstruct the streaming trace for temporal extraction
  const trace = {
    tokens: result.responseText.split(/(?<=\s)/), // Rough token split
    tokenTimestamps: [] as number[],
    startTime: result.trace.startTime,
    firstTokenTime: result.trace.firstTokenTime,
    endTime: result.trace.endTime,
  };

  // Reconstruct timestamps from inter-token intervals
  if (result.trace.interTokenIntervals.length > 0 && result.trace.firstTokenTime) {
    let t = result.trace.firstTokenTime;
    trace.tokenTimestamps.push(t);
    for (const interval of result.trace.interTokenIntervals) {
      t += interval;
      trace.tokenTimestamps.push(t);
    }
    // Adjust tokens array to match timestamp count
    trace.tokens = trace.tokens.slice(0, trace.tokenTimestamps.length);
    if (trace.tokens.length < trace.tokenTimestamps.length) {
      // Pad with empty tokens if needed
      while (trace.tokens.length < trace.tokenTimestamps.length) {
        trace.tokens.push(" ");
      }
    }
  }

  const capture = fromStreamingTrace(trace);
  const temporalSignals = extractTemporalSignals(capture);
  const temporalVec = temporalToFeatureVector(temporalSignals);

  const topologySignals = extractTopologySignals(result.responseText);
  const topologyVec = topologyToFeatureVector(topologySignals);

  const vocabSignals = extractVocabularySignals(result.responseText);
  const vocabVec = vocabularyToFeatureVector(vocabSignals);

  // Weighted combined: repeat temporal 5x, topology 2x, vocabulary 1x
  const combined = [
    ...temporalVec, ...temporalVec, ...temporalVec, ...temporalVec, ...temporalVec,
    ...topologyVec, ...topologyVec,
    ...vocabVec,
  ];

  // Build SenseFeatures for atlas
  const senseFeatures: SenseFeatures = { temporal: {}, topology: {}, vocabulary: {} };
  for (let i = 0; i < TEMPORAL_FEATURE_NAMES.length; i++) senseFeatures.temporal[TEMPORAL_FEATURE_NAMES[i]] = temporalVec[i];
  for (let i = 0; i < TOPOLOGY_FEATURE_NAMES.length; i++) senseFeatures.topology[TOPOLOGY_FEATURE_NAMES[i]] = topologyVec[i];
  for (let i = 0; i < VOCABULARY_FEATURE_NAMES.length; i++) senseFeatures.vocabulary[VOCABULARY_FEATURE_NAMES[i]] = vocabVec[i];

  return {
    agentId: result.agentId,
    temporal: temporalVec,
    topology: topologyVec,
    vocabulary: vocabVec,
    combined,
    senseFeatures,
  };
}

// ─── Analysis ────────────────────────────────────────────────────────────────

function confusionMatrix(predictions: Array<{ actual: string; predicted: string }>): string {
  const labels = [...new Set([...predictions.map(p => p.actual), ...predictions.map(p => p.predicted)])].sort();
  const idx = new Map(labels.map((l, i) => [l, i]));
  const matrix = Array.from({ length: labels.length }, () => Array(labels.length).fill(0));
  for (const p of predictions) matrix[idx.get(p.actual)!][idx.get(p.predicted)!]++;

  const maxLabel = Math.max(...labels.map(l => l.length), 8);
  let out = " ".repeat(maxLabel + 2) + labels.map(l => l.slice(0, 6).padStart(7)).join("") + "\n";
  for (let i = 0; i < labels.length; i++) {
    out += labels[i].padEnd(maxLabel + 2) + matrix[i].map((v: number) => String(v).padStart(7)).join("") + "\n";
  }
  return out;
}

async function main() {
  const files = process.argv.slice(2);
  if (files.length === 0) {
    console.error("Usage: npx tsx src/experiment/analyze-senses.ts results/raw/*.json");
    process.exit(1);
  }

  // Load all experiment results
  const allResults: ExperimentResult[] = [];
  for (const file of files) {
    const data = JSON.parse(await readFile(file, "utf-8")) as ExperimentRun;
    allResults.push(...data.results);
  }

  console.log(`\n  Soma Sense Analysis`);
  console.log(`  Loaded ${allResults.length} observations from ${files.length} file(s)`);

  // Extract sense features
  const extractions: SenseExtraction[] = [];
  let skipped = 0;
  for (const result of allResults) {
    const ext = extractSenseFeatures(result);
    if (ext) extractions.push(ext);
    else skipped++;
  }
  console.log(`  Extracted: ${extractions.length}, skipped: ${skipped}\n`);

  const agents = [...new Set(extractions.map(e => e.agentId))];
  console.log(`  Agents: ${agents.join(", ")}`);
  for (const agent of agents) {
    console.log(`    ${agent}: ${extractions.filter(e => e.agentId === agent).length} observations`);
  }

  // Need at least 2 agents with 2+ observations each
  const agentCounts = new Map<string, number>();
  for (const e of extractions) agentCounts.set(e.agentId, (agentCounts.get(e.agentId) ?? 0) + 1);
  const viableAgents = [...agentCounts.entries()].filter(([, c]) => c >= 2);
  if (viableAgents.length < 2) {
    console.error("\n  Not enough data for classification (need 2+ agents with 2+ observations each)");
    process.exit(1);
  }

  const viableSet = new Set(viableAgents.map(([a]) => a));
  const viable = extractions.filter(e => viableSet.has(e.agentId));

  console.log(`\n${"═".repeat(60)}`);
  console.log(`  CLASSIFICATION RESULTS`);
  console.log(`${"═".repeat(60)}`);

  // 1. Weighted 3-sense combined classification
  const combinedSamples: Sample[] = viable.map(e => ({ features: e.combined, label: e.agentId }));
  const combinedResult = crossValidate(combinedSamples);
  console.log(`\n  Weighted 3-Sense (temporal 5x, topology 2x, vocab 1x):`);
  console.log(`    Accuracy: ${(combinedResult.accuracy * 100).toFixed(1)}%`);
  console.log(`\n  Confusion Matrix:`);
  console.log(confusionMatrix(combinedResult.predictions));

  // 2. Per-sense accuracy
  const temporalSamples: Sample[] = viable.map(e => ({ features: e.temporal, label: e.agentId }));
  const topologySamples: Sample[] = viable.map(e => ({ features: e.topology, label: e.agentId }));
  const vocabSamples: Sample[] = viable.map(e => ({ features: e.vocabulary, label: e.agentId }));

  const temporalResult = crossValidate(temporalSamples);
  const topologyResult = crossValidate(topologySamples);
  const vocabResult = crossValidate(vocabSamples);

  console.log(`\n  Per-Sense Standalone Accuracy:`);
  console.log(`    Temporal (22 features, 5x weight):  ${(temporalResult.accuracy * 100).toFixed(1)}%`);
  console.log(`    Topology (9 features, 2x weight):   ${(topologyResult.accuracy * 100).toFixed(1)}%`);
  console.log(`    Vocabulary (10 features, 1x weight): ${(vocabResult.accuracy * 100).toFixed(1)}%`);

  // 3. Temporal: basic vs conditional timing surface
  // Basic temporal = first 7 features, conditional = features 8+
  const basicTemporalSamples: Sample[] = viable.map(e => ({ features: e.temporal.slice(0, 7), label: e.agentId }));
  const conditionalSamples: Sample[] = viable.map(e => ({ features: e.temporal.slice(7), label: e.agentId }));
  const basicResult = crossValidate(basicTemporalSamples);
  const conditionalResult = crossValidate(conditionalSamples);

  console.log(`\n  Temporal Breakdown:`);
  console.log(`    Basic temporal (7 aggregate features):     ${(basicResult.accuracy * 100).toFixed(1)}%`);
  console.log(`    Conditional timing surface (15 features):  ${(conditionalResult.accuracy * 100).toFixed(1)}%`);
  console.log(`    Full temporal (22 features):               ${(temporalResult.accuracy * 100).toFixed(1)}%`);

  // 4. Deployment identity (same model, different platforms)
  const deploymentPairs = [
    { model: "Llama 3.1 8B", agents: ["ollama-llama3", "llama3-8b", "or-llama3-8b"] },
    { model: "Gemma 2 9B", agents: ["ollama-gemma2", "gemma2"] },
  ];

  console.log(`\n${"═".repeat(60)}`);
  console.log(`  DEPLOYMENT IDENTITY`);
  console.log(`${"═".repeat(60)}`);

  for (const pair of deploymentPairs) {
    const pairData = extractions.filter(e => pair.agents.includes(e.agentId));
    const presentAgents = [...new Set(pairData.map(e => e.agentId))];
    if (presentAgents.length < 2) {
      console.log(`\n  ${pair.model}: only ${presentAgents.length} platform(s) in data, need 2+`);
      continue;
    }

    const pairSamples: Sample[] = pairData.map(e => ({ features: e.temporal, label: e.agentId }));
    const pairResult = crossValidate(pairSamples, Math.min(3, presentAgents.length));

    console.log(`\n  ${pair.model} across ${presentAgents.length} platforms:`);
    console.log(`    Platforms: ${presentAgents.join(", ")}`);
    console.log(`    Temporal classification accuracy: ${(pairResult.accuracy * 100).toFixed(1)}%`);
    console.log(`    (Same weights, same model, different infrastructure = different fingerprint)`);

    // Print mean temporal stats per platform
    for (const agent of presentAgents) {
      const agentData = pairData.filter(e => e.agentId === agent);
      if (agentData.length === 0) continue;
      const meanInterval = agentData.reduce((s, e) => s + e.temporal[1], 0) / agentData.length;
      const meanTTFT = agentData.reduce((s, e) => s + e.temporal[0], 0) / agentData.length;
      console.log(`    ${agent}: mean_interval=${meanInterval.toFixed(2)}ms ttft=${meanTTFT.toFixed(0)}ms (n=${agentData.length})`);
    }
  }

  // 5. Atlas validation
  console.log(`\n${"═".repeat(60)}`);
  console.log(`  ATLAS VALIDATION`);
  console.log(`${"═".repeat(60)}`);

  const atlas = new PhenotypeAtlas();

  // Split: 80% train atlas, 20% test
  const shuffled = [...viable];
  for (let i = shuffled.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]; }
  const splitPoint = Math.floor(shuffled.length * 0.8);
  const atlasTrain = shuffled.slice(0, splitPoint);
  const atlasTest = shuffled.slice(splitPoint);

  // Build atlas from training data
  for (const e of atlasTrain) {
    atlas.updateProfile(e.agentId, e.agentId, e.senseFeatures);
  }

  // Test atlas classification
  let atlasCorrect = 0;
  for (const e of atlasTest) {
    const classification = atlas.classifyObservation(e.senseFeatures, e.agentId);
    if (classification.match) atlasCorrect++;
  }
  const atlasAccuracy = atlasTest.length > 0 ? atlasCorrect / atlasTest.length : 0;

  console.log(`\n  Atlas reference profiles: ${atlas.size}`);
  console.log(`  Training observations: ${atlasTrain.length}`);
  console.log(`  Test observations: ${atlasTest.length}`);
  console.log(`  Atlas classification accuracy: ${(atlasAccuracy * 100).toFixed(1)}%`);

  // Save results
  const outputDir = "results/analysis";
  if (!existsSync(outputDir)) await mkdir(outputDir, { recursive: true });

  const report = {
    timestamp: new Date().toISOString(),
    totalObservations: extractions.length,
    agents: agents.length,
    classification: {
      weighted3Sense: combinedResult.accuracy,
      temporal: temporalResult.accuracy,
      topology: topologyResult.accuracy,
      vocabulary: vocabResult.accuracy,
      basicTemporal: basicResult.accuracy,
      conditionalTimingSurface: conditionalResult.accuracy,
    },
    atlas: {
      accuracy: atlasAccuracy,
      profiles: atlas.size,
      trainSize: atlasTrain.length,
      testSize: atlasTest.length,
    },
    perAgent: Object.fromEntries(agents.map(a => [a, extractions.filter(e => e.agentId === a).length])),
  };

  const outputPath = `${outputDir}/sense-analysis-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  await writeFile(outputPath, JSON.stringify(report, null, 2));
  console.log(`\n  Results saved: ${outputPath}`);

  // Save atlas for future use
  const atlasPath = `${outputDir}/phenotype-atlas.json`;
  await writeFile(atlasPath, JSON.stringify(atlas.toJSON(), null, 2));
  console.log(`  Atlas saved: ${atlasPath}`);

  console.log(`\n${"═".repeat(60)}\n`);
}

main().catch(err => { console.error("Analysis failed:", err); process.exit(1); });
