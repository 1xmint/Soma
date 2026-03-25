/**
 * ML classification for Phase 0 — can we tell agents apart by phenotype alone?
 *
 * Implements a random forest classifier from scratch. The dataset is small
 * (~1000 samples, ~34 features) — no heavy framework needed.
 *
 * Reports:
 * 1. Overall genome classification accuracy (all features)
 * 2. Per-channel accuracy (cognitive, structural, temporal, error)
 * 3. Model family classification (Llama vs Gemini vs Mistral vs Mixtral vs Gemma)
 * 4. Epigenetic detection (same model, different prompt)
 * 5. Proxy detection (real vs proxied agent)
 * 6. Confusion matrix + feature importance
 */

import { readFile, writeFile, readdir, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { signalsToFeatureVector, FEATURE_NAMES, type PhenotypicSignals } from "./signals.js";
import { AGENT_CONFIGS } from "./configs.js";
import type { ExperimentRun, ExperimentResult } from "./runner.js";

// ============================================================================
// Decision Tree (CART) — from scratch
// ============================================================================

interface TreeNode {
  featureIndex: number;
  threshold: number;
  left: TreeNode | LeafNode;
  right: TreeNode | LeafNode;
}

interface LeafNode {
  label: string;
  count: number;
}

interface Sample {
  features: number[];
  label: string;
}

function isLeaf(node: TreeNode | LeafNode): node is LeafNode {
  return "label" in node;
}

/** Gini impurity — probability of misclassification if we randomly label. */
function giniImpurity(labels: string[]): number {
  if (labels.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const l of labels) counts.set(l, (counts.get(l) ?? 0) + 1);
  let impurity = 1;
  for (const count of counts.values()) {
    const p = count / labels.length;
    impurity -= p * p;
  }
  return impurity;
}

/** Find the best binary split across all features. */
function findBestSplit(
  samples: Sample[],
  featureIndices: number[]
): { featureIndex: number; threshold: number; gain: number } | null {
  const parentGini = giniImpurity(samples.map((s) => s.label));
  let bestGain = 0;
  let bestFeature = -1;
  let bestThreshold = 0;

  for (const fi of featureIndices) {
    // Get unique sorted values for this feature
    const values = [...new Set(samples.map((s) => s.features[fi]))].sort((a, b) => a - b);

    // Try midpoints between consecutive values
    for (let i = 0; i < values.length - 1; i++) {
      const threshold = (values[i] + values[i + 1]) / 2;

      const leftLabels: string[] = [];
      const rightLabels: string[] = [];
      for (const s of samples) {
        if (s.features[fi] <= threshold) leftLabels.push(s.label);
        else rightLabels.push(s.label);
      }

      if (leftLabels.length === 0 || rightLabels.length === 0) continue;

      const leftWeight = leftLabels.length / samples.length;
      const rightWeight = rightLabels.length / samples.length;
      const gain =
        parentGini -
        leftWeight * giniImpurity(leftLabels) -
        rightWeight * giniImpurity(rightLabels);

      if (gain > bestGain) {
        bestGain = gain;
        bestFeature = fi;
        bestThreshold = threshold;
      }
    }
  }

  if (bestFeature === -1) return null;
  return { featureIndex: bestFeature, threshold: bestThreshold, gain: bestGain };
}

/** Majority vote label. */
function majorityLabel(samples: Sample[]): string {
  const counts = new Map<string, number>();
  for (const s of samples) counts.set(s.label, (counts.get(s.label) ?? 0) + 1);
  let best = "";
  let bestCount = 0;
  for (const [label, count] of counts) {
    if (count > bestCount) {
      best = label;
      bestCount = count;
    }
  }
  return best;
}

/** Build a CART decision tree recursively. */
function buildTree(
  samples: Sample[],
  featureIndices: number[],
  maxDepth: number,
  minSamples: number
): TreeNode | LeafNode {
  // Leaf conditions
  const uniqueLabels = new Set(samples.map((s) => s.label));
  if (uniqueLabels.size === 1) {
    return { label: samples[0].label, count: samples.length };
  }
  if (samples.length < minSamples || maxDepth <= 0) {
    return { label: majorityLabel(samples), count: samples.length };
  }

  const split = findBestSplit(samples, featureIndices);
  if (!split || split.gain < 1e-7) {
    return { label: majorityLabel(samples), count: samples.length };
  }

  const left: Sample[] = [];
  const right: Sample[] = [];
  for (const s of samples) {
    if (s.features[split.featureIndex] <= split.threshold) left.push(s);
    else right.push(s);
  }

  return {
    featureIndex: split.featureIndex,
    threshold: split.threshold,
    left: buildTree(left, featureIndices, maxDepth - 1, minSamples),
    right: buildTree(right, featureIndices, maxDepth - 1, minSamples),
  };
}

/** Predict a single sample's label. */
function predictTree(node: TreeNode | LeafNode, features: number[]): string {
  if (isLeaf(node)) return node.label;
  if (features[node.featureIndex] <= node.threshold) {
    return predictTree(node.left, features);
  }
  return predictTree(node.right, features);
}

// ============================================================================
// Random Forest
// ============================================================================

interface RandomForest {
  trees: (TreeNode | LeafNode)[];
}

/** Sample with replacement (bootstrap). */
function bootstrapSample(samples: Sample[]): Sample[] {
  const n = samples.length;
  const result: Sample[] = [];
  for (let i = 0; i < n; i++) {
    result.push(samples[Math.floor(Math.random() * n)]);
  }
  return result;
}

/** Random subset of feature indices (sqrt of total). */
function randomFeatureSubset(totalFeatures: number): number[] {
  const k = Math.max(1, Math.floor(Math.sqrt(totalFeatures)));
  const indices = Array.from({ length: totalFeatures }, (_, i) => i);
  // Fisher-Yates shuffle, take first k
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  return indices.slice(0, k);
}

function trainRandomForest(
  samples: Sample[],
  numTrees: number = 50,
  maxDepth: number = 15,
  minSamples: number = 2
): RandomForest {
  const trees: (TreeNode | LeafNode)[] = [];
  const totalFeatures = samples[0].features.length;

  for (let i = 0; i < numTrees; i++) {
    const bootstrap = bootstrapSample(samples);
    const featureSubset = randomFeatureSubset(totalFeatures);
    const tree = buildTree(bootstrap, featureSubset, maxDepth, minSamples);
    trees.push(tree);
  }

  return { trees };
}

function predictForest(forest: RandomForest, features: number[]): string {
  const votes = new Map<string, number>();
  for (const tree of forest.trees) {
    const prediction = predictTree(tree, features);
    votes.set(prediction, (votes.get(prediction) ?? 0) + 1);
  }
  let best = "";
  let bestCount = 0;
  for (const [label, count] of votes) {
    if (count > bestCount) {
      best = label;
      bestCount = count;
    }
  }
  return best;
}

// ============================================================================
// Feature importance via permutation
// ============================================================================

function computeFeatureImportance(
  forest: RandomForest,
  testSamples: Sample[],
  featureNames: string[]
): Array<{ feature: string; importance: number }> {
  // Baseline accuracy
  let baselineCorrect = 0;
  for (const s of testSamples) {
    if (predictForest(forest, s.features) === s.label) baselineCorrect++;
  }
  const baselineAccuracy = baselineCorrect / testSamples.length;

  const importances: Array<{ feature: string; importance: number }> = [];

  for (let fi = 0; fi < featureNames.length; fi++) {
    // Shuffle feature fi across test samples
    const shuffled = testSamples.map((s) => ({ ...s, features: [...s.features] }));
    const values = shuffled.map((s) => s.features[fi]);
    // Fisher-Yates shuffle
    for (let i = values.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [values[i], values[j]] = [values[j], values[i]];
    }
    for (let i = 0; i < shuffled.length; i++) {
      shuffled[i].features[fi] = values[i];
    }

    let permutedCorrect = 0;
    for (const s of shuffled) {
      if (predictForest(forest, s.features) === s.label) permutedCorrect++;
    }
    const permutedAccuracy = permutedCorrect / testSamples.length;
    importances.push({
      feature: featureNames[fi],
      importance: baselineAccuracy - permutedAccuracy,
    });
  }

  return importances.sort((a, b) => b.importance - a.importance);
}

// ============================================================================
// Stratified K-Fold Cross Validation
// ============================================================================

function stratifiedKFold(samples: Sample[], k: number): Array<{ train: Sample[]; test: Sample[] }> {
  // Group by label
  const byLabel = new Map<string, Sample[]>();
  for (const s of samples) {
    const arr = byLabel.get(s.label) ?? [];
    arr.push(s);
    byLabel.set(s.label, arr);
  }

  // Shuffle each group
  for (const group of byLabel.values()) {
    for (let i = group.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [group[i], group[j]] = [group[j], group[i]];
    }
  }

  // Assign to folds
  const folds: Sample[][] = Array.from({ length: k }, () => []);
  for (const group of byLabel.values()) {
    for (let i = 0; i < group.length; i++) {
      folds[i % k].push(group[i]);
    }
  }

  // Build train/test splits
  const splits: Array<{ train: Sample[]; test: Sample[] }> = [];
  for (let i = 0; i < k; i++) {
    const test = folds[i];
    const train = folds.filter((_, j) => j !== i).flat();
    splits.push({ train, test });
  }
  return splits;
}

// ============================================================================
// Feature Index Ranges (for per-channel classification)
// ============================================================================

// These must match the order in signalsToFeatureVector
const COGNITIVE_INDICES = [0, 1, 2, 3, 4, 5];                   // 6 features
const STRUCTURAL_INDICES = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]; // 15 features
const TEMPORAL_INDICES = [21, 22, 23, 24, 25, 26, 27];          // 7 features
const ERROR_INDICES = [28, 29, 30, 31, 32, 33];                 // 6 features

function selectFeatures(features: number[], indices: number[]): number[] {
  return indices.map((i) => features[i]);
}

function selectFeatureNames(indices: number[]): string[] {
  return indices.map((i) => FEATURE_NAMES[i]);
}

// ============================================================================
// Confusion Matrix
// ============================================================================

interface ConfusionMatrix {
  labels: string[];
  matrix: number[][]; // matrix[actual][predicted]
}

function buildConfusionMatrix(
  predictions: Array<{ actual: string; predicted: string }>
): ConfusionMatrix {
  const labelSet = new Set<string>();
  for (const p of predictions) {
    labelSet.add(p.actual);
    labelSet.add(p.predicted);
  }
  const labels = [...labelSet].sort();
  const labelIndex = new Map(labels.map((l, i) => [l, i]));
  const n = labels.length;
  const matrix: number[][] = Array.from({ length: n }, () => Array(n).fill(0));

  for (const p of predictions) {
    const ai = labelIndex.get(p.actual)!;
    const pi = labelIndex.get(p.predicted)!;
    matrix[ai][pi]++;
  }

  return { labels, matrix };
}

function formatConfusionMatrix(cm: ConfusionMatrix): string {
  const maxLabelLen = Math.max(...cm.labels.map((l) => l.length), 8);
  const colWidth = Math.max(5, maxLabelLen + 1);
  const pad = (s: string, w: number) => s.padEnd(w);
  const padNum = (n: number, w: number) => String(n).padStart(w);

  let out = "\n" + pad("Actual \\ Pred", maxLabelLen + 2);
  for (const l of cm.labels) out += pad(l, colWidth);
  out += "\n" + "─".repeat(maxLabelLen + 2 + cm.labels.length * colWidth);

  for (let i = 0; i < cm.labels.length; i++) {
    out += "\n" + pad(cm.labels[i], maxLabelLen + 2);
    for (let j = 0; j < cm.labels.length; j++) {
      out += padNum(cm.matrix[i][j], colWidth - 1) + " ";
    }
  }
  return out;
}

// ============================================================================
// Classification Report Runner
// ============================================================================

interface ClassificationReport {
  name: string;
  accuracy: number;
  foldAccuracies: number[];
  confusionMatrix: ConfusionMatrix;
  featureImportance: Array<{ feature: string; importance: number }>;
  sampleCount: number;
  classCount: number;
}

function runClassification(
  name: string,
  samples: Sample[],
  featureNames: string[],
  kFolds: number = 5,
  numTrees: number = 50
): ClassificationReport {
  const folds = stratifiedKFold(samples, kFolds);
  const allPredictions: Array<{ actual: string; predicted: string }> = [];
  const foldAccuracies: number[] = [];
  let lastForest: RandomForest | null = null;
  let lastTestSamples: Sample[] = [];

  for (const { train, test } of folds) {
    const forest = trainRandomForest(train, numTrees);
    let correct = 0;
    for (const s of test) {
      const prediction = predictForest(forest, s.features);
      allPredictions.push({ actual: s.label, predicted: prediction });
      if (prediction === s.label) correct++;
    }
    foldAccuracies.push(test.length > 0 ? correct / test.length : 0);
    lastForest = forest;
    lastTestSamples = test;
  }

  const overallCorrect = allPredictions.filter((p) => p.actual === p.predicted).length;
  const accuracy = allPredictions.length > 0 ? overallCorrect / allPredictions.length : 0;

  const featureImportance = lastForest
    ? computeFeatureImportance(lastForest, lastTestSamples, featureNames)
    : [];

  return {
    name,
    accuracy,
    foldAccuracies,
    confusionMatrix: buildConfusionMatrix(allPredictions),
    featureImportance,
    sampleCount: samples.length,
    classCount: new Set(samples.map((s) => s.label)).size,
  };
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadLatestResults(): Promise<ExperimentRun> {
  const dir = "results/raw";
  if (!existsSync(dir)) {
    throw new Error(`No results directory found at ${dir}. Run the experiment first: pnpm run experiment`);
  }

  const files = (await readdir(dir)).filter((f) => f.endsWith(".json")).sort();
  if (files.length === 0) {
    throw new Error(`No experiment results found in ${dir}. Run the experiment first: pnpm run experiment`);
  }

  const latest = files[files.length - 1];
  console.log(`Loading: ${dir}/${latest}`);
  const raw = await readFile(`${dir}/${latest}`, "utf-8");
  return JSON.parse(raw) as ExperimentRun;
}

function resultToSamples(
  results: ExperimentResult[],
  labelFn: (r: ExperimentResult) => string | null,
  featureIndices?: number[]
): Sample[] {
  const samples: Sample[] = [];
  for (const r of results) {
    if (r.error) continue;
    const label = labelFn(r);
    if (label === null) continue;
    const allFeatures = signalsToFeatureVector(r.signals);
    const features = featureIndices ? selectFeatures(allFeatures, featureIndices) : allFeatures;
    samples.push({ features, label });
  }
  return samples;
}

// ============================================================================
// Report Formatting
// ============================================================================

function formatReport(report: ClassificationReport): string {
  const foldStr = report.foldAccuracies.map((a) => `${(a * 100).toFixed(1)}%`).join(", ");
  const topFeatures = report.featureImportance.slice(0, 10);

  let out = `\n${"═".repeat(60)}\n`;
  out += `  ${report.name}\n`;
  out += `${"═".repeat(60)}\n`;
  out += `  Accuracy:  ${(report.accuracy * 100).toFixed(1)}%\n`;
  out += `  Samples:   ${report.sampleCount}\n`;
  out += `  Classes:   ${report.classCount}\n`;
  out += `  Folds:     ${foldStr}\n`;

  if (topFeatures.length > 0) {
    out += `\n  Top Features (permutation importance):\n`;
    for (let i = 0; i < topFeatures.length; i++) {
      const f = topFeatures[i];
      const bar = "█".repeat(Math.max(0, Math.round(f.importance * 200)));
      out += `    ${(i + 1).toString().padStart(2)}. ${f.feature.padEnd(25)} ${(f.importance * 100).toFixed(1).padStart(6)}%  ${bar}\n`;
    }
  }

  out += formatConfusionMatrix(report.confusionMatrix);
  return out;
}

function verdictEmoji(accuracy: number): string {
  if (accuracy >= 0.8) return "STRONG SIGNAL";
  if (accuracy >= 0.5) return "MODERATE SIGNAL";
  return "WEAK SIGNAL";
}

function verdictDescription(accuracy: number): string {
  if (accuracy >= 0.8) return "Phenotype is real. Proceed to Phase 1.";
  if (accuracy >= 0.5) return "Some channels work. Investigate which, improve probes.";
  return "Hypothesis doesn't hold as tested. Rethink probe design or signal capture.";
}

// ============================================================================
// Main Analysis
// ============================================================================

async function analyze(): Promise<void> {
  console.log("\n  Soma Phase 0 — Phenotype Analysis\n");

  const run = await loadLatestResults();
  const validResults = run.results.filter((r) => !r.error);
  console.log(`  ${validResults.length} valid results from ${run.agentCount} agents × ${run.probeCount} probes`);
  console.log(`  ${run.errors.length} errors skipped\n`);

  if (validResults.length < 20) {
    console.error("  Not enough valid results for classification. Need at least 20.");
    process.exit(1);
  }

  // Build agent config lookup
  const agentConfigMap = new Map(AGENT_CONFIGS.map((c) => [c.id, c]));

  // --- 1. Overall Genome Classification ---
  const genomeSamples = resultToSamples(validResults, (r) => r.agentId);
  const genomeReport = runClassification(
    "GENOME CLASSIFICATION (All Features)",
    genomeSamples,
    FEATURE_NAMES
  );

  // --- 2. Per-Channel Classification ---
  const cogSamples = resultToSamples(validResults, (r) => r.agentId, COGNITIVE_INDICES);
  const cogReport = runClassification(
    "COGNITIVE CHANNEL ONLY",
    cogSamples,
    selectFeatureNames(COGNITIVE_INDICES)
  );

  const strSamples = resultToSamples(validResults, (r) => r.agentId, STRUCTURAL_INDICES);
  const strReport = runClassification(
    "STRUCTURAL CHANNEL ONLY",
    strSamples,
    selectFeatureNames(STRUCTURAL_INDICES)
  );

  const tmpSamples = resultToSamples(validResults, (r) => r.agentId, TEMPORAL_INDICES);
  const tmpReport = runClassification(
    "TEMPORAL CHANNEL ONLY",
    tmpSamples,
    selectFeatureNames(TEMPORAL_INDICES)
  );

  const errSamples = resultToSamples(validResults, (r) => r.agentId, ERROR_INDICES);
  const errReport = runClassification(
    "ERROR CHANNEL ONLY",
    errSamples,
    selectFeatureNames(ERROR_INDICES)
  );

  // --- 3. Model Family Classification ---
  const familySamples = resultToSamples(validResults, (r) => {
    const config = agentConfigMap.get(r.agentId);
    return config?.family ?? null;
  });
  const familyReport = familySamples.length >= 15
    ? runClassification(
        "MODEL FAMILY CLASSIFICATION (Llama vs Gemini vs Mistral vs ...)",
        familySamples,
        FEATURE_NAMES
      )
    : null;

  // --- 4. Epigenetic Detection ---
  // Only include the three llama3-70b variants (base, formal, chaotic)
  const epigeneticIds = new Set(["llama3-70b", "llama3-70b-formal", "llama3-70b-chaotic"]);
  const epiSamples = resultToSamples(validResults, (r) =>
    epigeneticIds.has(r.agentId) ? r.agentId : null
  );
  const epiReport = epiSamples.length >= 15
    ? runClassification("EPIGENETIC DETECTION (Same Model, Different Prompt)", epiSamples, FEATURE_NAMES)
    : null;

  // --- 5. Proxy Detection ---
  // Binary: real llama3-70b vs proxy-llama3-70b
  const proxyIds = new Set(["llama3-70b", "proxy-llama3-70b"]);
  const proxySamples = resultToSamples(validResults, (r) =>
    proxyIds.has(r.agentId) ? r.agentId : null
  );
  const proxyReport = proxySamples.length >= 10
    ? runClassification("PROXY DETECTION (Real vs Proxied Agent)", proxySamples, FEATURE_NAMES)
    : null;

  // Proxy with temporal features only (the true test)
  const proxyTemporalSamples = resultToSamples(
    validResults,
    (r) => (proxyIds.has(r.agentId) ? r.agentId : null),
    TEMPORAL_INDICES
  );
  const proxyTemporalReport = proxyTemporalSamples.length >= 10
    ? runClassification(
        "PROXY DETECTION (Temporal Features Only)",
        proxyTemporalSamples,
        selectFeatureNames(TEMPORAL_INDICES)
      )
    : null;

  // --- Output Reports ---
  const reports = [
    genomeReport,
    cogReport,
    strReport,
    tmpReport,
    errReport,
  ];
  if (familyReport) reports.push(familyReport);
  if (epiReport) reports.push(epiReport);
  if (proxyReport) reports.push(proxyReport);
  if (proxyTemporalReport) reports.push(proxyTemporalReport);

  let fullOutput = "";
  for (const report of reports) {
    const formatted = formatReport(report);
    console.log(formatted);
    fullOutput += formatted + "\n";
  }

  // --- Verdict ---
  const verdictStr = `
${"═".repeat(60)}
  PHASE 0 VERDICT
${"═".repeat(60)}

  Overall Genome Accuracy:   ${(genomeReport.accuracy * 100).toFixed(1)}%  →  ${verdictEmoji(genomeReport.accuracy)}
  Model Family Accuracy:     ${familyReport ? (familyReport.accuracy * 100).toFixed(1) + "%" : "(insufficient data)"}
  ${epiReport ? `Epigenetic Detection:      ${(epiReport.accuracy * 100).toFixed(1)}%` : "Epigenetic Detection:      (insufficient data)"}
  ${proxyReport ? `Proxy Detection (all):     ${(proxyReport.accuracy * 100).toFixed(1)}%` : "Proxy Detection:           (insufficient data)"}
  ${proxyTemporalReport ? `Proxy Detection (timing):  ${(proxyTemporalReport.accuracy * 100).toFixed(1)}%` : "Proxy Detection (timing):  (insufficient data)"}

  Per-Channel Breakdown:
    Cognitive:   ${(cogReport.accuracy * 100).toFixed(1)}%
    Structural:  ${(strReport.accuracy * 100).toFixed(1)}%
    Temporal:    ${(tmpReport.accuracy * 100).toFixed(1)}%
    Error:       ${(errReport.accuracy * 100).toFixed(1)}%

  ${verdictDescription(genomeReport.accuracy)}
${"═".repeat(60)}
`;
  console.log(verdictStr);
  fullOutput += verdictStr;

  // Save analysis report
  const analysisDir = "results/analysis";
  if (!existsSync(analysisDir)) {
    await mkdir(analysisDir, { recursive: true });
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const outputPath = `${analysisDir}/analysis-${timestamp}.txt`;
  await writeFile(outputPath, fullOutput);

  // Save machine-readable summary
  const summary = {
    timestamp: new Date().toISOString(),
    validSamples: validResults.length,
    errors: run.errors.length,
    genomeAccuracy: genomeReport.accuracy,
    familyAccuracy: familyReport?.accuracy ?? null,
    epigeneticAccuracy: epiReport?.accuracy ?? null,
    proxyAccuracy: proxyReport?.accuracy ?? null,
    proxyTemporalAccuracy: proxyTemporalReport?.accuracy ?? null,
    channelAccuracies: {
      cognitive: cogReport.accuracy,
      structural: strReport.accuracy,
      temporal: tmpReport.accuracy,
      error: errReport.accuracy,
    },
    topFeatures: genomeReport.featureImportance.slice(0, 10),
    verdict: verdictEmoji(genomeReport.accuracy),
  };
  await writeFile(
    `${analysisDir}/summary-${timestamp}.json`,
    JSON.stringify(summary, null, 2)
  );

  console.log(`  Reports saved to ${analysisDir}/`);
}

// --- Entry Point ---

analyze().catch((err) => {
  console.error("Analysis failed:", err);
  process.exit(1);
});
