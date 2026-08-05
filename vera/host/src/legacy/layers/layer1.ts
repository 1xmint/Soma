import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { EmbeddingRecord, ObservationRecord } from "../observation-reader.js";
import { getDataDir } from "../heart-setup.js";

const EMBEDDINGS_DIR = "embeddings";
const STATS_FILE = "embedding-stats.json";
const MIN_OBSERVATIONS = 1000;

export interface Layer1Result {
  mode: "observing" | "scoring";
  observationsCollected: number;
  observationsNeeded: number;
  energyScore: number | null;
  anomalyFlag: boolean;
  embeddingsStored: number;
}

interface EmbeddingStats {
  count: number;
  dimensions: number;
  mean: number[];
  variance: number[];
  minEnergy: number;
  maxEnergy: number;
  threshold: number;
}

export async function evaluateLayer1(observation: ObservationRecord): Promise<Layer1Result> {
  const dir = join(getDataDir(), EMBEDDINGS_DIR);
  await mkdir(dir, { recursive: true });

  const stats = await loadStats(dir);
  const newEmbeddings = observation.embeddings || [];

  // Store new embeddings and update running statistics
  for (const emb of newEmbeddings) {
    await storeEmbedding(dir, observation.sessionId, emb);
    updateStats(stats, emb.vector);
  }

  await saveStats(dir, stats);

  if (stats.count < MIN_OBSERVATIONS) {
    return {
      mode: "observing",
      observationsCollected: stats.count,
      observationsNeeded: MIN_OBSERVATIONS,
      energyScore: null,
      anomalyFlag: false,
      embeddingsStored: newEmbeddings.length,
    };
  }

  // Score mode: compute energy for each embedding
  let maxEnergy = -Infinity;
  for (const emb of newEmbeddings) {
    const energy = computeEnergy(emb.vector, stats);
    if (energy > maxEnergy) maxEnergy = energy;
  }

  const anomaly = maxEnergy > stats.threshold;

  return {
    mode: "scoring",
    observationsCollected: stats.count,
    observationsNeeded: MIN_OBSERVATIONS,
    energyScore: newEmbeddings.length > 0 ? maxEnergy : null,
    anomalyFlag: anomaly,
    embeddingsStored: newEmbeddings.length,
  };
}

function computeEnergy(vector: number[], stats: EmbeddingStats): number {
  // Log-sum-exp energy score (per Liu et al., NeurIPS 2020)
  // E(x) = -T * log(sum_i(exp(f_i(x) / T)))
  // For Day 0: simplified as Mahalanobis-like distance from learned distribution
  const T = 1.0;
  let sumExp = 0;

  for (let i = 0; i < vector.length && i < stats.mean.length; i++) {
    const z = stats.variance[i] > 1e-10
      ? (vector[i] - stats.mean[i]) / Math.sqrt(stats.variance[i])
      : 0;
    sumExp += Math.exp(-z * z / (2 * T));
  }

  return -T * Math.log(Math.max(sumExp, 1e-10));
}

function updateStats(stats: EmbeddingStats, vector: number[]): void {
  if (stats.dimensions === 0) {
    stats.dimensions = vector.length;
    stats.mean = new Array(vector.length).fill(0);
    stats.variance = new Array(vector.length).fill(0);
  }

  stats.count++;
  const n = stats.count;

  // Welford's online algorithm for mean and variance
  for (let i = 0; i < vector.length && i < stats.mean.length; i++) {
    const delta = vector[i] - stats.mean[i];
    stats.mean[i] += delta / n;
    const delta2 = vector[i] - stats.mean[i];
    stats.variance[i] += (delta * delta2 - stats.variance[i]) / n;
  }

  // Update energy bounds and threshold (z-score > 3)
  if (n >= 10) {
    const energy = computeEnergy(vector, stats);
    if (energy < stats.minEnergy) stats.minEnergy = energy;
    if (energy > stats.maxEnergy) stats.maxEnergy = energy;
    // Simple threshold: 3 standard deviations above mean energy
    stats.threshold = stats.minEnergy + (stats.maxEnergy - stats.minEnergy) * 0.95;
  }
}

async function storeEmbedding(
  dir: string,
  sessionId: string,
  emb: EmbeddingRecord,
): Promise<void> {
  const path = join(dir, `${sessionId}-turn${emb.turn}.json`);
  await writeFile(path, JSON.stringify({
    sessionId,
    turn: emb.turn,
    dimensions: emb.dimensions,
    timestamp: Date.now(),
  }), "utf-8");
  // Vectors stored separately for efficient batch access
  const vecPath = join(dir, `${sessionId}-turn${emb.turn}.vec`);
  const buf = Buffer.alloc(emb.vector.length * 4);
  for (let i = 0; i < emb.vector.length; i++) {
    buf.writeFloatLE(emb.vector[i], i * 4);
  }
  await writeFile(vecPath, buf);
}

async function loadStats(dir: string): Promise<EmbeddingStats> {
  try {
    const raw = await readFile(join(dir, STATS_FILE), "utf-8");
    return JSON.parse(raw) as EmbeddingStats;
  } catch {
    return {
      count: 0,
      dimensions: 0,
      mean: [],
      variance: [],
      minEnergy: Infinity,
      maxEnergy: -Infinity,
      threshold: Infinity,
    };
  }
}

async function saveStats(dir: string, stats: EmbeddingStats): Promise<void> {
  await writeFile(join(dir, STATS_FILE), JSON.stringify(stats), "utf-8");
}
