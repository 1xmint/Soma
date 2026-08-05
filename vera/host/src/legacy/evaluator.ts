import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { HeartRuntime } from "soma-heart";
import type { SignKeyPair } from "soma-heart/crypto-provider";
import { getCryptoProvider } from "soma-heart/crypto-provider";
import { sha256 } from "soma-heart/core";
import type { ObservationRecord } from "./observation-reader.js";
import { verifyHeartbeatChain } from "./observation-reader.js";
import { evaluateLayer0, type Layer0Result } from "./layers/layer0.js";
import { evaluateLayer1, type Layer1Result } from "./layers/layer1.js";
import { evaluateLayer2, type Layer2Result } from "./layers/layer2.js";
import { getDataDir } from "./heart-setup.js";

export interface EvaluationResult {
  evaluationId: string;
  veraDid: string;
  cortexDid: string;
  sessionId: string;
  timestamp: number;
  chainVerified: boolean;
  layer0: Layer0Result;
  layer1: Layer1Result;
  layer2: Layer2Result;
  confidence: number;
  anomalyFlags: string[];
  overallScore: number;
  headSignature: string;
}

const EVALUATIONS_DIR = "evaluations";

export async function evaluate(
  heart: HeartRuntime,
  keyPair: SignKeyPair,
  observation: ObservationRecord,
): Promise<EvaluationResult> {
  const chain = heart.heartbeats;
  const evaluationId = `vera-eval-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  chain.record("session_start", JSON.stringify({
    evaluationId,
    cortexDid: observation.cortexDid,
    sessionId: observation.sessionId,
    heartbeatCount: observation.heartbeats.length,
  }));

  // Verify Cortex's heartbeat chain integrity
  const chainVerified = verifyHeartbeatChain(observation);
  chain.record("tool_call", JSON.stringify({
    tool: "verify_chain",
    cortexDid: observation.cortexDid,
    result: chainVerified,
  }));

  if (!chainVerified) {
    console.log("  WARNING: Cortex heartbeat chain failed verification!");
  }

  // Run evaluation layers
  chain.record("tool_call", JSON.stringify({ tool: "layer0_evaluate" }));
  const layer0 = await evaluateLayer0(observation);
  chain.record("tool_result", JSON.stringify({
    tool: "layer0",
    score: layer0.score,
    compilationPassed: layer0.compilationCheck.passed,
  }));

  chain.record("tool_call", JSON.stringify({ tool: "layer1_evaluate" }));
  const layer1 = await evaluateLayer1(observation);
  chain.record("tool_result", JSON.stringify({
    tool: "layer1",
    mode: layer1.mode,
    energyScore: layer1.energyScore,
    observationsCollected: layer1.observationsCollected,
  }));

  chain.record("tool_call", JSON.stringify({ tool: "layer2_evaluate" }));
  const layer2 = await evaluateLayer2(observation);
  chain.record("tool_result", JSON.stringify({
    tool: "layer2",
    score: layer2.score,
    entropy: layer2.aggregateEntropy,
    complexity: layer2.aggregateComplexity,
    flagCount: layer2.dependencyFlags.length,
  }));

  // Compute combined score and confidence
  const { overallScore, confidence, anomalyFlags } = combineResults(
    chainVerified, layer0, layer1, layer2,
  );

  // Sign the evaluation
  const provider = getCryptoProvider();
  const evalHash = sha256(JSON.stringify({ evaluationId, overallScore, confidence, anomalyFlags }));
  const sig = provider.signing.sign(
    new TextEncoder().encode(evalHash),
    keyPair.secretKey,
  );

  chain.record("response_sent", JSON.stringify({
    evaluationId,
    overallScore,
    confidence,
    anomalyFlagCount: anomalyFlags.length,
  }));

  const result: EvaluationResult = {
    evaluationId,
    veraDid: heart.did,
    cortexDid: observation.cortexDid,
    sessionId: observation.sessionId,
    timestamp: Date.now(),
    chainVerified,
    layer0,
    layer1,
    layer2,
    confidence,
    anomalyFlags,
    overallScore,
    headSignature: provider.encoding.encodeBase64(sig),
  };

  // Persist evaluation
  const evalDir = join(getDataDir(), EVALUATIONS_DIR);
  await mkdir(evalDir, { recursive: true });
  const path = join(evalDir, `${evaluationId}.json`);
  await writeFile(path, JSON.stringify(result, null, 2), "utf-8");

  return result;
}

function combineResults(
  chainVerified: boolean,
  layer0: Layer0Result,
  layer1: Layer1Result,
  layer2: Layer2Result,
): { overallScore: number; confidence: number; anomalyFlags: string[] } {
  const anomalyFlags: string[] = [];

  if (!chainVerified) {
    anomalyFlags.push("CHAIN_INTEGRITY_FAILED");
  }

  if (!layer0.compilationCheck.passed && layer0.compilationCheck.checked) {
    anomalyFlags.push("COMPILATION_FAILED");
  }

  if (layer0.testResults && layer0.testResults.passRate < 1.0) {
    anomalyFlags.push("TESTS_FAILING");
  }

  if (layer1.anomalyFlag) {
    anomalyFlags.push("ENERGY_ANOMALY");
  }

  if (layer2.dependencyFlags.length > 0) {
    for (const flag of layer2.dependencyFlags) {
      anomalyFlags.push(`SUSPICIOUS: ${flag}`);
    }
  }

  if (layer2.aggregateEntropy > 6.0) {
    anomalyFlags.push("HIGH_ENTROPY");
  }

  if (layer2.aggregateComplexity > 50) {
    anomalyFlags.push("HIGH_COMPLEXITY");
  }

  // Weighted score: Layer 0 = 50%, Layer 2 = 50% (Layer 1 not scoring yet on Day 0)
  let overallScore: number;
  if (layer1.mode === "scoring" && layer1.energyScore !== null) {
    // When Layer 1 is active: L0=40%, L1=20%, L2=40%
    const l1Score = layer1.anomalyFlag ? 0.3 : 1.0;
    overallScore = layer0.score * 0.4 + l1Score * 0.2 + layer2.score * 0.4;
  } else {
    overallScore = layer0.score * 0.5 + layer2.score * 0.5;
  }

  if (!chainVerified) {
    overallScore *= 0.1;
  }

  // Confidence: how much we trust this evaluation
  let confidence = 0.5;
  if (layer0.compilationCheck.checked) confidence += 0.15;
  if (layer0.testResults?.ran) confidence += 0.15;
  if (layer1.mode === "scoring") confidence += 0.1;
  if (chainVerified) confidence += 0.1;
  confidence = Math.min(1.0, confidence);

  return { overallScore, confidence, anomalyFlags };
}
