/**
 * Self-test: verifies the Vera evaluation pipeline works on a synthetic observation.
 * Run: node dist/self-test.js
 */

import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { HeartbeatChain } from "soma-heart";
import { initializeHeart, persistHeartbeats } from "./heart-setup.js";
import { evaluate } from "./evaluator.js";
import type { ObservationRecord, ActionRecord, EmbeddingRecord } from "./observation-reader.js";

const TEST_DIR = join(process.cwd(), ".vera-test");
const TEST_FILE = join(TEST_DIR, "test-output.ts");

async function selfTest() {
  console.log("Vera Self-Test — Evaluating synthetic observation\n");

  // Create a test file that Vera will analyze
  await mkdir(TEST_DIR, { recursive: true });
  await writeFile(TEST_FILE, `
import { readFile } from "node:fs/promises";

export async function greet(name: string): Promise<string> {
  if (!name) throw new Error("Name required");
  return \`Hello, \${name}!\`;
}

export async function readConfig(path: string): Promise<string> {
  const content = await readFile(path, "utf-8");
  return JSON.parse(content);
}
`, "utf-8");

  // Build a synthetic heartbeat chain
  const chain = new HeartbeatChain();
  chain.record("session_start", JSON.stringify({ task: "test", model: "qwen2.5-coder:14b" }));
  chain.record("query_received", "test-prompt-hash");
  chain.record("model_call_start", JSON.stringify({ model: "qwen2.5-coder:14b", turn: 1 }));
  chain.record("model_call_end", JSON.stringify({ model: "qwen2.5-coder:14b", turn: 1, outputHash: "abc123" }));
  chain.record("tool_call", JSON.stringify({ tool: "write_file", argsHash: "def456" }));
  chain.record("tool_result", JSON.stringify({ tool: "write_file", success: true, outputHash: "ghi789" }));
  chain.record("response_sent", JSON.stringify({ turn: 1, status: "complete" }));

  // Create synthetic embeddings (random, 384 dimensions)
  const embeddings: EmbeddingRecord[] = [{
    turn: 1,
    dimensions: 384,
    vector: Array.from({ length: 384 }, () => Math.random() * 2 - 1),
  }];

  const actions: ActionRecord[] = [
    { type: "file_write", path: TEST_FILE, success: true, bytesWritten: 250 },
  ];

  const observation: ObservationRecord = {
    sessionId: "test-session-001",
    cortexDid: "did:key:zTEST_CORTEX",
    startedAt: Date.now() - 5000,
    completedAt: Date.now(),
    heartbeats: [...chain.getChain()],
    chainHead: chain.head,
    chainLength: chain.length,
    headSignature: "test-signature",
    task: "Create a greeting utility module",
    actions,
    embeddings,
  };

  // Initialize Vera's heart and evaluate
  const { heart, keyPair } = await initializeHeart();
  console.log(`Vera DID: ${heart.did}`);

  const result = await evaluate(heart, keyPair, observation);

  console.log("\n--- Self-Test Results ---");
  console.log(`Chain verified: ${result.chainVerified}`);
  console.log(`Layer 0 score: ${(result.layer0.score * 100).toFixed(1)}%`);
  console.log(`  Files checked: ${result.layer0.fileChecks.length}`);
  console.log(`  Compilation: ${result.layer0.compilationCheck.checked ? (result.layer0.compilationCheck.passed ? "PASS" : "FAIL") : "NOT CHECKED"}`);
  console.log(`Layer 1 mode: ${result.layer1.mode} (${result.layer1.observationsCollected} obs collected)`);
  console.log(`Layer 2 score: ${(result.layer2.score * 100).toFixed(1)}%`);
  console.log(`  Files analyzed: ${result.layer2.files.length}`);
  if (result.layer2.files.length > 0) {
    const f = result.layer2.files[0];
    console.log(`  First file: entropy=${f.entropy.toFixed(2)}, complexity=${f.complexity}, nesting=${f.nestingDepth}`);
    console.log(`  Imports: ${f.importCount}, suspicious: ${f.suspiciousImports.join(", ") || "none"}`);
  }
  console.log(`Overall: ${(result.overallScore * 100).toFixed(1)}% (confidence: ${(result.confidence * 100).toFixed(0)}%)`);
  console.log(`Anomaly flags: ${result.anomalyFlags.length > 0 ? result.anomalyFlags.join(", ") : "none"}`);
  console.log(`Vera heartbeats: ${heart.heartbeats.length}`);
  console.log(`Evaluation saved: ${result.evaluationId}`);

  await persistHeartbeats(heart);

  // Cleanup test file
  await rm(TEST_DIR, { recursive: true, force: true });

  const allGood = result.chainVerified &&
    result.layer0.score > 0 &&
    result.layer2.score > 0 &&
    result.overallScore > 0;

  console.log(`\n${allGood ? "SELF-TEST PASSED" : "SELF-TEST FAILED"}`);
  process.exit(allGood ? 0 : 1);
}

selfTest().catch((err) => {
  console.error("Self-test failed:", err);
  process.exit(1);
});
