import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import {
  createSomaHeart,
  HeartbeatChain,
  type HeartRuntime,
  type Heartbeat,
} from "soma-heart";
import {
  createGenome,
  commitGenome,
  type GenomeCommitment,
} from "soma-heart/core";
import { getCryptoProvider, type SignKeyPair } from "soma-heart/crypto-provider";

const VERA_DATA_DIR = join(process.cwd(), ".vera");
const IDENTITY_FILE = join(VERA_DATA_DIR, "identity.json");
const HEARTBEATS_FILE = join(VERA_DATA_DIR, "heartbeats.json");

interface StoredIdentity {
  publicKeyB64: string;
  secretKeyB64: string;
  genome: GenomeCommitment;
}

export async function initializeHeart(): Promise<{ heart: HeartRuntime; keyPair: SignKeyPair }> {
  await mkdir(VERA_DATA_DIR, { recursive: true });
  const provider = getCryptoProvider();

  let keyPair: SignKeyPair;
  let genome: GenomeCommitment;
  let priorHeartbeats: Heartbeat[] | undefined;

  try {
    const raw = await readFile(IDENTITY_FILE, "utf-8");
    const stored: StoredIdentity = JSON.parse(raw);
    keyPair = {
      publicKey: provider.encoding.decodeBase64(stored.publicKeyB64),
      secretKey: provider.encoding.decodeBase64(stored.secretKeyB64),
    };
    genome = stored.genome;

    try {
      const hbRaw = await readFile(HEARTBEATS_FILE, "utf-8");
      priorHeartbeats = JSON.parse(hbRaw);
    } catch {
      // Fresh chain
    }
  } catch {
    keyPair = provider.signing.generateKeyPair();
    const genomeDoc = createGenome({
      modelProvider: "vera",
      modelId: "vera-evaluator-day0",
      modelVersion: "0.1.0",
      systemPrompt: "Vera Day 0 evaluation framework — guardian model for code quality assessment",
      toolManifest: "evaluate_observation, layer0_check, layer1_energy, layer2_structural",
      runtimeId: "vera-day0",
      deploymentTier: "tier1",
    }, provider);
    genome = commitGenome(genomeDoc, keyPair, provider);

    const stored: StoredIdentity = {
      publicKeyB64: provider.encoding.encodeBase64(keyPair.publicKey),
      secretKeyB64: provider.encoding.encodeBase64(keyPair.secretKey),
      genome,
    };
    await writeFile(IDENTITY_FILE, JSON.stringify(stored, null, 2), "utf-8");
  }

  const heart = createSomaHeart({
    genome,
    signingKeyPair: keyPair,
    modelApiKey: "vera-internal",
    modelBaseUrl: "http://localhost:11434/v1",
    modelId: "vera-evaluator-day0",
    restoreHeartbeats: priorHeartbeats,
  });

  return { heart, keyPair };
}

export async function persistHeartbeats(heart: HeartRuntime): Promise<void> {
  await mkdir(VERA_DATA_DIR, { recursive: true });
  const heartbeats = [...heart.heartbeats.getChain()];
  await writeFile(HEARTBEATS_FILE, JSON.stringify(heartbeats), "utf-8");
}

export function getDataDir(): string {
  return VERA_DATA_DIR;
}
