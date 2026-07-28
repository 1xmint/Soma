import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { HeartbeatChain } from "soma-heart";

export interface ActionRecord {
  type: "file_read" | "file_write" | "command";
  path?: string;
  command?: string;
  success: boolean;
  bytesWritten?: number;
  exitCode?: number;
}

export interface EmbeddingRecord {
  turn: number;
  dimensions: number;
  vector: number[];
}

export interface ObservationRecord {
  sessionId: string;
  cortexDid: string;
  startedAt: number;
  completedAt: number;
  heartbeats: Array<{
    sequence: number;
    previousHash: string;
    eventType: string;
    eventHash: string;
    timestamp: number;
    hash: string;
  }>;
  chainHead: string;
  chainLength: number;
  headSignature: string;
  task: string;
  actions: ActionRecord[];
  embeddings: EmbeddingRecord[];
}

export async function readObservation(path: string): Promise<ObservationRecord> {
  const raw = await readFile(path, "utf-8");
  return JSON.parse(raw) as ObservationRecord;
}

export async function listObservations(dir: string): Promise<string[]> {
  try {
    const files = await readdir(dir);
    return files
      .filter(f => f.endsWith(".json"))
      .map(f => join(dir, f))
      .sort();
  } catch {
    return [];
  }
}

export function verifyHeartbeatChain(observation: ObservationRecord): boolean {
  return HeartbeatChain.verify(observation.heartbeats as any);
}

export function getWrittenFiles(observation: ObservationRecord): string[] {
  return observation.actions
    .filter(a => a.type === "file_write" && a.success && a.path)
    .map(a => a.path!);
}

export function getCommandResults(observation: ObservationRecord): ActionRecord[] {
  return observation.actions.filter(a => a.type === "command");
}
