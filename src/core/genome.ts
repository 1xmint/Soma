import { createHash } from "node:crypto";
import nacl from "tweetnacl";
import { encodeBase64, decodeBase64 } from "tweetnacl-util";

// --- Types ---

export interface Genome {
  modelProvider: string;
  modelId: string;
  modelVersion: string;
  systemPromptHash: string;
  toolManifestHash: string;
  runtimeId: string;
  createdAt: number;
  version: number;
  parentHash: string | null;
}

export interface GenomeCommitment {
  genome: Genome;
  hash: string;
  signature: string; // base64-encoded Ed25519 signature
  publicKey: string; // base64-encoded Ed25519 public key
  did: string; // did:key identifier
}

// --- Helpers ---

/** SHA-256 hash of an arbitrary string, returned as hex. */
export function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Deterministic JSON serialization — sorted keys, no whitespace. */
function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}

/** Derive a did:key identifier from an Ed25519 public key. */
export function publicKeyToDid(publicKey: Uint8Array): string {
  // Multicodec prefix for Ed25519 public key: 0xed 0x01
  const multicodec = new Uint8Array(2 + publicKey.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKey, 2);
  return `did:key:z${encodeBase64(multicodec)}`;
}

// --- Core Operations ---

/**
 * Create a genome from agent configuration.
 * System prompt and tool manifest are hashed — the originals never leave the agent.
 */
export function createGenome(config: {
  modelProvider: string;
  modelId: string;
  modelVersion: string;
  systemPrompt: string;
  toolManifest: string;
  runtimeId: string;
  parentHash?: string | null;
  version?: number;
}): Genome {
  return {
    modelProvider: config.modelProvider,
    modelId: config.modelId,
    modelVersion: config.modelVersion,
    systemPromptHash: sha256(config.systemPrompt),
    toolManifestHash: sha256(config.toolManifest),
    runtimeId: config.runtimeId,
    createdAt: Date.now(),
    version: config.version ?? 1,
    parentHash: config.parentHash ?? null,
  };
}

/** Compute the SHA-256 hash of a genome's canonical form. */
export function computeHash(genome: Genome): string {
  return sha256(canonicalize(genome));
}

/**
 * Commit a genome by signing its hash with an Ed25519 key pair.
 * This is the "DNA sequencing" step — the agent declares what it is.
 */
export function commitGenome(
  genome: Genome,
  keyPair: nacl.SignKeyPair
): GenomeCommitment {
  const hash = computeHash(genome);
  const hashBytes = new TextEncoder().encode(hash);
  const signature = nacl.sign.detached(hashBytes, keyPair.secretKey);

  return {
    genome,
    hash,
    signature: encodeBase64(signature),
    publicKey: encodeBase64(keyPair.publicKey),
    did: publicKeyToDid(keyPair.publicKey),
  };
}

/**
 * Verify a genome commitment:
 * 1. Hash matches the genome document
 * 2. Signature is valid for the hash
 * 3. DID matches the public key
 */
export function verifyCommitment(commitment: GenomeCommitment): boolean {
  // Recompute hash from genome and check it matches
  const recomputedHash = computeHash(commitment.genome);
  if (recomputedHash !== commitment.hash) {
    return false;
  }

  // Verify Ed25519 signature
  const publicKey = decodeBase64(commitment.publicKey);
  const signature = decodeBase64(commitment.signature);
  const hashBytes = new TextEncoder().encode(commitment.hash);

  if (!nacl.sign.detached.verify(hashBytes, signature, publicKey)) {
    return false;
  }

  // Verify DID matches public key
  const expectedDid = publicKeyToDid(publicKey);
  if (commitment.did !== expectedDid) {
    return false;
  }

  return true;
}

/**
 * Mutate a genome — like biological mutation, tracked and versioned.
 * Creates a new genome linked to its parent via hash chain.
 */
export function mutateGenome(
  parent: Genome,
  parentHash: string,
  changes: Partial<
    Pick<
      Genome,
      | "modelProvider"
      | "modelId"
      | "modelVersion"
      | "systemPromptHash"
      | "toolManifestHash"
      | "runtimeId"
    >
  >
): Genome {
  return {
    ...parent,
    ...changes,
    createdAt: Date.now(),
    version: parent.version + 1,
    parentHash,
  };
}
