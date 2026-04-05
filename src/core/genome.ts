import {
  getCryptoProvider,
  type CryptoProvider,
  type SignKeyPair,
} from "./crypto-provider.js";

// Re-export key pair type for consumers
export type { SignKeyPair };

// --- Types ---

export interface Genome {
  modelProvider: string;
  modelId: string;
  modelVersion: string;
  systemPromptHash: string;
  toolManifestHash: string;
  runtimeId: string;
  /** Cloud provider (e.g. "aws", "gcp", "azure"). */
  cloudProvider?: string;
  /** Deployment region (e.g. "us-east-1"). */
  region?: string;
  /** Instance type (e.g. "g5.xlarge"). */
  instanceType?: string;
  /** Deployment tier: "tier1" (software) or "tier2" (TEE). */
  deploymentTier?: string;
  createdAt: number;
  version: number;
  parentHash: string | null;
}

export interface GenomeCommitment {
  genome: Genome;
  hash: string;
  signature: string; // base64-encoded signature
  publicKey: string; // base64-encoded public key
  did: string; // did:key identifier
}

// --- Helpers ---

/** Hash an arbitrary string, returned as hex. Delegates to the active provider. */
export function sha256(data: string, provider?: CryptoProvider): string {
  return (provider ?? getCryptoProvider()).hashing.hash(data);
}

/** Deterministic JSON serialization — sorted keys, no whitespace. */
function canonicalize(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}

/** Derive a did:key identifier from a public key. Uses the provider's multicodec prefix. */
export function publicKeyToDid(publicKey: Uint8Array, provider?: CryptoProvider): string {
  const p = provider ?? getCryptoProvider();
  const prefix = p.signing.multicodecPrefix;
  const multicodec = new Uint8Array(prefix.length + publicKey.length);
  multicodec.set(prefix, 0);
  multicodec.set(publicKey, prefix.length);
  return `did:key:z${p.encoding.encodeBase64(multicodec)}`;
}

/**
 * Decode a did:key identifier back to its public key bytes.
 * Strips the multicodec prefix. Throws on malformed input or wrong prefix.
 */
export function didToPublicKey(did: string, provider?: CryptoProvider): Uint8Array {
  const p = provider ?? getCryptoProvider();
  if (!did.startsWith('did:key:z')) {
    throw new Error(`invalid did:key format: ${did}`);
  }
  const encoded = did.slice('did:key:z'.length);
  const multicodec = p.encoding.decodeBase64(encoded);
  const prefix = p.signing.multicodecPrefix;
  if (multicodec.length < prefix.length) {
    throw new Error(`did:key too short: ${did}`);
  }
  for (let i = 0; i < prefix.length; i++) {
    if (multicodec[i] !== prefix[i]) {
      throw new Error(`did:key multicodec prefix mismatch: ${did}`);
    }
  }
  return multicodec.slice(prefix.length);
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
  cloudProvider?: string;
  region?: string;
  instanceType?: string;
  deploymentTier?: string;
  parentHash?: string | null;
  version?: number;
}, provider?: CryptoProvider): Genome {
  const hash = (data: string) => sha256(data, provider);
  return {
    modelProvider: config.modelProvider,
    modelId: config.modelId,
    modelVersion: config.modelVersion,
    systemPromptHash: hash(config.systemPrompt),
    toolManifestHash: hash(config.toolManifest),
    runtimeId: config.runtimeId,
    cloudProvider: config.cloudProvider,
    region: config.region,
    instanceType: config.instanceType,
    deploymentTier: config.deploymentTier,
    createdAt: Date.now(),
    version: config.version ?? 1,
    parentHash: config.parentHash ?? null,
  };
}

/** Compute the hash of a genome's canonical form. */
export function computeHash(genome: Genome, provider?: CryptoProvider): string {
  return sha256(canonicalize(genome), provider);
}

/**
 * Commit a genome by signing its hash with a key pair.
 * This is the "DNA sequencing" step — the agent declares what it is.
 */
export function commitGenome(
  genome: Genome,
  keyPair: SignKeyPair,
  provider?: CryptoProvider
): GenomeCommitment {
  const p = provider ?? getCryptoProvider();
  const hash = computeHash(genome, p);
  const hashBytes = new TextEncoder().encode(hash);
  const signature = p.signing.sign(hashBytes, keyPair.secretKey);

  return {
    genome,
    hash,
    signature: p.encoding.encodeBase64(signature),
    publicKey: p.encoding.encodeBase64(keyPair.publicKey),
    did: publicKeyToDid(keyPair.publicKey, p),
  };
}

/**
 * Verify a genome commitment:
 * 1. Hash matches the genome document
 * 2. Signature is valid for the hash
 * 3. DID matches the public key
 */
export function verifyCommitment(commitment: GenomeCommitment, provider?: CryptoProvider): boolean {
  const p = provider ?? getCryptoProvider();

  // Recompute hash from genome and check it matches
  const recomputedHash = computeHash(commitment.genome, p);
  if (recomputedHash !== commitment.hash) {
    return false;
  }

  // Verify signature
  const publicKey = p.encoding.decodeBase64(commitment.publicKey);
  const signature = p.encoding.decodeBase64(commitment.signature);
  const hashBytes = new TextEncoder().encode(commitment.hash);

  if (!p.signing.verify(hashBytes, signature, publicKey)) {
    return false;
  }

  // Verify DID matches public key
  const expectedDid = publicKeyToDid(publicKey, p);
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
