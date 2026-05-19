/**
 * Fork Ceremony — offline lineage provisioning between two hearts.
 *
 * The ceremony is a provisioning step, not a runtime protocol. It runs
 * once per parent-child relationship, at deployment time, by an operator
 * who has access to both hearts' encrypted blobs and passwords.
 *
 * Protocol (from lineage-fork-ceremony proposal §3):
 *   1. Decrypt parent heart blob
 *   2. Extract parent signing key
 *   3. Decrypt or create child heart
 *   4. Create lineage certificate (parent signs over child)
 *   5. Build child's lineage chain (append parent's chain if any)
 *   6. Patch child state with lineage
 *   7. Wipe parent signing key from memory
 *   8. Re-encrypt child heart blob
 *
 * Security (proposal §12):
 *   - No network requests
 *   - All key material wiped from memory after use
 *   - Idempotent: re-running produces a new cert (new nonce/timestamp)
 *     but does not corrupt the child's existing state
 *   - Patched child blob is verifiable by verifyLineageChain immediately
 */

import { type CryptoProvider, getCryptoProvider } from '../core/crypto-provider.js';
import { createGenome, commitGenome, type GenomeCommitment } from '../core/genome.js';
import { createLineageCertificate, type LineageCertificate } from './lineage.js';
import {
  loadHeartState, serializeHeart, signKeyPairFromJson, signKeyPairToJson,
  type HeartState, type ScryptParams,
} from './persistence.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/**
 * Options for the fork ceremony — everything needed to establish
 * a cryptographic parent-child lineage between two hearts.
 *
 * @example
 * ```ts
 * const result = forkCeremony({
 *   parentBlob: fs.readFileSync('parent-heart.json', 'utf8'),
 *   parentSecret: process.env.PARENT_SECRET!,
 *   childBlob: fs.readFileSync('child-heart.json', 'utf8'),
 *   childSecret: process.env.CHILD_SECRET!,
 *   capabilities: ['tool:search', 'content:post'],
 *   ttl: 90 * 24 * 60 * 60 * 1000, // 90 days
 * });
 * fs.writeFileSync('child-heart.json', result.childBlob);
 * ```
 */
export interface ForkCeremonyOptions {
  /** Encrypted JSON blob of the parent heart. */
  parentBlob: string;
  /** Password to decrypt the parent heart. */
  parentSecret: string;
  /** Encrypted JSON blob of an existing child heart. If omitted, a fresh child heart is created. */
  childBlob?: string;
  /** Password to encrypt/decrypt the child heart. */
  childSecret: string;
  /** Capabilities to grant (defaults to [] = inherit all from parent). */
  capabilities?: string[];
  /** TTL in milliseconds (optional). */
  ttl?: number;
  /** Budget credits (optional). */
  budgetCredits?: number;
  /** Crypto provider override (optional). */
  provider?: CryptoProvider;
  /** scrypt KDF parameters for re-encryption (test use — production should use defaults). */
  scryptParams?: ScryptParams;
}

/**
 * Result of a fork ceremony — contains the patched child blob and
 * metadata for revocation reference and chain verification.
 */
export interface ForkCeremonyResult {
  /** Re-encrypted patched child heart blob. */
  childBlob: string;
  /** Lineage certificate ID for revocation reference. */
  certificateId: string;
  /** Parent heart's DID. */
  parentDid: string;
  /** Child heart's DID. */
  childDid: string;
  /** Root of the lineage chain. */
  rootDid: string;
  /** Total chain length after ceremony. */
  chainLength: number;
}

// ─── Ceremony ───────────────────────────────────────────────────────────────

/**
 * Run an offline fork ceremony — establish cryptographic parent-child
 * lineage between two hearts.
 *
 * Decrypts the parent heart to obtain its signing key, creates (or
 * decrypts) the child heart, issues a lineage certificate signed by
 * the parent, patches the child's state with the full lineage chain,
 * and re-encrypts the child blob. The parent blob is never modified.
 *
 * All signing key material is wiped from memory before returning.
 *
 * @param opts - Ceremony configuration (see {@link ForkCeremonyOptions}).
 * @returns The patched child blob and ceremony metadata.
 * @throws On invalid blobs, wrong passwords, or mismatched crypto providers.
 *
 * @example
 * ```ts
 * import { forkCeremony } from 'soma-heart';
 *
 * const result = forkCeremony({
 *   parentBlob: parentEncrypted,
 *   parentSecret: 'parent-password',
 *   childBlob: childEncrypted,
 *   childSecret: 'child-password',
 *   capabilities: ['tool:search'],
 * });
 * // result.childBlob contains the patched, re-encrypted child heart
 * ```
 */
export function forkCeremony(opts: ForkCeremonyOptions): ForkCeremonyResult {
  if (!opts.childSecret) {
    throw new Error('childSecret required');
  }

  const p = opts.provider ?? getCryptoProvider();

  // Step 1: Decrypt parent heart
  const parentState = loadHeartState(opts.parentBlob, opts.parentSecret, { provider: p });

  // Step 2: Extract parent signing key
  const parentKp = signKeyPairFromJson(parentState.signingKey, p);

  // Step 3: Parent genome commitment is already on state
  const parentGenome: GenomeCommitment = parentState.genome;

  // Step 4: Resolve or create child heart
  let childState: HeartState;
  let childGenome: GenomeCommitment;
  let freshChildSecretKey: Uint8Array | null = null;

  if (opts.childBlob) {
    childState = loadHeartState(opts.childBlob, opts.childSecret, { provider: p });
    childGenome = childState.genome;
  } else {
    const childKp = p.signing.generateKeyPair();
    freshChildSecretKey = childKp.secretKey;

    const genome = createGenome({
      modelProvider: 'pending',
      modelId: 'pending',
      modelVersion: '0',
      systemPrompt: '',
      toolManifest: '[]',
      runtimeId: 'fork-ceremony',
    }, p);
    childGenome = commitGenome(genome, childKp, p);

    childState = {
      version: 1,
      genome: childGenome,
      signingKey: signKeyPairToJson(childKp, p),
      modelId: 'pending',
      modelBaseUrl: 'pending',
      dataSources: [],
      credentials: [],
      heartbeats: [],
      revocations: [],
      savedAt: Date.now(),
    };
  }

  // Step 5: Create lineage certificate
  const cert = createLineageCertificate({
    parent: parentGenome,
    parentSigningKey: parentKp.secretKey,
    child: childGenome,
    capabilities: opts.capabilities,
    ttl: opts.ttl,
    budgetCredits: opts.budgetCredits,
    provider: p,
  });

  // Step 6: Build child's lineage chain
  let chain: LineageCertificate[];
  let rootDid: string;

  if (parentState.lineageChain && parentState.lineageChain.length > 0) {
    chain = [...parentState.lineageChain, cert];
    rootDid = parentState.lineageRootDid!;
  } else {
    chain = [cert];
    rootDid = parentGenome.did;
  }

  // Step 7: Patch child state
  const patchedState: HeartState = {
    ...childState,
    lineageChain: chain,
    lineageRootDid: rootDid,
  };

  // Step 8: Wipe parent signing key
  parentKp.secretKey.fill(0);
  if (freshChildSecretKey) {
    freshChildSecretKey.fill(0);
  }

  // Step 9: Re-serialize child
  const childBlobOut = serializeHeart(patchedState, opts.childSecret, {
    scrypt: opts.scryptParams,
    provider: p,
  });

  // Step 10: Return result
  return {
    childBlob: childBlobOut,
    certificateId: cert.id,
    parentDid: parentGenome.did,
    childDid: childGenome.did,
    rootDid,
    chainLength: chain.length,
  };
}
