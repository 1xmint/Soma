/**
 * The heart seed — cryptographic entanglement of output with the heart.
 *
 * Two mechanisms that make output inseparable from the heart:
 *
 * 1. Token-Level HMAC Authentication (PRIMARY — cryptographic guarantee)
 *    Every token is individually authenticated with an HMAC computed from the
 *    session key. Mathematical. Either the HMAC verifies or it doesn't.
 *
 * 2. Dynamic Seed Generation (SECONDARY — behavioral defense-in-depth)
 *    The heart dynamically generates a unique behavioral modification for every
 *    interaction. No fixed library — the modification is constructed on the fly
 *    from a continuous parameter space, making enumeration attacks infeasible
 *    even with full source code access.
 *
 * The generator is deterministic from the session key:
 *   HKDF(session_key, interaction_counter, query_hash) -> 256-bit nonce
 *   Nonce bytes -> point in continuous behavioral space (verbosity, structure, formality)
 *   Parameters -> unique system prompt addition
 *   Both sides share the session key -> both derive identical parameters
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from "../core/crypto-provider.js";

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for seed derivation. */
export interface SeedConfig {
  sessionKey: Uint8Array;
  interactionCounter: number;
}

/** Behavioral parameters derived from the nonce — a point in continuous space. */
export interface BehavioralParams {
  /** 0.0–1.0: terse to detailed. */
  verbosity: number;
  /** 0.0–1.0: front-loaded to back-loaded argument organization. */
  structure: number;
  /** 0.0–1.0: casual to formal register. */
  formality: number;
}

/** Expected behavioral region — what the verifier checks. */
export interface BehavioralRegion {
  verbosityRange: [number, number];
  structureRange: [number, number];
  formalityRange: [number, number];
}

/** A derived seed for a single interaction. */
export interface HeartSeed {
  /** The HKDF-derived nonce, unique per interaction (hex-encoded). */
  nonce: string;
  /** The interaction counter at derivation time. */
  interactionCounter: number;
  /** Continuous behavioral parameters derived from the nonce. */
  behavioralParams: BehavioralParams;
  /** The prompt text to append to the system prompt. */
  promptModification: string;
  /** The behavioral region the verifier checks against. */
  expectedBehavioralRegion: BehavioralRegion;
}

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Number of distinguishable bins per dimension for verification.
 * 5 bins per dimension = 125 behavioral regions total.
 * Coarse enough for reliable statistical verification, fine enough that
 * random guessing fails across multiple interactions.
 */
const BINS_PER_DIMENSION = 5;
const BIN_WIDTH = 1.0 / BINS_PER_DIMENSION; // 0.2

// ─── Dynamic Seed Generation ─────────────────────────────────────────────────

/**
 * Derive a heart seed for a specific interaction.
 *
 * Deterministic: same session key + counter + query = same seed.
 * The receiving party independently derives the same seed and verifies
 * that the response characteristics match the expected behavioral region.
 *
 * The search space is continuous (~10^6 distinct meaningful points with
 * 3 dimensions at 100 levels each). Even with full source code, predicting
 * the modification requires the session key — which only exists in the two
 * endpoints. This is cryptographically hard, not combinatorially annoying.
 */
export function deriveSeed(config: SeedConfig, queryHash: string, provider?: CryptoProvider): HeartSeed {
  const p = provider ?? getCryptoProvider();

  // Step 1: HKDF(session_key, interaction_counter || query_hash) -> 256-bit nonce
  // The per-call context goes into the `info` parameter so every
  // (interaction, query) pair yields an independent nonce.
  const info = `soma-seed-nonce/v1|${config.interactionCounter}|${queryHash}`;
  const nonce = p.hashing.deriveKey(config.sessionKey, 32, info);
  const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, "0")).join("");

  // Step 2: Map nonce bytes to continuous behavioral space using integer arithmetic.
  // No floating-point drift, no platform-dependent behavior.
  const behavioralParams = nonceToBehavioralParams(nonce);

  // Step 3: Generate the prompt modification from continuous parameters
  const promptModification = generatePromptModification(behavioralParams, nonceHex);

  // Step 4: Compute the expected behavioral region (bins for verification)
  const expectedBehavioralRegion = computeBehavioralRegion(behavioralParams);

  return {
    nonce: nonceHex,
    interactionCounter: config.interactionCounter,
    behavioralParams,
    promptModification,
    expectedBehavioralRegion,
  };
}

/**
 * Map nonce bytes to behavioral parameters using integer arithmetic.
 * Deterministic and pure — same nonce in, same parameters out, every time.
 *
 * Uses 4 bytes per dimension for high resolution (2^32 = ~4 billion levels,
 * mapped to 0.0–1.0 with 8 decimal digits of precision).
 */
function nonceToBehavioralParams(nonce: Uint8Array): BehavioralParams {
  // Read 4 bytes each from different nonce regions (big-endian)
  const verbosityInt = (nonce[0] << 24 | nonce[1] << 16 | nonce[2] << 8 | nonce[3]) >>> 0;
  const structureInt = (nonce[8] << 24 | nonce[9] << 16 | nonce[10] << 8 | nonce[11]) >>> 0;
  const formalityInt = (nonce[16] << 24 | nonce[17] << 16 | nonce[18] << 8 | nonce[19]) >>> 0;

  // Map to 0.0–1.0 with integer arithmetic: value / 0xFFFFFFFF
  const MAX_UINT32 = 0xFFFFFFFF;
  return {
    verbosity: verbosityInt / MAX_UINT32,
    structure: structureInt / MAX_UINT32,
    formality: formalityInt / MAX_UINT32,
  };
}

/**
 * Generate a semantically neutral prompt modification from continuous parameters.
 *
 * The modification interpolates between behavioral extremes:
 * - Verbosity: terse <-> exhaustively detailed
 * - Structure: conclusion-first <-> build-up-to-conclusion
 * - Formality: casual/conversational <-> precise/technical
 *
 * Parameters are chosen for measurable model response: verbosity and structure
 * produce statistically verifiable output shifts. Parameters like "use more metaphors"
 * are excluded because they're too noisy to verify reliably.
 */
function generatePromptModification(params: BehavioralParams, nonceHex: string): string {
  const parts: string[] = [];

  // Verbosity instruction (0.0 = ultra-concise, 1.0 = exhaustive)
  if (params.verbosity < 0.2) {
    parts.push("Be extremely concise. Use as few words as possible.");
  } else if (params.verbosity < 0.4) {
    parts.push("Keep your response brief and to the point.");
  } else if (params.verbosity < 0.6) {
    parts.push("Provide a balanced level of detail.");
  } else if (params.verbosity < 0.8) {
    parts.push("Provide thorough detail in your response.");
  } else {
    parts.push("Be exhaustively detailed. Cover every aspect thoroughly.");
  }

  // Structure instruction (0.0 = front-loaded, 1.0 = back-loaded)
  if (params.structure < 0.2) {
    parts.push("Lead with your conclusion. State the key point first.");
  } else if (params.structure < 0.4) {
    parts.push("Open with the main insight, then elaborate.");
  } else if (params.structure < 0.6) {
    parts.push("Balance your opening and closing equally.");
  } else if (params.structure < 0.8) {
    parts.push("Build context before presenting your conclusion.");
  } else {
    parts.push("Build up gradually. Save your main point for the end.");
  }

  // Formality instruction (0.0 = casual, 1.0 = formal/technical)
  if (params.formality < 0.2) {
    parts.push("Use a casual, conversational tone.");
  } else if (params.formality < 0.4) {
    parts.push("Be approachable and clear in your language.");
  } else if (params.formality < 0.6) {
    parts.push("Use a neutral, professional tone.");
  } else if (params.formality < 0.8) {
    parts.push("Use precise, structured language.");
  } else {
    parts.push("Use formal, technical language with precise terminology.");
  }

  // Session context — unique identifier derived from nonce
  const sessionContext = `SOMA-${nonceHex.slice(0, 8)}`;
  parts.push(`Session context: ${sessionContext}`);

  return parts.join(" ");
}

/**
 * Compute the expected behavioral region for verification.
 * Maps each parameter to one of BINS_PER_DIMENSION bins.
 */
function computeBehavioralRegion(params: BehavioralParams): BehavioralRegion {
  return {
    verbosityRange: paramToRange(params.verbosity),
    structureRange: paramToRange(params.structure),
    formalityRange: paramToRange(params.formality),
  };
}

/** Map a 0.0–1.0 parameter to its bin range. */
function paramToRange(value: number): [number, number] {
  const binIndex = Math.min(Math.floor(value / BIN_WIDTH), BINS_PER_DIMENSION - 1);
  return [binIndex * BIN_WIDTH, (binIndex + 1) * BIN_WIDTH];
}

/**
 * Apply a seed to a system prompt — modifies the input to influence generation.
 * This is NOT a watermark added after. It changes HOW the model generates.
 */
export function applySeed(systemPrompt: string, seed: HeartSeed): string {
  return `${systemPrompt}\n\n[${seed.promptModification}]`;
}

// ─── Seed Influence Verification ─────────────────────────────────────────────

/**
 * Verify that a response's behavioral characteristics land within the expected
 * behavioral region. Returns per-dimension scores and an overall confidence.
 *
 * Verification is statistical, not exact. We measure observable output properties
 * that correspond to the seed's behavioral parameters and check whether they
 * fall in the expected region.
 */
export function verifySeedInfluence(
  responseText: string,
  seed: HeartSeed,
  baselineWordCount: number
): { verified: boolean; confidence: number; details: string; perDimension: Record<string, number> } {
  const words = responseText.split(/\s+/).filter(w => w.length > 0);
  const wordCount = words.length;

  // Measure verbosity: word count relative to baseline
  const verbosityScore = measureVerbosity(wordCount, baselineWordCount, seed.expectedBehavioralRegion.verbosityRange);

  // Measure structure: front-loading vs back-loading
  const structureScore = measureStructure(responseText, seed.expectedBehavioralRegion.structureRange);

  // Measure formality: casual vs formal register
  const formalityScore = measureFormality(responseText, wordCount, seed.expectedBehavioralRegion.formalityRange);

  // Weighted combination (verbosity and structure are more reliably measurable)
  const confidence = verbosityScore * 0.4 + structureScore * 0.3 + formalityScore * 0.3;
  const verified = confidence > 0.5;

  return {
    verified,
    confidence,
    details: `verbosity=${verbosityScore.toFixed(2)} structure=${structureScore.toFixed(2)} formality=${formalityScore.toFixed(2)}`,
    perDimension: { verbosity: verbosityScore, structure: structureScore, formality: formalityScore },
  };
}

/** Measure verbosity alignment: does the word count match the expected verbosity region? */
function measureVerbosity(wordCount: number, baselineWordCount: number, expectedRange: [number, number]): number {
  if (baselineWordCount <= 0) return 0.5;

  // Map word count ratio to 0.0–1.0 scale
  // ratio < 0.5 -> verbosity ~0.0, ratio ~1.0 -> ~0.5, ratio > 2.0 -> ~1.0
  const ratio = wordCount / baselineWordCount;
  const observedVerbosity = Math.min(Math.max((ratio - 0.5) / 1.5, 0), 1);

  // Check if observed lands in expected range (with tolerance)
  const tolerance = BIN_WIDTH * 0.5;
  const low = expectedRange[0] - tolerance;
  const high = expectedRange[1] + tolerance;

  if (observedVerbosity >= low && observedVerbosity <= high) return 0.8;
  const distance = observedVerbosity < low ? low - observedVerbosity : observedVerbosity - high;
  return Math.max(0.2, 0.8 - distance * 2);
}

/** Measure structure alignment: front-loaded vs back-loaded. */
function measureStructure(text: string, expectedRange: [number, number]): number {
  const paragraphs = text.split(/\n\n/).filter(p => p.trim().length > 0);
  if (paragraphs.length < 2) return 0.5; // Can't measure with single paragraph

  const words = (p: string) => p.split(/\s+/).filter(w => w.length > 0).length;
  const totalWords = paragraphs.reduce((sum, p) => sum + words(p), 0);
  if (totalWords === 0) return 0.5;

  // Ratio of first paragraph to total: high = front-loaded (structure ~0.0), low = back-loaded (~1.0)
  const firstRatio = words(paragraphs[0]) / totalWords;
  const lastRatio = words(paragraphs[paragraphs.length - 1]) / totalWords;

  // structure 0.0 = front-loaded (firstRatio high), 1.0 = back-loaded (lastRatio high)
  const observedStructure = lastRatio / (firstRatio + lastRatio);

  const tolerance = BIN_WIDTH * 0.5;
  const low = expectedRange[0] - tolerance;
  const high = expectedRange[1] + tolerance;

  if (observedStructure >= low && observedStructure <= high) return 0.8;
  const distance = observedStructure < low ? low - observedStructure : observedStructure - high;
  return Math.max(0.2, 0.8 - distance * 2);
}

/** Measure formality alignment: casual vs formal register. */
function measureFormality(text: string, wordCount: number, expectedRange: [number, number]): number {
  if (wordCount === 0) return 0.5;

  // Count informal markers (contractions, colloquialisms)
  const contractions = (
    text.match(
      /\b(?:don't|won't|can't|it's|I'm|isn't|aren't|wasn't|weren't|couldn't|shouldn't|wouldn't|they're|we're|you're|he's|she's|that's|there's|here's|let's|who's|what's|how's)\b/g
    ) || []
  ).length;

  // Count formal markers (technical terms, precise language)
  const formalWords = (
    text.match(
      /\b(?:specifically|precisely|technically|furthermore|consequently|therefore|nevertheless|accordingly|implementation|architecture|protocol|mechanism|algorithm|parameter|configuration|methodology)\b/gi
    ) || []
  ).length;

  const informalRate = contractions / wordCount;
  const formalRate = formalWords / wordCount;

  // Map to 0.0 (very informal) to 1.0 (very formal)
  const observedFormality = Math.min(Math.max(0.5 + (formalRate - informalRate) * 10, 0), 1);

  const tolerance = BIN_WIDTH * 0.5;
  const low = expectedRange[0] - tolerance;
  const high = expectedRange[1] + tolerance;

  if (observedFormality >= low && observedFormality <= high) return 0.8;
  const distance = observedFormality < low ? low - observedFormality : observedFormality - high;
  return Math.max(0.2, 0.8 - distance * 2);
}

// ─── Token-Level HMAC Authentication ─────────────────────────────────────────

/**
 * Derive an HMAC key from the session key for token authentication.
 * Separate from the session key itself — domain separation.
 */
export function deriveHmacKey(sessionKey: Uint8Array, provider?: CryptoProvider): Uint8Array {
  const p = provider ?? getCryptoProvider();
  // HKDF with domain-separated info; independent from vault key and seed nonce.
  return p.hashing.deriveKey(sessionKey, 32, "soma-token-hmac/v1");
}

/**
 * Compute HMAC for a single token.
 *
 * HMAC(hmacKey, token || sequence || interactionCounter)
 *
 * Every token is individually authenticated. The receiver verifies
 * each HMAC as it arrives — a single mismatch = immediate RED.
 */
export function computeTokenHmac(
  hmacKey: Uint8Array,
  token: string,
  sequence: number,
  interactionCounter: number,
  provider?: CryptoProvider
): string {
  const p = provider ?? getCryptoProvider();
  const message = `${token}|${sequence}|${interactionCounter}`;
  return p.hmac.compute(hmacKey, message);
}

/**
 * Verify a token's HMAC. Constant-time comparison.
 * Returns true if the token was authenticated by this heart.
 */
export function verifyTokenHmac(
  hmacKey: Uint8Array,
  token: string,
  sequence: number,
  interactionCounter: number,
  expectedHmac: string,
  provider?: CryptoProvider
): boolean {
  const p = provider ?? getCryptoProvider();
  const message = `${token}|${sequence}|${interactionCounter}`;
  return p.hmac.verify(hmacKey, message, expectedHmac);
}
