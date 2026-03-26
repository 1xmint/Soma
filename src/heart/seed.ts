/**
 * The heart seed — cryptographic entanglement of output with the heart.
 *
 * For each interaction the heart derives a deterministic seed from:
 * - The session key (known only to the two communicating parties)
 * - The interaction counter (prevents replay)
 * - A hash of the user's query (entangles seed with specific input)
 *
 * The seed selects a semantically neutral prompt modification that subtly
 * influences the model's output. This is NOT a watermark added after
 * generation — it modifies the INPUT so the model generates differently.
 *
 * The receiving party derives the same seed (they share the session key)
 * and verifies the response characteristics match the expected influence.
 * Verification is statistical, not exact.
 */

import {
  getCryptoProvider,
  type CryptoProvider,
} from "../core/crypto-provider.js";

/** Seed modifications — semantically neutral prompt additions. */
const SEED_MODIFICATIONS = [
  { id: "concise", prompt: "Be concise in your response.", expectedInfluence: "shorter_output" },
  { id: "thorough", prompt: "Provide thorough detail.", expectedInfluence: "longer_output" },
  { id: "frontload", prompt: "Start with the key point.", expectedInfluence: "frontloaded_structure" },
  { id: "buildup", prompt: "Build up to your conclusion.", expectedInfluence: "backloaded_structure" },
  { id: "examples", prompt: "Include concrete examples.", expectedInfluence: "example_presence" },
  { id: "structured", prompt: "Use structured formatting.", expectedInfluence: "formatted_output" },
  { id: "conversational", prompt: "Be conversational in tone.", expectedInfluence: "informal_tone" },
  { id: "precise", prompt: "Be precise and technical.", expectedInfluence: "technical_tone" },
] as const;

export type SeedModificationId = (typeof SEED_MODIFICATIONS)[number]["id"];
export type ExpectedInfluence = (typeof SEED_MODIFICATIONS)[number]["expectedInfluence"];

/** Configuration for seed derivation. */
export interface SeedConfig {
  sessionKey: Uint8Array;
  interactionCounter: number;
}

/** A derived seed for a single interaction. */
export interface HeartSeed {
  /** The derived nonce (hex). */
  nonce: string;
  /** The modification ID selected by the nonce. */
  modificationId: SeedModificationId;
  /** The prompt text to append to the system prompt. */
  promptModification: string;
  /** What the verifier checks for. */
  expectedInfluence: ExpectedInfluence;
  /** The interaction counter at derivation time. */
  interactionCounter: number;
  /** Session context string embedded in the modification. */
  sessionContext: string;
}

/**
 * Derive a heart seed for a specific interaction.
 *
 * Deterministic: same session key + counter + query = same seed.
 * The receiving party independently derives the same seed and verifies
 * that the response characteristics match the expected influence.
 */
export function deriveSeed(config: SeedConfig, queryHash: string, provider?: CryptoProvider): HeartSeed {
  const p = provider ?? getCryptoProvider();

  // Derive nonce: H(sessionKey || counter || queryHash)
  const material = new Uint8Array([
    ...config.sessionKey,
    ...new TextEncoder().encode(`|${config.interactionCounter}|${queryHash}`),
  ]);
  const nonce = p.hashing.hash(new TextDecoder().decode(material));

  // Select modification based on nonce (first 4 hex chars -> index)
  const modIndex = parseInt(nonce.slice(0, 4), 16) % SEED_MODIFICATIONS.length;
  const modification = SEED_MODIFICATIONS[modIndex];

  // Session context — a prefix derived from the nonce for model context influence
  const sessionContext = `SOMA-${nonce.slice(0, 8)}`;

  return {
    nonce,
    modificationId: modification.id,
    promptModification: `${modification.prompt} Session context: ${sessionContext}`,
    expectedInfluence: modification.expectedInfluence,
    interactionCounter: config.interactionCounter,
    sessionContext,
  };
}

/**
 * Apply a seed to a system prompt — modifies the input to influence generation.
 * This is NOT a watermark added after. It changes HOW the model generates.
 */
export function applySeed(systemPrompt: string, seed: HeartSeed): string {
  return `${systemPrompt}\n\n[${seed.promptModification}]`;
}

/**
 * Verify that a response matches the expected seed influence.
 * Returns a confidence score 0-1.
 *
 * Verification is statistical, not exact. We check behavioral characteristics
 * against the expected influence direction, relative to a baseline.
 */
export function verifySeedInfluence(
  responseText: string,
  seed: HeartSeed,
  baselineWordCount: number
): { verified: boolean; confidence: number; details: string } {
  const words = responseText.split(/\s+/).filter((w) => w.length > 0);
  const wordCount = words.length;

  switch (seed.expectedInfluence) {
    case "shorter_output": {
      const ratio = wordCount / Math.max(baselineWordCount, 1);
      const confidence = ratio < 0.8 ? 0.9 : ratio < 1.0 ? 0.6 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Word ratio: ${ratio.toFixed(2)}` };
    }
    case "longer_output": {
      const ratio = wordCount / Math.max(baselineWordCount, 1);
      const confidence = ratio > 1.2 ? 0.9 : ratio > 1.0 ? 0.6 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Word ratio: ${ratio.toFixed(2)}` };
    }
    case "frontloaded_structure": {
      const paragraphs = responseText.split(/\n\n/).filter((p) => p.trim().length > 0);
      if (paragraphs.length < 2) return { verified: true, confidence: 0.5, details: "Single paragraph" };
      const firstParaWords = paragraphs[0].split(/\s+/).length;
      const ratio = firstParaWords / wordCount;
      const confidence = ratio > 0.4 ? 0.8 : ratio > 0.25 ? 0.5 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Frontload ratio: ${ratio.toFixed(2)}` };
    }
    case "backloaded_structure": {
      const paragraphs = responseText.split(/\n\n/).filter((p) => p.trim().length > 0);
      if (paragraphs.length < 2) return { verified: true, confidence: 0.5, details: "Single paragraph" };
      const lastParaWords = paragraphs[paragraphs.length - 1].split(/\s+/).length;
      const ratio = lastParaWords / wordCount;
      const confidence = ratio > 0.4 ? 0.8 : ratio > 0.25 ? 0.5 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Backload ratio: ${ratio.toFixed(2)}` };
    }
    case "example_presence": {
      const hasExamples =
        /\b(?:for example|for instance|e\.g\.|such as|consider|suppose|imagine|like when)\b/i.test(
          responseText
        );
      const confidence = hasExamples ? 0.8 : 0.3;
      return { verified: hasExamples, confidence, details: `Examples present: ${hasExamples}` };
    }
    case "formatted_output": {
      const hasFormatting = /(?:^#{1,6}\s|\n[-*]\s|\n\d+[.)]\s|```|\*\*)/m.test(responseText);
      const confidence = hasFormatting ? 0.8 : 0.3;
      return { verified: hasFormatting, confidence, details: `Formatting present: ${hasFormatting}` };
    }
    case "informal_tone": {
      const contractions = (
        responseText.match(
          /\b(?:don't|won't|can't|it's|I'm|isn't|aren't|wasn't|weren't|couldn't|shouldn't|wouldn't|they're|we're|you're|he's|she's|that's|there's|here's|let's|who's|what's|how's)\b/g
        ) || []
      ).length;
      const ratio = (contractions / Math.max(wordCount, 1)) * 100;
      const confidence = ratio > 1.5 ? 0.8 : ratio > 0.5 ? 0.5 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Contraction rate: ${ratio.toFixed(2)}%` };
    }
    case "technical_tone": {
      const technicalPatterns =
        /\b(?:specifically|precisely|technically|defined as|characterized by|implementation|architecture|protocol|mechanism|algorithm|parameter|configuration)\b/gi;
      const matches = responseText.match(technicalPatterns) || [];
      const density = (matches.length / Math.max(wordCount, 1)) * 100;
      const confidence = density > 1.0 ? 0.8 : density > 0.3 ? 0.5 : 0.3;
      return { verified: confidence > 0.5, confidence, details: `Technical density: ${density.toFixed(2)}%` };
    }
  }
}

/** Get all available seed modifications (for testing/inspection). */
export function getSeedModifications(): ReadonlyArray<{
  id: SeedModificationId;
  prompt: string;
  expectedInfluence: ExpectedInfluence;
}> {
  return SEED_MODIFICATIONS;
}
