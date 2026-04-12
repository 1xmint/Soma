/**
 * Attack 6: Seed Prediction
 *
 * Adversary has full source code and attempts to predict or enumerate
 * the dynamic seed modification without the session key.
 *
 * The continuous parameter space (~10^6 points) derived from the session
 * key via HKDF makes enumeration infeasible. Without the session key,
 * the behavioral target is unknowable.
 *
 * Expected: failure — random guessing produces statistically detectable mismatch.
 */

import { getCryptoProvider } from "../../../core/crypto-provider.js";
import { deriveSeed, type SeedConfig } from "../../../heart/seed.js";
import type { AttackResult } from "../harness.js";

export function runSeedPredictionAttack(): AttackResult {
  const crypto = getCryptoProvider();

  // Step 1: The legitimate heart derives a seed
  const realSessionKey = crypto.random.randomBytes(32);
  const realConfig: SeedConfig = { sessionKey: realSessionKey, interactionCounter: 42 };
  const queryHash = "test-query-hash-abc123";
  const realSeed = deriveSeed(realConfig, queryHash);

  // Step 2: Adversary tries to predict the seed WITHOUT the session key.
  // They have full source code but not the session key.
  // They try N random session keys to find one that produces the same behavioral region.
  const ATTEMPTS = 10000;
  let regionMatches = 0;
  let exactNonceMatch = 0;

  for (let i = 0; i < ATTEMPTS; i++) {
    const guessKey = crypto.random.randomBytes(32);
    const guessConfig: SeedConfig = { sessionKey: guessKey, interactionCounter: 42 };
    const guessSeed = deriveSeed(guessConfig, queryHash);

    // Check if the guessed seed lands in the same behavioral region
    const verbosityMatch =
      guessSeed.expectedBehavioralRegion.verbosityRange[0] === realSeed.expectedBehavioralRegion.verbosityRange[0];
    const structureMatch =
      guessSeed.expectedBehavioralRegion.structureRange[0] === realSeed.expectedBehavioralRegion.structureRange[0];
    const formalityMatch =
      guessSeed.expectedBehavioralRegion.formalityRange[0] === realSeed.expectedBehavioralRegion.formalityRange[0];

    if (verbosityMatch && structureMatch && formalityMatch) {
      regionMatches++;
    }
    if (guessSeed.nonce === realSeed.nonce) {
      exactNonceMatch++;
    }
  }

  // With 5 bins per dimension, random chance of matching ALL 3 dimensions = 1/125 = 0.8%
  // Expected matches in 10000 attempts: ~80
  const expectedByChance = ATTEMPTS / 125;
  const regionMatchRate = regionMatches / ATTEMPTS;

  // Step 3: Even if attacker guesses the region for ONE interaction,
  // they must guess correctly for MULTIPLE interactions.
  // Test cumulative failure: 5 consecutive interactions
  let consecutiveSuccesses = 0;
  const CONSECUTIVE_TARGET = 5;
  let maxConsecutive = 0;
  let currentConsecutive = 0;

  for (let interaction = 0; interaction < 100; interaction++) {
    const guessKey = crypto.random.randomBytes(32);
    const realInteractionSeed = deriveSeed(
      { sessionKey: realSessionKey, interactionCounter: interaction },
      `query-${interaction}`
    );
    const guessInteractionSeed = deriveSeed(
      { sessionKey: guessKey, interactionCounter: interaction },
      `query-${interaction}`
    );

    const allMatch =
      guessInteractionSeed.expectedBehavioralRegion.verbosityRange[0] ===
        realInteractionSeed.expectedBehavioralRegion.verbosityRange[0] &&
      guessInteractionSeed.expectedBehavioralRegion.structureRange[0] ===
        realInteractionSeed.expectedBehavioralRegion.structureRange[0] &&
      guessInteractionSeed.expectedBehavioralRegion.formalityRange[0] ===
        realInteractionSeed.expectedBehavioralRegion.formalityRange[0];

    if (allMatch) {
      currentConsecutive++;
      if (currentConsecutive > maxConsecutive) maxConsecutive = currentConsecutive;
    } else {
      currentConsecutive = 0;
    }
  }

  consecutiveSuccesses = maxConsecutive;

  // Detection: attack fails if:
  // 1. No exact nonce match (cryptographic infeasibility)
  // 2. Region match rate is near random chance (no signal exploitation)
  // 3. Consecutive matches never reach the target (cumulative failure)
  const detected =
    exactNonceMatch === 0 &&
    regionMatchRate < 0.02 && // Close to theoretical 0.8%
    consecutiveSuccesses < CONSECUTIVE_TARGET;

  return {
    attackName: "Seed Prediction",
    description: "Enumerate/predict dynamic seed without session key",
    expectedDetection: "Failure — continuous space makes enumeration infeasible",
    detected,
    matchRatio: 1.0 - regionMatchRate, // Higher = better defense
    details: {
      attempts: ATTEMPTS,
      regionMatches,
      regionMatchRate: regionMatchRate.toFixed(4),
      expectedByChance: expectedByChance.toFixed(0),
      exactNonceMatches: exactNonceMatch,
      consecutiveRegionMatches: consecutiveSuccesses,
      consecutiveTarget: CONSECUTIVE_TARGET,
      searchSpaceSize: "~10^6 (5^3 bins × higher continuous resolution)",
    },
  };
}
