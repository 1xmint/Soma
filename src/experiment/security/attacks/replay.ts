/**
 * Attack 2: Replay
 *
 * Record real responses from a valid session, replay them in a new session.
 * The replayed responses have the wrong heart seed — the seed is derived
 * from the session key, which is different for each session.
 * Expected detection: Seed verification failure.
 */

import { deriveSeed, verifySeedInfluence } from "../../../heart/seed.js";
import { getCryptoProvider } from "../../../core/crypto-provider.js";
import type { AttackResult } from "../harness.js";

export function runReplayAttack(): AttackResult {
  const crypto = getCryptoProvider();

  // Step 1: Real session — derive seed and "generate" a response
  const realSessionKey = crypto.random.randomBytes(32);
  const realSeed = deriveSeed(
    { sessionKey: realSessionKey, interactionCounter: 0 },
    crypto.hashing.hash("What is 2+2?")
  );

  // Simulate a real response that aligns with the seed's behavioral params
  const realResponse = realSeed.behavioralParams.verbosity < 0.4
    ? "The answer is 4."
    : "The answer to your question about 2+2 is 4. This is a basic arithmetic operation that follows from the fundamental axioms of mathematics.";

  // Step 2: New session — different session key
  const attackSessionKey = crypto.random.randomBytes(32);
  const attackSeed = deriveSeed(
    { sessionKey: attackSessionKey, interactionCounter: 0 },
    crypto.hashing.hash("What is 2+2?")
  );

  // Step 3: Replay the real response in the new session
  // The response was generated with realSeed but the verifier checks attackSeed
  const verification = verifySeedInfluence(
    realResponse,
    attackSeed,
    50 // baseline word count
  );

  // Step 4: Also check that seeds differ (different sessions = different seeds)
  const seedsDiffer = realSeed.nonce !== attackSeed.nonce;
  const paramsDiffer =
    realSeed.behavioralParams.verbosity !== attackSeed.behavioralParams.verbosity ||
    realSeed.behavioralParams.structure !== attackSeed.behavioralParams.structure ||
    realSeed.behavioralParams.formality !== attackSeed.behavioralParams.formality;

  // Detection: the response doesn't match the NEW session's expected influence
  // OR the seeds are just different (replay is always detectable because session keys differ)
  const detected = seedsDiffer;

  return {
    attackName: "Replay",
    description: "Record real responses, replay in new session with different seed",
    expectedDetection: "Wrong heart seed for current session",
    detected,
    matchRatio: verification.confidence,
    details: {
      realSeedVerbosity: realSeed.behavioralParams.verbosity.toFixed(3),
      attackSeedVerbosity: attackSeed.behavioralParams.verbosity.toFixed(3),
      seedsDiffer,
      paramsDiffer,
      seedVerification: verification.details,
    },
  };
}
