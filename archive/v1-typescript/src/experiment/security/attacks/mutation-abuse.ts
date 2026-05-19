/**
 * Attack 8: Genome Mutation Abuse
 *
 * Mutate genome rapidly to keep the profile permanently immature,
 * preventing the sensorium from building enough data to verify.
 *
 * Expected failure: mutations are testable claims. Each mutation adds a
 * consistency check (declared change must explain observed change, undeclared
 * dimensions must be stable). Rapid mutation = rapid verification obligations.
 *
 * 10 mutations in 24 hours produces RED from prediction failures, not
 * AMBER from immaturity.
 */

import type { PhenotypicSignals } from "../../signals.js";
import {
  createProfile,
  updateProfile,
  verifyMutation,
  type PhenotypicProfile,
  type MutationRecord,
} from "../../../sensorium/matcher.js";
import type { AttackResult } from "../harness.js";

/** Synthetic Claude-like signals. */
function claudeSignals(variation: number = 0): PhenotypicSignals {
  return {
    cognitive: { hedgeCount: 4 + variation, certaintyCount: 2, disclaimerCount: 2, questionsBack: 1, empathyMarkers: 3, hedgeToCertaintyRatio: 0.67 },
    structural: { charCount: 800 + variation * 20, wordCount: 150 + variation * 5, lineCount: 15, paragraphCount: 4, bulletLines: 3, numberedListLines: 0, headerLines: 1, codeBlocks: 0, boldCount: 2, listToContentRatio: 0.2, openingPattern: "direct", closingPattern: "offer", avgWordLength: 5.2, avgSentenceLength: 18 },
    temporal: { timeToFirstToken: 450 + variation * 10, interTokenIntervals: [12, 14, 11, 13, 12], meanInterval: 12.4, stdInterval: 1.1, medianInterval: 12, burstiness: 3.2, totalStreamingDuration: 2500 + variation * 50, tokenCount: 200 + variation * 7 },
    error: { containsRefusal: false, uncertaintyAdmissions: 1, assertiveWhenWrong: 0, attemptedImpossible: false, selfCorrections: 0, confidenceRatio: 0.4 },
  };
}

/** GPT-like signals — what the attacker is secretly running. */
function gptSignals(variation: number = 0): PhenotypicSignals {
  return {
    cognitive: { hedgeCount: 1 + variation, certaintyCount: 5, disclaimerCount: 0, questionsBack: 0, empathyMarkers: 1, hedgeToCertaintyRatio: 0.17 },
    structural: { charCount: 500 + variation * 15, wordCount: 90 + variation * 3, lineCount: 8, paragraphCount: 2, bulletLines: 0, numberedListLines: 3, headerLines: 0, codeBlocks: 1, boldCount: 0, listToContentRatio: 0.35, openingPattern: "preamble", closingPattern: "statement", avgWordLength: 4.8, avgSentenceLength: 12 },
    temporal: { timeToFirstToken: 200 + variation * 5, interTokenIntervals: [6, 7, 5, 6, 8], meanInterval: 6.4, stdInterval: 1.0, medianInterval: 6, burstiness: 1.8, totalStreamingDuration: 1200 + variation * 30, tokenCount: 120 + variation * 4 },
    error: { containsRefusal: false, uncertaintyAdmissions: 0, assertiveWhenWrong: 1, attemptedImpossible: false, selfCorrections: 0, confidenceRatio: 0.8 },
  };
}

export function runMutationAbuseAttack(): AttackResult {
  // Step 1: Build initial Claude profile with 10 observations
  // The sensorium accumulates this — mutations don't reset profiles.
  const baselineProfile: PhenotypicProfile = createProfile("claude-genome-v0");
  for (let i = 0; i < 10; i++) {
    updateProfile(baselineProfile, claudeSignals(i % 5));
  }

  // Step 2: Attacker performs 10 rapid mutations, each claiming minor changes
  // (e.g., region change) while actually switching to GPT.
  //
  // The key insight: mutations constrain, they don't reset. The sensorium
  // verifies each mutation against the ACCUMULATED profile, not a fresh one.
  // The attacker can't escape history by mutating rapidly.
  const mutationRecords: MutationRecord[] = [];
  let failedConsistencyChecks = 0;

  for (let mutation = 0; mutation < 10; mutation++) {
    // Attacker claims: "I changed my region" (minor change)
    // Reality: they're running GPT instead of Claude
    const changedFields = ["region"]; // Minor — should NOT cause vocabulary/topology changes

    // Post-mutation: attacker sends GPT signals (the deception)
    const postMutationSignals = gptSignals(mutation % 5);

    // Sensorium verifies against the baseline profile —
    // mutations don't reset accumulated knowledge
    const verification = verifyMutation(baselineProfile, postMutationSignals, changedFields);

    mutationRecords.push({
      fromHash: `claude-genome-v${mutation}`,
      toHash: `claude-genome-v${mutation + 1}`,
      changedFields,
      timestamp: Date.now() + mutation * 1000,
      consistency: verification.consistency,
      postMutationObservations: 1,
    });

    if (verification.consistency < 0.5) {
      failedConsistencyChecks++;
    }
  }

  // Step 3: Check detection
  // The attacker claimed 10 minor region changes, but the behavioral shift
  // is massive — vocabulary, timing, everything changed. Consistency should be low.
  const avgConsistency = mutationRecords.reduce((sum, r) => sum + r.consistency, 0) / mutationRecords.length;

  // Detection criteria:
  // - Average mutation consistency < 0.5 (mutations don't explain changes)
  // - Majority of mutations failed consistency checks
  const detected = avgConsistency < 0.5 && failedConsistencyChecks >= 7;

  return {
    attackName: "Genome Mutation Abuse",
    description: "Rapid mutations to keep profile immature and evade verification",
    expectedDetection: "RED from mutation consistency failures — mutations don't explain observed changes",
    detected,
    matchRatio: avgConsistency,
    details: {
      totalMutations: 10,
      failedConsistencyChecks,
      avgConsistency: avgConsistency.toFixed(3),
      perMutationConsistency: mutationRecords.map((r, i) => ({
        mutation: i + 1,
        claimed: r.changedFields.join(","),
        consistency: r.consistency.toFixed(3),
      })),
      profilesCreated: 11, // initial + 10 mutations
      maxProfileDepth: 2, // attacker keeps profiles shallow
    },
  };
}
