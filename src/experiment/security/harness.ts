/**
 * Security Harness — runs all 8 attacks and verifies detection.
 *
 * All attacks MUST be detected. If any attack succeeds undetected,
 * the security model has a gap.
 *
 * Attacks 1-5: original security attacks
 * Attack 6: Seed prediction (new — dynamic seed enumeration)
 * Attack 7: Slow drift poisoning (new — gradual model swap)
 * Attack 8: Genome mutation abuse (new — rapid mutations to evade)
 */

import { runImpersonationAttack } from "./attacks/impersonation.js";
import { runReplayAttack } from "./attacks/replay.js";
import { runSignalInjectionAttack } from "./attacks/signal-injection.js";
import { runTimingManipulationAttack } from "./attacks/timing-manipulation.js";
import { runCompositeAttack } from "./attacks/composite.js";
import { runSeedPredictionAttack } from "./attacks/seed-prediction.js";
import { runSlowDriftAttack } from "./attacks/slow-drift.js";
import { runMutationAbuseAttack } from "./attacks/mutation-abuse.js";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AttackResult {
  attackName: string;
  description: string;
  expectedDetection: string;
  detected: boolean;
  matchRatio: number;
  details: Record<string, unknown>;
}

export interface SecurityReport {
  timestamp: number;
  totalAttacks: number;
  detected: number;
  undetected: number;
  allDetected: boolean;
  results: AttackResult[];
}

// ─── Harness ────────────────────────────────────────────────────────────────

/**
 * Run the complete security harness — all 8 attacks.
 * Returns a report with per-attack and aggregate results.
 */
export function runSecurityHarness(): SecurityReport {
  const results: AttackResult[] = [
    // Original 5 attacks
    runImpersonationAttack(),
    runReplayAttack(),
    runSignalInjectionAttack(),
    runTimingManipulationAttack(),
    runCompositeAttack(),
    // New attacks (Phase 2)
    runSeedPredictionAttack(),
    runSlowDriftAttack(),
    runMutationAbuseAttack(),
  ];

  const detected = results.filter(r => r.detected).length;

  return {
    timestamp: Date.now(),
    totalAttacks: results.length,
    detected,
    undetected: results.length - detected,
    allDetected: detected === results.length,
    results,
  };
}
