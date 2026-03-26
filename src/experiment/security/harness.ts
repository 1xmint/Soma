/**
 * Security Harness — runs all 5 attacks and verifies detection.
 *
 * All attacks MUST be detected. If any attack succeeds undetected,
 * the security model has a gap.
 */

import { runImpersonationAttack } from "./attacks/impersonation.js";
import { runReplayAttack } from "./attacks/replay.js";
import { runSignalInjectionAttack } from "./attacks/signal-injection.js";
import { runTimingManipulationAttack } from "./attacks/timing-manipulation.js";
import { runCompositeAttack } from "./attacks/composite.js";

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
 * Run the complete security harness — all 5 attacks.
 * Returns a report with per-attack and aggregate results.
 */
export function runSecurityHarness(): SecurityReport {
  const results: AttackResult[] = [
    runImpersonationAttack(),
    runReplayAttack(),
    runSignalInjectionAttack(),
    runTimingManipulationAttack(),
    runCompositeAttack(),
  ];

  const detected = results.filter((r) => r.detected).length;

  return {
    timestamp: Date.now(),
    totalAttacks: results.length,
    detected,
    undetected: results.length - detected,
    allDetected: detected === results.length,
    results,
  };
}
