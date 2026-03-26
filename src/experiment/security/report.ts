/**
 * Security report formatting and output.
 */

import type { SecurityReport, AttackResult } from "./harness.js";

/** Format a security report as a human-readable string. */
export function formatSecurityReport(report: SecurityReport): string {
  const lines: string[] = [];

  lines.push("╔══════════════════════════════════════════════════════════╗");
  lines.push("║            SOMA SECURITY HARNESS REPORT                ║");
  lines.push("╠══════════════════════════════════════════════════════════╣");
  lines.push(`║  Timestamp:  ${new Date(report.timestamp).toISOString()}`);
  lines.push(`║  Attacks:    ${report.totalAttacks}`);
  lines.push(`║  Detected:   ${report.detected}/${report.totalAttacks}`);
  lines.push(`║  Status:     ${report.allDetected ? "ALL DETECTED ✓" : "BREACH — UNDETECTED ATTACKS ✗"}`);
  lines.push("╠══════════════════════════════════════════════════════════╣");

  for (const result of report.results) {
    lines.push("");
    lines.push(`  Attack: ${result.attackName}`);
    lines.push(`  ${result.description}`);
    lines.push(`  Expected: ${result.expectedDetection}`);
    lines.push(`  Detected: ${result.detected ? "YES ✓" : "NO ✗"}`);
    lines.push(`  Match Ratio: ${result.matchRatio.toFixed(4)}`);

    for (const [key, value] of Object.entries(result.details)) {
      if (Array.isArray(value)) {
        lines.push(`  ${key}:`);
        for (const item of value) {
          lines.push(`    - ${item}`);
        }
      } else {
        lines.push(`  ${key}: ${value}`);
      }
    }

    lines.push("  ────────────────────────────────────────");
  }

  lines.push("");
  lines.push("╚══════════════════════════════════════════════════════════╝");

  return lines.join("\n");
}
