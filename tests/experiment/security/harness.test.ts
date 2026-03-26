import { describe, it, expect } from "vitest";
import { runSecurityHarness, type SecurityReport } from "../../../src/experiment/security/harness.js";
import { formatSecurityReport } from "../../../src/experiment/security/report.js";
import { runImpersonationAttack } from "../../../src/experiment/security/attacks/impersonation.js";
import { runReplayAttack } from "../../../src/experiment/security/attacks/replay.js";
import { runSignalInjectionAttack } from "../../../src/experiment/security/attacks/signal-injection.js";
import { runTimingManipulationAttack } from "../../../src/experiment/security/attacks/timing-manipulation.js";
import { runCompositeAttack } from "../../../src/experiment/security/attacks/composite.js";

describe("Security Harness", () => {
  describe("Individual Attacks", () => {
    it("Attack 1: Impersonation — detected via phenotype mismatch", () => {
      const result = runImpersonationAttack();
      expect(result.detected).toBe(true);
      expect(result.matchRatio).toBeLessThan(0.8); // Not GREEN
      expect((result.details.maxZScore as number)).toBeGreaterThan(5); // Extreme deviations
      expect(result.attackName).toBe("Impersonation");
    });

    it("Attack 2: Replay — detected via wrong heart seed", () => {
      const result = runReplayAttack();
      expect(result.detected).toBe(true);
      expect(result.details.seedsDiffer).toBe(true);
      expect(result.attackName).toBe("Replay");
    });

    it("Attack 3: Signal Injection — detected via artificial timing", () => {
      const result = runSignalInjectionAttack();
      expect(result.detected).toBe(true);
      expect(result.attackName).toBe("Signal Injection");
    });

    it("Attack 4: Timing Manipulation — detected via chunk disruption", () => {
      const result = runTimingManipulationAttack();
      expect(result.detected).toBe(true);
      expect(result.attackName).toBe("Timing Manipulation");
    });

    it("Attack 5: Composite Agent — detected via cross-category instability", () => {
      const result = runCompositeAttack();
      expect(result.detected).toBe(true);
      expect(result.attackName).toBe("Composite Agent");
    });
  });

  describe("Full Harness", () => {
    it("runs all 5 attacks", () => {
      const report = runSecurityHarness();
      expect(report.totalAttacks).toBe(5);
      expect(report.results.length).toBe(5);
    });

    it("ALL attacks must be detected", () => {
      const report = runSecurityHarness();
      expect(report.allDetected).toBe(true);
      expect(report.detected).toBe(5);
      expect(report.undetected).toBe(0);

      // Print the report for visibility
      for (const result of report.results) {
        expect(result.detected).toBe(true);
      }
    });

    it("report contains per-attack details", () => {
      const report = runSecurityHarness();
      for (const result of report.results) {
        expect(result.attackName).toBeTruthy();
        expect(result.description).toBeTruthy();
        expect(result.expectedDetection).toBeTruthy();
        expect(typeof result.matchRatio).toBe("number");
        expect(result.details).toBeDefined();
      }
    });
  });

  describe("Report Formatting", () => {
    it("formats a readable report", () => {
      const report = runSecurityHarness();
      const formatted = formatSecurityReport(report);
      expect(formatted).toContain("SOMA SECURITY HARNESS REPORT");
      expect(formatted).toContain("ALL DETECTED");
      expect(formatted).toContain("Impersonation");
      expect(formatted).toContain("Replay");
      expect(formatted).toContain("Signal Injection");
      expect(formatted).toContain("Timing Manipulation");
      expect(formatted).toContain("Composite Agent");
      expect(formatted).toContain("5/5");
    });
  });
});
