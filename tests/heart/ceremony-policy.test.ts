import { describe, it, expect } from "vitest";
import {
  createCeremonyPolicy,
  DEFAULT_POLICY,
} from "../../src/heart/ceremony-policy.js";

describe("CeremonyPolicy — default map", () => {
  const decide = createCeremonyPolicy();

  it("allows read at L0", () => {
    expect(decide("read", "L0").ok).toBe(true);
  });

  it("rejects read below L0 — N/A, lowest tier", () => {
    // Any tier >= L0 passes; negative case handled by unknown tiers.
    expect(decide("read", "L3").ok).toBe(true);
  });

  it("requires L1 for write", () => {
    expect(decide("write", "L0").ok).toBe(false);
    expect(decide("write", "L1").ok).toBe(true);
  });

  it("requires L2 for spend and deploy", () => {
    expect(decide("spend", "L1").ok).toBe(false);
    expect(decide("spend", "L2").ok).toBe(true);
    expect(decide("deploy", "L1").ok).toBe(false);
    expect(decide("deploy", "L2").ok).toBe(true);
  });

  it("requires L3 for admin", () => {
    expect(decide("admin", "L2").ok).toBe(false);
    expect(decide("admin", "L3").ok).toBe(true);
  });

  it("defaults unknown classes to L2 (fail-safe)", () => {
    expect(decide("something-weird", "L1").ok).toBe(false);
    expect(decide("something-weird", "L2").ok).toBe(true);
  });
});

describe("CeremonyPolicy — overrides", () => {
  it("lets callers tighten a default class", () => {
    const decide = createCeremonyPolicy({ overrides: { write: "L2" } });
    expect(decide("write", "L1").ok).toBe(false);
    expect(decide("write", "L2").ok).toBe(true);
  });

  it("lets callers loosen a default class", () => {
    const decide = createCeremonyPolicy({ overrides: { deploy: "L1" } });
    expect(decide("deploy", "L1").ok).toBe(true);
  });

  it("lets callers add custom classes", () => {
    const decide = createCeremonyPolicy({
      overrides: { "voice-call": "L2" },
    });
    expect(decide("voice-call", "L1").ok).toBe(false);
    expect(decide("voice-call", "L2").ok).toBe(true);
  });

  it("lets callers change the unknown-class fail-safe tier", () => {
    const decide = createCeremonyPolicy({ unknownClassTier: "L3" });
    expect(decide("mystery", "L2").ok).toBe(false);
    expect(decide("mystery", "L3").ok).toBe(true);
  });
});

describe("CeremonyPolicy — shape", () => {
  it("exposes requiredTier + actualTier on every decision", () => {
    const decide = createCeremonyPolicy();
    const d = decide("spend", "L1");
    expect(d.requiredTier).toBe("L2");
    expect(d.actualTier).toBe("L1");
    expect(d.ok).toBe(false);
    expect(d.reason).toMatch(/requires L2/);
  });

  it("exports a readable default map", () => {
    expect(DEFAULT_POLICY.read).toBe("L0");
    expect(DEFAULT_POLICY.admin).toBe("L3");
  });
});
