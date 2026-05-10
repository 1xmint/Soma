import { describe, it, expect, beforeEach } from "vitest";
import {
  IdentityRecoveryCoordinator,
  InMemoryRecoveryStore,
  type RecoveryStore,
} from "../../src/heart/recovery-coordinator.js";

describe("IdentityRecoveryCoordinator", () => {
  let store: RecoveryStore;
  let coord: IdentityRecoveryCoordinator;
  const DID = "did:key:z6MkFrozenIdentity";
  const T0 = 1_700_000_000_000;

  beforeEach(() => {
    store = new InMemoryRecoveryStore();
    coord = new IdentityRecoveryCoordinator(store, { now: () => T0 });
  });

  // ─── isFrozen ──────────────────────────────────────────────────────────────

  describe("isFrozen", () => {
    it("returns false for nominal identity (no ceremony)", () => {
      expect(coord.isFrozen(DID)).toBe(false);
    });

    it("returns true after freezeIdentity", () => {
      coord.freezeIdentity(DID);
      expect(coord.isFrozen(DID)).toBe(true);
    });

    it("returns true in pending state", () => {
      coord.freezeIdentity(DID);
      coord.initiatePending(DID, "recovery-seed", 72 * 3600_000);
      expect(coord.isFrozen(DID)).toBe(true);
    });

    it("returns true in verifying state", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      expect(coord.isFrozen(DID)).toBe(true);
    });

    it("returns false after completeRecovery (restored → nominal)", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      coord.completeRecovery(DID, { now: T0 + 2 });
      expect(coord.isFrozen(DID)).toBe(false);
    });
  });

  // ─── freezeIdentity ────────────────────────────────────────────────────────

  describe("freezeIdentity", () => {
    it("creates a ceremony in frozen state", () => {
      const result = coord.freezeIdentity(DID, { now: T0 });
      expect(result.ceremonyId).toContain("recovery-");

      const status = coord.getStatus(DID);
      expect(status).not.toBeNull();
      expect(status!.state).toBe("frozen");
      expect(status!.frozenAt).toBe(T0);
      expect(status!.initiatedAt).toBeNull();
      expect(status!.evidenceType).toBeNull();
      expect(status!.timeLockExpiresAt).toBeNull();
    });

    it("throws if identity is already frozen", () => {
      coord.freezeIdentity(DID);
      expect(() => coord.freezeIdentity(DID)).toThrow(/already in recovery/);
    });

    it("throws if identity is in pending state", () => {
      coord.freezeIdentity(DID);
      coord.initiatePending(DID, "recovery-seed", 72 * 3600_000);
      expect(() => coord.freezeIdentity(DID)).toThrow(/already in recovery/);
    });

    it("different identities are independent", () => {
      const DID2 = "did:key:z6MkOtherIdentity";
      coord.freezeIdentity(DID);
      expect(coord.isFrozen(DID)).toBe(true);
      expect(coord.isFrozen(DID2)).toBe(false);
    });
  });

  // ─── getStatus ─────────────────────────────────────────────────────────────

  describe("getStatus", () => {
    it("returns null for nominal identity", () => {
      expect(coord.getStatus(DID)).toBeNull();
    });

    it("returns status for frozen identity", () => {
      coord.freezeIdentity(DID, { now: T0 });
      const status = coord.getStatus(DID)!;
      expect(status.identityDid).toBe(DID);
      expect(status.state).toBe("frozen");
      expect(status.frozenAt).toBe(T0);
    });

    it("reflects pending state after initiation", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "guardian-quorum", 86_400_000, { now: T0 + 1000 });
      const status = coord.getStatus(DID)!;
      expect(status.state).toBe("pending");
      expect(status.evidenceType).toBe("guardian-quorum");
      expect(status.initiatedAt).toBe(T0 + 1000);
      expect(status.timeLockExpiresAt).toBe(T0 + 1000 + 86_400_000);
    });
  });

  // ─── initiatePending ───────────────────────────────────────────────────────

  describe("initiatePending", () => {
    it("transitions frozen → pending with time-lock", () => {
      coord.freezeIdentity(DID, { now: T0 });
      const ceremony = coord.initiatePending(DID, "recovery-seed", 72 * 3600_000, { now: T0 + 100 });
      expect(ceremony.state).toBe("pending");
      expect(ceremony.evidenceType).toBe("recovery-seed");
      expect(ceremony.timeLockExpiresAt).toBe(T0 + 100 + 72 * 3600_000);
    });

    it("throws if identity is not frozen", () => {
      expect(() => coord.initiatePending(DID, "recovery-seed", 0)).toThrow(/not frozen/);
    });

    it("throws if identity is already pending", () => {
      coord.freezeIdentity(DID);
      coord.initiatePending(DID, "recovery-seed", 0);
      expect(() => coord.initiatePending(DID, "recovery-seed", 0)).toThrow(/expected 'frozen'/);
    });
  });

  // ─── cancelRecovery ────────────────────────────────────────────────────────

  describe("cancelRecovery", () => {
    it("reverts pending → frozen", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 72 * 3600_000, { now: T0 });
      const cancelled = coord.cancelRecovery(DID, { now: T0 + 1000 });
      expect(cancelled).toBe(true);

      const status = coord.getStatus(DID)!;
      expect(status.state).toBe("frozen");
      expect(status.cancelledAt).toBe(T0 + 1000);
      expect(status.initiatedAt).toBeNull();
      expect(status.evidenceType).toBeNull();
      expect(status.timeLockExpiresAt).toBeNull();
    });

    it("returns false for frozen (not pending) identity", () => {
      coord.freezeIdentity(DID);
      expect(coord.cancelRecovery(DID)).toBe(false);
    });

    it("returns false for nominal identity", () => {
      expect(coord.cancelRecovery(DID)).toBe(false);
    });

    it("identity remains frozen after cancellation (no arbitrary unfreeze)", () => {
      coord.freezeIdentity(DID);
      coord.initiatePending(DID, "recovery-seed", 0);
      coord.cancelRecovery(DID);
      expect(coord.isFrozen(DID)).toBe(true);
      expect(coord.getStatus(DID)!.state).toBe("frozen");
    });
  });

  // ─── advanceToVerifying ────────────────────────────────────────────────────

  describe("advanceToVerifying", () => {
    it("transitions pending → verifying after time-lock expires", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 1000, { now: T0 });
      const ceremony = coord.advanceToVerifying(DID, { now: T0 + 1001 });
      expect(ceremony.state).toBe("verifying");
    });

    it("throws if time-lock has not expired", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 10_000, { now: T0 });
      expect(() => coord.advanceToVerifying(DID, { now: T0 + 5000 })).toThrow(/time-lock has not expired/);
    });

    it("throws if not in pending state", () => {
      coord.freezeIdentity(DID);
      expect(() => coord.advanceToVerifying(DID)).toThrow(/expected 'pending'/);
    });

    it("throws if no ceremony exists", () => {
      expect(() => coord.advanceToVerifying(DID)).toThrow(/no active recovery/);
    });
  });

  // ─── completeRecovery ──────────────────────────────────────────────────────

  describe("completeRecovery", () => {
    it("transitions verifying → nominal (deletes ceremony)", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      const snapshot = coord.completeRecovery(DID, { now: T0 + 2 });

      expect(snapshot.completedAt).toBe(T0 + 2);
      expect(snapshot.state).toBe("verifying");
      expect(coord.isFrozen(DID)).toBe(false);
      expect(coord.getStatus(DID)).toBeNull();
    });

    it("throws if not in verifying state", () => {
      coord.freezeIdentity(DID);
      expect(() => coord.completeRecovery(DID)).toThrow(/expected 'verifying'/);
    });

    it("throws if identity is pending (must go through verifying first)", () => {
      coord.freezeIdentity(DID);
      coord.initiatePending(DID, "recovery-seed", 0);
      expect(() => coord.completeRecovery(DID)).toThrow(/expected 'verifying'/);
    });
  });

  // ─── No Arbitrary Unfreeze ─────────────────────────────────────────────────

  describe("no arbitrary unfreeze", () => {
    it("cannot escape frozen without going through the full ceremony", () => {
      coord.freezeIdentity(DID, { now: T0 });
      expect(coord.isFrozen(DID)).toBe(true);

      // Cancel doesn't work on frozen (only pending)
      expect(coord.cancelRecovery(DID)).toBe(false);
      expect(coord.isFrozen(DID)).toBe(true);

      // Can't advance to verifying from frozen
      expect(() => coord.advanceToVerifying(DID)).toThrow();
      expect(coord.isFrozen(DID)).toBe(true);

      // Can't complete from frozen
      expect(() => coord.completeRecovery(DID)).toThrow();
      expect(coord.isFrozen(DID)).toBe(true);
    });

    it("only path out: frozen → pending → verifying → completeRecovery", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      coord.completeRecovery(DID, { now: T0 + 2 });
      expect(coord.isFrozen(DID)).toBe(false);
    });
  });

  // ─── Full Lifecycle Round-trip ─────────────────────────────────────────────

  describe("full lifecycle", () => {
    it("freeze → pending → cancel → pending again → verify → complete", () => {
      coord.freezeIdentity(DID, { now: T0 });

      // First recovery attempt — cancelled
      coord.initiatePending(DID, "recovery-seed", 1000, { now: T0 + 100 });
      coord.cancelRecovery(DID, { now: T0 + 200 });
      expect(coord.getStatus(DID)!.state).toBe("frozen");

      // Second recovery attempt — succeeds
      coord.initiatePending(DID, "guardian-quorum", 500, { now: T0 + 300 });
      expect(coord.getStatus(DID)!.evidenceType).toBe("guardian-quorum");

      coord.advanceToVerifying(DID, { now: T0 + 801 });
      const snapshot = coord.completeRecovery(DID, { now: T0 + 900 });

      expect(snapshot.completedAt).toBe(T0 + 900);
      expect(coord.isFrozen(DID)).toBe(false);
    });

    it("can freeze the same identity again after recovery completes", () => {
      coord.freezeIdentity(DID, { now: T0 });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      coord.completeRecovery(DID, { now: T0 + 2 });

      // Re-freeze should work — identity is nominal again
      const result = coord.freezeIdentity(DID, { now: T0 + 100 });
      expect(result.ceremonyId).toContain("recovery-");
      expect(coord.isFrozen(DID)).toBe(true);
    });
  });

  // ─── Persistence Seam ──────────────────────────────────────────────────────

  describe("persistence seam", () => {
    it("InMemoryRecoveryStore implements RecoveryStore correctly", () => {
      const s = new InMemoryRecoveryStore();
      expect(s.get("nonexistent")).toBeUndefined();

      s.put({
        id: "test",
        identityDid: DID,
        state: "frozen",
        frozenAt: T0,
        frozenAccountIds: [],
        initiatedAt: null,
        evidenceType: null,
        timeLockExpiresAt: null,
        cancelledAt: null,
        completedAt: null,
      });

      expect(s.get(DID)!.id).toBe("test");
      expect(s.delete(DID)).toBe(true);
      expect(s.get(DID)).toBeUndefined();
      expect(s.delete(DID)).toBe(false);
    });

    it("coordinator works with any RecoveryStore implementation", () => {
      // Custom store that wraps an object instead of Map
      const backing: Record<string, any> = {};
      const customStore: RecoveryStore = {
        get: (did) => backing[did],
        put: (c) => { backing[c.identityDid] = c; },
        delete: (did) => { const had = did in backing; delete backing[did]; return had; },
      };

      const c = new IdentityRecoveryCoordinator(customStore);
      c.freezeIdentity(DID);
      expect(c.isFrozen(DID)).toBe(true);
    });
  });

  // ─── Account-Level Freeze ──────────────────────────────────────────────────

  describe("isAccountFrozen", () => {
    it("returns false when no accounts are frozen", () => {
      expect(coord.isAccountFrozen("acct-1")).toBe(false);
    });

    it("returns true for accounts associated with a frozen identity", () => {
      coord.freezeIdentity(DID, { now: T0, accountIds: ["acct-1", "acct-2"] });
      expect(coord.isAccountFrozen("acct-1")).toBe(true);
      expect(coord.isAccountFrozen("acct-2")).toBe(true);
      expect(coord.isAccountFrozen("acct-3")).toBe(false);
    });

    it("returns false after recovery completes", () => {
      coord.freezeIdentity(DID, { now: T0, accountIds: ["acct-1"] });
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      coord.completeRecovery(DID, { now: T0 + 2 });
      expect(coord.isAccountFrozen("acct-1")).toBe(false);
    });

    it("remains true through pending and verifying states", () => {
      coord.freezeIdentity(DID, { now: T0, accountIds: ["acct-1"] });
      expect(coord.isAccountFrozen("acct-1")).toBe(true);

      coord.initiatePending(DID, "recovery-seed", 1000, { now: T0 });
      expect(coord.isAccountFrozen("acct-1")).toBe(true);

      // Cancel → still frozen
      coord.cancelRecovery(DID, { now: T0 + 100 });
      expect(coord.isAccountFrozen("acct-1")).toBe(true);

      // Re-initiate → verify → still frozen
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 + 200 });
      coord.advanceToVerifying(DID, { now: T0 + 201 });
      expect(coord.isAccountFrozen("acct-1")).toBe(true);
    });

    it("tracks accounts across multiple frozen identities", () => {
      const DID2 = "did:key:z6MkOtherIdentity";
      coord.freezeIdentity(DID, { now: T0, accountIds: ["acct-1"] });
      coord.freezeIdentity(DID2, { now: T0, accountIds: ["acct-2"] });

      expect(coord.isAccountFrozen("acct-1")).toBe(true);
      expect(coord.isAccountFrozen("acct-2")).toBe(true);

      // Complete recovery for DID only
      coord.initiatePending(DID, "recovery-seed", 0, { now: T0 });
      coord.advanceToVerifying(DID, { now: T0 + 1 });
      coord.completeRecovery(DID, { now: T0 + 2 });

      expect(coord.isAccountFrozen("acct-1")).toBe(false);
      expect(coord.isAccountFrozen("acct-2")).toBe(true);
    });
  });
});
