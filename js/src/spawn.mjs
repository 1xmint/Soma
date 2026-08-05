import { canonicalize } from "./canonicalize.mjs";
import { sha256, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { attesterKeyFromDid } from "./receipt.mjs";

/**
 * Earned spawning: creating an agent costs the creator's standing.
 *
 * Identity is free and must stay free -- the identifier is the key, and any
 * gate on creating one is a registry with an owner. So spawning cannot be
 * restricted. What it can be is PRICED.
 *
 * The mechanism is a signed spawn record in which a parent declares a child
 * and puts its own standing behind it. Nothing prevents anyone generating
 * keypairs by the million; what the record changes is what those keypairs are
 * worth.
 *
 * THE FORCED CHOICE
 *
 * This is the property the whole file exists for, and it needs no enforcement
 * because it falls out of trust being unforgeable by its subject:
 *
 *   Declare lineage  -> the child inherits standing, and is VISIBLY RELATED to
 *                       its parent, so the two of them corroborating each other
 *                       is worth almost nothing.
 *
 *   Hide lineage     -> the child looks independent, and starts from ZERO. No
 *                       history, no inheritance, nobody vouching.
 *
 * An operator spawning a million agents must choose per agent, and neither
 * branch gives what the attack needs. Inherited standing and apparent
 * independence are mutually exclusive resources.
 *
 * WHAT THIS IS NOT
 *
 * Not a registry, and not traceable to any source of truth. A spawn record
 * traces to a STAKE, not to an authority: the only thing behind it is a parent
 * risking something it had to earn. Nobody issues it, nobody can withhold it,
 * and an agent with no spawn record at all is perfectly valid -- merely
 * unbacked, which is a different thing from invalid.
 *
 * Not frozen. This is evaluator policy; two evaluators may price spawning
 * differently while every signature still verifies.
 */

const SPAWN_ID_DOMAIN = "somavera:soma-agent-spawn:v1";
const SPAWN_SIGNATURE_DOMAIN = "somavera:soma-agent-spawn-signature:v1";
const SPAWN_SCHEMA = "soma.agent-spawn.provisional-v1";

const CORE_FIELDS = ["capability_scope", "child_did", "parent_did", "schema_version", "stake"];
const SUITES = new Set(["Ed25519-v1"]);

function requireDid(value, field) {
  if (typeof value !== "string" || !value.startsWith("did:key:")) {
    throw new SomaError(`${field} must be a did:key identifier`, 2, "SPAWN_DID_INVALID");
  }
}

/**
 * The bytes a parent signs to bring a child into existence.
 *
 * `stake` is how much of its own standing the parent is putting at risk, as a
 * fraction. It has no default: staking nothing is a coherent choice — it means
 * "this is mine but I do not vouch for it" — and it must be said out loud
 * rather than assumed either way.
 */
export function spawnCore({ parentDid, childDid, capabilityScope, stake }) {
  requireDid(parentDid, "parent_did");
  requireDid(childDid, "child_did");
  if (parentDid === childDid) {
    // Self-spawning would let an identity manufacture its own backing, which
    // is the one thing standing must never permit.
    throw new SomaError("an agent cannot spawn itself", 2, "SPAWN_SELF");
  }
  if (!Array.isArray(capabilityScope) || capabilityScope.length === 0
      || capabilityScope.some((c) => typeof c !== "string" || c.length === 0)) {
    throw new SomaError("capability_scope must be a non-empty array of strings", 2, "SPAWN_SCOPE_INVALID");
  }
  if (typeof stake !== "number" || !Number.isFinite(stake) || stake < 0 || stake > 1) {
    throw new SomaError("stake must be a number between 0 and 1", 2, "SPAWN_STAKE_INVALID");
  }
  const core = {
    capability_scope: [...capabilityScope].sort(),
    child_did: childDid,
    parent_did: parentDid,
    schema_version: SPAWN_SCHEMA,
    stake: stake
  };
  for (const k of Object.keys(core)) {
    if (!CORE_FIELDS.includes(k)) throw new SomaError(`unknown field ${k}`, 2, "SPAWN_UNKNOWN_FIELD");
  }
  return core;
}

export function spawnId(core) {
  return sha256(Buffer.from(`${SPAWN_ID_DOMAIN}\n${canonicalize(core)}`, "utf8"));
}

function signaturePreimage(id) {
  return Buffer.concat([
    Buffer.from(`${SPAWN_SIGNATURE_DOMAIN}\n`, "utf8"),
    Buffer.from(id, "hex")
  ]);
}

/**
 * Verify a spawn record against the key its PARENT identifier commits to.
 *
 * The parent signs, never the child: a child signing its own spawn record
 * would be manufacturing its own backing. The verifying key is derived from
 * the parent's identifier and is never accepted as an argument.
 */
export function verifySpawn(record) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new SomaError("spawn record must be an object", 2, "SPAWN_INVALID");
  }
  const { signature, spawn_id: claimedId, ...core } = record;
  // Rebuilding from named fields would silently drop anything unexpected,
  // which lets the most permissive implementation quietly become the
  // specification. Unknown members are refused, never ignored.
  for (const k of Object.keys(core)) {
    if (!CORE_FIELDS.includes(k)) {
      throw new SomaError(`unknown field ${k}`, 2, "SPAWN_UNKNOWN_FIELD");
    }
  }
  for (const k of CORE_FIELDS) {
    if (!(k in core)) throw new SomaError(`missing field ${k}`, 2, "SPAWN_MISSING_FIELD");
  }
  const recomputed = spawnCore({
    parentDid: core.parent_did,
    childDid: core.child_did,
    capabilityScope: core.capability_scope,
    stake: core.stake
  });
  const id = spawnId(recomputed);
  if (claimedId !== undefined && claimedId !== id) {
    throw new SomaError("spawn_id does not match its contents", 2, "SPAWN_ID_MISMATCH");
  }
  if (!signature || typeof signature !== "object" || !SUITES.has(signature.suite)) {
    throw new SomaError("unsupported or missing signature suite", 2, "SPAWN_SUITE_UNSUPPORTED");
  }
  const key = attesterKeyFromDid(core.parent_did);
  if (!verifyEd25519(key, signaturePreimage(id), signature.value)) {
    throw new SomaError("spawn signature does not verify under the parent's key", 2, "SPAWN_SIGNATURE_INVALID");
  }
  return { spawn_id: id, ...recomputed };
}

/**
 * Ancestors of a child, nearest first.
 *
 * Cycles terminate rather than hang: a ring of mutual spawn records is
 * malformed, not a lineage, and must not be able to stall a verifier.
 */
export function lineageOf(childDid, spawnRecords) {
  const byChild = new Map();
  for (const r of spawnRecords) byChild.set(r.child_did, r);
  const chain = [];
  const seen = new Set([childDid]);
  let cursor = childDid;
  while (byChild.has(cursor)) {
    const rec = byChild.get(cursor);
    if (seen.has(rec.parent_did)) break;
    chain.push(rec.parent_did);
    seen.add(rec.parent_did);
    cursor = rec.parent_did;
  }
  return chain;
}

/** Do two identities share a declared ancestor? */
export function sharesLineage(a, b, spawnRecords) {
  if (a === b) return true;
  const la = new Set([a, ...lineageOf(a, spawnRecords)]);
  for (const anc of [b, ...lineageOf(b, spawnRecords)]) if (la.has(anc)) return true;
  return false;
}

/**
 * The forced choice, computed.
 *
 * Returns what a child actually gets from its position. Declared lineage buys
 * inherited standing and costs independence; declaring nothing buys
 * independence and inherits nothing.
 *
 * `decay` is the fraction of the parent's standing that reaches the child, and
 * has no default — it is somebody's policy, and no tunable number may be
 * frozen.
 */
export function childPosition({ childDid, spawnRecords, standingOf, decay }) {
  if (typeof decay !== "number" || !Number.isFinite(decay) || decay < 0 || decay > 1) {
    throw new SomaError("decay must be a number between 0 and 1", 2, "SPAWN_DECAY_INVALID");
  }
  const ancestors = lineageOf(childDid, spawnRecords);
  if (ancestors.length === 0) {
    // Unbacked. Perfectly valid, entirely independent, and worth nothing yet.
    return { inherited: 0, independent: true, ancestors: [] };
  }
  const record = spawnRecords.find((r) => r.child_did === childDid);
  const parentStanding = standingOf(record.parent_did) ?? 0;
  return {
    // Capped by the stake: a parent that vouched for nothing lends nothing.
    inherited: parentStanding * record.stake * Math.pow(decay, ancestors.length),
    independent: false,
    ancestors: ancestors
  };
}

/**
 * What a parent currently has at risk.
 *
 * Exposure accumulates per child while standing does not, so spawning at scale
 * is self-limiting without any cap — and a cap would be an arbitrary frozen
 * number anyway. This is collateral denominated in reputation, which is the
 * only currency available that has no issuer.
 */
export function parentExposure(parentDid, spawnRecords) {
  return spawnRecords
    .filter((r) => r.parent_did === parentDid)
    .reduce((total, r) => total + r.stake, 0);
}

/**
 * Standing a parent loses when a child it vouched for is judged to have
 * defected. Only the stake is at risk — a parent that staked nothing loses
 * nothing, and has correspondingly lent nothing.
 */
export function stakeForfeited(parentDid, defectedChildDids, spawnRecords) {
  const defected = new Set(defectedChildDids);
  return spawnRecords
    .filter((r) => r.parent_did === parentDid && defected.has(r.child_did))
    .reduce((total, r) => total + r.stake, 0);
}
