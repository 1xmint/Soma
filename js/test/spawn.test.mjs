import test from "node:test";
import assert from "node:assert/strict";
import { spawnCore, spawnId, verifySpawn, lineageOf, sharesLineage,
         childPosition, parentExposure, stakeForfeited } from "../src/spawn.mjs";
import { createInitialKeyMaterial, privateKeyForRole, signEd25519 } from "../src/crypto.mjs";

function newAgent() {
  const material = createInitialKeyMaterial("2026-08-05T00:00:00Z");
  return {
    did: material.publicIdentity.agent_did,
    privateKeyBase64: privateKeyForRole(material.secretBundle, "agent_signing").private_key_pkcs8_base64
  };
}

function signedSpawn(parent, childDid, stake, scope = ["code-review"]) {
  const core = spawnCore({ parentDid: parent.did, childDid: childDid, capabilityScope: scope, stake: stake });
  const id = spawnId(core);
  const preimage = Buffer.concat([
    Buffer.from("somavera:soma-agent-spawn-signature:v1\n", "utf8"),
    Buffer.from(id, "hex")
  ]);
  return { spawn_id: id, ...core,
           signature: { suite: "Ed25519-v1", value: signEd25519(parent.privateKeyBase64, preimage) } };
}

test("the parent signs, and a child cannot manufacture its own backing", () => {
  const parent = newAgent(), child = newAgent();
  const good = signedSpawn(parent, child.did, 0.5);
  assert.equal(verifySpawn(good).parent_did, parent.did);

  // An impostor signs a real record, then rewrites parent_did to claim the
  // parent's backing. This is the attack that matters: helping yourself to
  // somebody else's standing without their key.
  const impostor = newAgent();
  const forged = signedSpawn(impostor, child.did, 0.5);
  forged.parent_did = parent.did;
  delete forged.spawn_id;   // recomputed from contents, so it cannot mask the swap
  assert.throws(() => verifySpawn(forged), /does not verify under the parent's key/);
});

test("an agent cannot spawn itself", () => {
  const a = newAgent();
  assert.throws(() => spawnCore({ parentDid: a.did, childDid: a.did, capabilityScope: ["x"], stake: 0.5 }),
    /cannot spawn itself/);
});

test("THE FORCED CHOICE: declared lineage inherits standing and forfeits independence", () => {
  const parent = newAgent(), backed = newAgent(), unbacked = newAgent();
  const records = [signedSpawn(parent, backed.did, 1.0)].map(verifySpawn);
  const standingOf = (did) => (did === parent.did ? 0.9 : 0);

  const withLineage = childPosition({ childDid: backed.did, spawnRecords: records, standingOf, decay: 0.8 });
  const without = childPosition({ childDid: unbacked.did, spawnRecords: records, standingOf, decay: 0.8 });

  assert.ok(withLineage.inherited > 0, "a declared child inherits something");
  assert.equal(withLineage.independent, false, "and is visibly related to its parent");

  assert.equal(without.inherited, 0, "an undeclared identity inherits nothing");
  assert.equal(without.independent, true, "and is indistinguishable from any stranger");

  // Neither branch gives an operator both. That is the whole mechanism.
  assert.ok(!(withLineage.inherited > 0 && withLineage.independent));
  assert.ok(!(without.inherited > 0 && without.independent === false));
});

test("relatedness is transitive, so a bloc cannot launder itself through generations", () => {
  const g0 = newAgent(), g1 = newAgent(), g2 = newAgent(), stranger = newAgent();
  const records = [signedSpawn(g0, g1.did, 0.5), signedSpawn(g1, g2.did, 0.5)].map(verifySpawn);

  assert.deepEqual(lineageOf(g2.did, records), [g1.did, g0.did]);
  assert.equal(sharesLineage(g2.did, g0.did, records), true, "a grandchild is still related to its grandparent");
  assert.equal(sharesLineage(g2.did, stranger.did, records), false);
});

test("inheritance decays with distance, so depth is not a laundering route", () => {
  const g0 = newAgent(), g1 = newAgent(), g2 = newAgent();
  const records = [signedSpawn(g0, g1.did, 1.0), signedSpawn(g1, g2.did, 1.0)].map(verifySpawn);
  const standingOf = (did) => (did === g0.did || did === g1.did ? 0.9 : 0);

  const near = childPosition({ childDid: g1.did, spawnRecords: records, standingOf, decay: 0.5 });
  const far = childPosition({ childDid: g2.did, spawnRecords: records, standingOf, decay: 0.5 });
  assert.ok(far.inherited < near.inherited, "each generation inherits less than the last");
});

test("a cycle of spawn records terminates instead of hanging a verifier", () => {
  const a = newAgent(), b = newAgent();
  const records = [signedSpawn(a, b.did, 0.5), signedSpawn(b, a.did, 0.5)].map(verifySpawn);
  assert.ok(lineageOf(a.did, records).length <= 2, "a malformed ring must not stall resolution");
});

test("exposure accumulates per child while standing does not, so scale is self-limiting", () => {
  const parent = newAgent();
  const records = [];
  for (var i = 0; i < 20; i++) records.push(verifySpawn(signedSpawn(parent, newAgent().did, 0.25)));

  assert.equal(parentExposure(parent.did, records), 5, "twenty children at 0.25 is five units at risk");
  // The parent's own standing is bounded by 1. Spawning past that stakes more
  // than it has, which is the natural limit -- no arbitrary cap required.
  assert.ok(parentExposure(parent.did, records) > 1);
});

test("only the stake is forfeited, so vouching for nothing costs nothing and lends nothing", () => {
  const parent = newAgent(), staked = newAgent(), unstaked = newAgent();
  const records = [signedSpawn(parent, staked.did, 0.6), signedSpawn(parent, unstaked.did, 0)].map(verifySpawn);

  assert.equal(stakeForfeited(parent.did, [staked.did], records), 0.6);
  assert.equal(stakeForfeited(parent.did, [unstaked.did], records), 0, "a parent that staked nothing loses nothing");

  const standingOf = () => 0.9;
  assert.equal(childPosition({ childDid: unstaked.did, spawnRecords: records, standingOf, decay: 0.9 }).inherited, 0,
    "and correspondingly lent nothing");
});

test("stake and decay are required, because no tunable number may be frozen", () => {
  const a = newAgent(), b = newAgent();
  assert.throws(() => spawnCore({ parentDid: a.did, childDid: b.did, capabilityScope: ["x"] }), /stake/);
  assert.throws(() => spawnCore({ parentDid: a.did, childDid: b.did, capabilityScope: ["x"], stake: 1.5 }), /stake/);
  const records = [verifySpawn(signedSpawn(a, b.did, 0.5))];
  assert.throws(() => childPosition({ childDid: b.did, spawnRecords: records, standingOf: () => 1 }), /decay/);
});

test("an unknown field is rejected rather than ignored", () => {
  const a = newAgent(), b = newAgent();
  const rec = signedSpawn(a, b.did, 0.5);
  assert.ok(verifySpawn(rec), "the record verifies before tampering");
  rec.priority = "high";
  // Ignoring this would let the most permissive implementation become the
  // specification, and would let a field carry meaning no signature covers.
  assert.throws(() => verifySpawn(rec), /unknown field/);
});
