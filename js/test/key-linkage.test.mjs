import test from "node:test";
import assert from "node:assert/strict";
import { createInitialKeyMaterial, privateKeyForRole } from "../src/crypto.mjs";
import {
  createKeyLinkage,
  didOfKeyId,
  sameParty,
  verifyKeyLinkage
} from "../src/key-linkage.mjs";

const CREATED_AT = "2026-07-28T00:00:00Z";

function party() {
  const material = createInitialKeyMaterial(CREATED_AT);
  const key = (role) => material.publicIdentity.keys.find((k) => k.role === role);
  const priv = (role) => privateKeyForRole(material.secretBundle, role).private_key_pkcs8_base64;
  return {
    controllerKeyId: key("controller_signing").key_id,
    controllerPrivate: priv("controller_signing"),
    agentKeyId: key("agent_signing").key_id,
    agentPrivate: priv("agent_signing"),
    observerKeyId: key("observer_signing").key_id,
    observerPrivate: priv("observer_signing")
  };
}

const linkageFor = (who, a = "controller", b = "agent") =>
  createKeyLinkage({
    keyIdA: who[`${a}KeyId`],
    privateKeyA: who[`${a}Private`],
    keyIdB: who[`${b}KeyId`],
    privateKeyB: who[`${b}Private`]
  });

test("a mutually signed linkage verifies", () => {
  const p = party();
  const verified = verifyKeyLinkage(linkageFor(p));
  assert.equal(verified.key_ids.length, 2);
  assert.deepEqual(verified.dids.sort(), verified.key_ids.map(didOfKeyId).sort());
});

test("the same pair yields the same identifier whichever order it is built in", () => {
  // Otherwise one relationship has two identifiers, and an evaluator counting
  // distinct linkages can be shown two where there is one.
  const p = party();
  assert.equal(linkageFor(p, "controller", "agent").linkage_id, linkageFor(p, "agent", "controller").linkage_id);
});

test("one key cannot claim another party's key on its own", () => {
  // The land-grab attack, and the reason the record is mutual: if a one-way
  // statement counted, anyone could point at a stranger's agent and either
  // inherit its standing or attach their own misbehaviour to it.
  const attacker = party();
  const victim = party();
  const forged = createKeyLinkage({
    keyIdA: attacker.controllerKeyId,
    privateKeyA: attacker.controllerPrivate,
    // The attacker does not hold this private key, so it signs with its own.
    keyIdB: victim.agentKeyId,
    privateKeyB: attacker.controllerPrivate
  });
  assert.throws(() => verifyKeyLinkage(forged), /signature does not verify/);
});

test("two signatures from one key are not two signatures", () => {
  const p = party();
  const genuine = linkageFor(p);
  const doubled = {
    ...genuine,
    signatures: [genuine.signatures[0], { ...genuine.signatures[0] }]
  };
  assert.throws(() => verifyKeyLinkage(doubled), /signature from each/);
});

test("a half-signed linkage is refused outright, not treated as weaker", () => {
  const p = party();
  const genuine = linkageFor(p);
  const half = { ...genuine, signatures: [genuine.signatures[0]] };
  assert.throws(() => verifyKeyLinkage(half), /signature from each/);
});

test("swapping in a different key breaks the identifier", () => {
  const p = party();
  const other = party();
  const genuine = linkageFor(p);
  const tampered = { ...genuine, key_ids: [genuine.key_ids[0], other.agentKeyId].sort() };
  assert.throws(() => verifyKeyLinkage(tampered), /does not match its contents|does not verify/);
});

test("a key cannot be linked to itself", () => {
  const p = party();
  assert.throws(
    () =>
      createKeyLinkage({
        keyIdA: p.agentKeyId,
        privateKeyA: p.agentPrivate,
        keyIdB: p.agentKeyId,
        privateKeyB: p.agentPrivate
      }),
    /cannot be linked to itself/
  );
});

test("linkage is transitive across a party's several keys", () => {
  // controller <-> agent and agent <-> observer means controller and observer
  // are one party. Every hop still required both private keys.
  const p = party();
  const linkages = [linkageFor(p, "controller", "agent"), linkageFor(p, "agent", "observer")];
  assert.ok(
    sameParty(didOfKeyId(p.controllerKeyId), didOfKeyId(p.observerKeyId), linkages),
    "a chain of mutual assertions should join the ends"
  );
});

test("two strangers are not made one party by holding linkages of their own", () => {
  const a = party();
  const b = party();
  const linkages = [linkageFor(a), linkageFor(b)];
  assert.equal(sameParty(didOfKeyId(a.agentKeyId), didOfKeyId(b.agentKeyId), linkages), false);
});

test("sameParty re-verifies every linkage it is handed", () => {
  const attacker = party();
  const victim = party();
  const forged = createKeyLinkage({
    keyIdA: attacker.controllerKeyId,
    privateKeyA: attacker.controllerPrivate,
    keyIdB: victim.agentKeyId,
    privateKeyB: attacker.controllerPrivate
  });
  assert.throws(
    () => sameParty(didOfKeyId(attacker.controllerKeyId), didOfKeyId(victim.agentKeyId), [forged]),
    /signature does not verify/
  );
});

test("the record claims nothing about the world, and says so", () => {
  const verified = verifyKeyLinkage(linkageFor(party()));
  assert.match(verified.truth_claim, /establishes no interval/);
});
