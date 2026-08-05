import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { witnessesOf, depthOf, precedes, currentWeight, referenceCommitment, viewDivergence } from "../src/depth-clock.mjs";

const sha = (s) => createHash("sha256").update(s).digest("hex");

const A = "did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN";
const B = "did:key:z6MktcCgWP6EoLbhR1i4uhwJbs4pS3js5bdJaoxAcyPbGQ8o";
const C = "did:key:z6MkfZ6S4NLNTcRPbeMPuSonrhK7NfCLHFbSbLTLTLTLTLTL";

const h = (n) => String(n).repeat(64).slice(0, 64);

/** A head published by `signer` naming the heads it had seen. */
const head = (hash, signer, refs = []) => ({
  head_hash: hash,
  signer_did: signer,
  observed_head_hashes: refs
});

test("a party cannot age itself: self-references contribute no depth", () => {
  // A publishes a long chain referencing only its own earlier heads. If depth
  // could be self-generated, an adversary would mint arbitrary age offline.
  const corpus = [
    head(h(1), A),
    head(h(2), A, [h(1)]),
    head(h(3), A, [h(2)]),
    head(h(4), A, [h(3)])
  ];
  assert.equal(witnessesOf(h(1), corpus).size, 0);
});

test("depth is spent by others, and counts distinct signers not head count", () => {
  const corpus = [
    head(h(1), A),
    head(h(2), B, [h(1)]),
    head(h(3), B, [h(2)]),   // B publishing more does not buy more depth
    head(h(4), B, [h(3)]),
    head(h(5), C, [h(1)])
  ];
  const witnesses = witnessesOf(h(1), corpus);
  assert.deepEqual([...witnesses].sort(), [B, C].sort());
  assert.equal(witnesses.size, 2, "publishing frequently is free, so it must not buy depth");
});

test("depth is transitive: reaching through an intermediary counts", () => {
  const corpus = [
    head(h(1), A),
    head(h(2), B, [h(1)]),
    head(h(3), C, [h(2)])   // C never saw h(1) directly
  ];
  assert.ok(witnessesOf(h(1), corpus).has(C));
});

test("depth must be counted over an explicit trust set, never globally", () => {
  const corpus = [head(h(1), A), head(h(2), B, [h(1)])];
  // A global count is the inflatable aggregate the identity model rules out,
  // so there is deliberately no default to fall back on.
  assert.throws(() => depthOf(h(1), corpus), /signers the evaluator trusts/);
  assert.throws(() => depthOf(h(1), corpus, new Set()), /signers the evaluator trusts/);
});

test("an untrusted clique generates no depth for an evaluator who trusts none of it", () => {
  // B and C cross-reference enthusiastically. To an evaluator who trusts
  // neither, that activity is invisible -- which is the whole point.
  const corpus = [
    head(h(1), A),
    head(h(2), B, [h(1)]),
    head(h(3), C, [h(2)]),
    head(h(4), B, [h(3)]),
    head(h(5), C, [h(4)])
  ];
  assert.equal(depthOf(h(1), corpus, new Set([A])), 0);
  assert.equal(depthOf(h(1), corpus, new Set([B, C])), 2);
});

test("a large bloc sharing one view buys almost no depth, however many identities it runs", () => {
  // The corporate attack: spin up many identities, have them do real work and
  // reference genuinely. Every identity is real, every reference is honest.
  // Their only shared property is that one operator drives them, so they all
  // see the same thing.
  const target = h(1);
  const corpus = [head(target, A)];
  // Parties the evaluator trusts. Divergence is measured against what THEY
  // signed, because that is the part an adversary cannot invent.
  const anchors = [];
  const anchorHashes = [];
  for (let t = 0; t < 6; t += 1) {
    const did = `did:key:z6Mkanch${String(t).padStart(40, "0")}`;
    anchors.push(did);
    anchorHashes.push(sha(`anchor-${t}`));
    corpus.push(head(sha(`anchor-${t}`), did, [target]));
  }

  const bloc = [];
  for (let i = 0; i < 40; i += 1) {
    const did = `did:key:z6Mkbloc${String(i).padStart(40, "0")}`;
    bloc.push(did);
    // Identical view of anchored reality: one viewpoint behind forty faces.
    corpus.push(head(sha(`bloc-head-${i}`), did, [target].concat(anchorHashes)));
  }

  const trusted = new Set(bloc.concat(anchors));
  const undiscounted = depthOf(target, corpus, trusted, { discountCorrelated: false });
  const discounted = depthOf(target, corpus, trusted);

  assert.equal(undiscounted, 46, "count alone treats one operator as forty separate witnesses");
  assert.ok(discounted < 12, `forty identical viewpoints must collapse, got ${discounted}`);
});

test("genuinely separate observers keep their depth, so the discount is not just a cap", () => {
  // Same size bloc, but each observer has actually seen different things --
  // which is what being on a different network looks like. If the discount
  // punished these too, it would be measuring group size rather than
  // correlation, and would penalise honest participation at scale.
  const target = h(1);
  const corpus = [head(target, A)];
  const independents = [];
  for (let i = 0; i < 40; i += 1) {
    const did = `did:key:z6Mkindep${String(i).padStart(39, "0")}`;
    independents.push(did);
    const own = [target];
    for (let j = 0; j < 6; j += 1) own.push(sha(`observer-${i}-saw-${j}`));
    corpus.push(head(sha(`head-${i}`), did, own));
  }
  const discounted = depthOf(target, corpus, new Set(independents), { discountCorrelated: false });
  assert.ok(discounted > 30, `divergent observers must retain their depth, got ${discounted}`);
});

test("a bloc cannot buy apparent independence with invented references", () => {
  // The attack Josh found: reference sets are claims the adversary writes, so
  // if divergence is measured over raw claims, a random number generator
  // defeats the entire correlation discount for free.
  var target = h(1);
  var anchors = [];
  var corpus = [head(target, A)];
  for (var t = 0; t < 5; t++) {
    var did = "did:key:z6Mkanchor" + String(t).padStart(38, "0");
    anchors.push(did);
    corpus.push(head(sha("anchor-head-" + t), did, [target]));
  }
  var anchorHashes = [];
  for (var t2 = 0; t2 < 5; t2++) anchorHashes.push(sha("anchor-head-" + t2));

  // Twenty identities that genuinely share one view of the anchored heads,
  // each padded with a different pile of invented hashes to look divergent.
  var bloc = [];
  for (var i = 0; i < 20; i++) {
    var did2 = "did:key:z6Mkspoof" + String(i).padStart(39, "0");
    bloc.push(did2);
    var refs = [target].concat(anchorHashes);
    for (var j = 0; j < 30; j++) refs.push(sha("invented-" + i + "-" + j));
    corpus.push(head(sha("spoof-head-" + i), did2, refs));
  }

  var trusted = new Set(bloc.concat(anchors));
  var d = depthOf(target, corpus, trusted);
  // Five real anchors plus twenty identities whose only genuine observations
  // are identical. The invented padding must buy them nothing.
  assert.ok(d < 9, "invented references must not manufacture independence, got " + d);

  // And the measure refuses to run unanchored, rather than silently trusting
  // whatever the adversary wrote.
  assert.throws(function () { viewDivergence(bloc[0], bloc[1], corpus); }, /anchored/);
});

test("precedes proves ordering only when the reference closure shows it", () => {
  const corpus = [
    head(h(1), A),
    head(h(2), B, [h(1)]),
    head(h(3), C)            // concurrent, references nothing
  ];
  assert.equal(precedes(h(1), h(2), corpus), true);
  assert.equal(precedes(h(2), h(1), corpus), false);
  // Unordered must read as false, and false must not be taken as the reverse.
  assert.equal(precedes(h(1), h(3), corpus), false);
  assert.equal(precedes(h(3), h(1), corpus), false);
});

test("standing lapses as depth accrues, which is the point of the exercise", () => {
  const base = [head(h(1), A)];
  const witnessed = [
    head(h(1), A),
    head(h(2), B, [h(1)]),
    head(h(3), C, [h(1)])
  ];
  const fresh = currentWeight({
    evidenceHeadHash: h(1), heads: base, trustedSigners: new Set([B, C]), halfLife: 2
  });
  const stale = currentWeight({
    evidenceHeadHash: h(1), heads: witnessed, trustedSigners: new Set([B, C]), halfLife: 2
  });
  assert.equal(fresh, 1, "evidence with no network movement past it is undiminished");
  assert.ok(stale < fresh, "standing must weaken as the network moves on without fresh evidence");
  assert.ok(Math.abs(stale - 0.5) < 1e-9, "two depth units at half-life two is exactly one halving");
});

test("half-life is required, because no tunable number may be frozen", () => {
  const corpus = [head(h(1), A)];
  const args = { evidenceHeadHash: h(1), heads: corpus, trustedSigners: new Set([B]) };
  assert.throws(() => currentWeight({ ...args }), /halfLife/);
  assert.throws(() => currentWeight({ ...args, halfLife: 0 }), /halfLife/);
  assert.throws(() => currentWeight({ ...args, halfLife: -1 }), /halfLife/);
});

test("a reference commitment is order-independent and rejects malformed hashes", () => {
  // Two parties who saw the same heads must commit identically, or the
  // commitment measures arrival order rather than knowledge.
  assert.equal(
    referenceCommitment([h(1), h(2)]),
    referenceCommitment([h(2), h(1), h(1)])
  );
  assert.throws(() => referenceCommitment([h(1), "NOTHEX"]), /64 lowercase hex/);
  assert.throws(() => referenceCommitment("not-an-array"), /must be an array/);
});

test("a duplicated head hash is refused rather than merged", () => {
  const corpus = [head(h(1), A), head(h(1), B)];
  assert.throws(() => witnessesOf(h(1), corpus), /duplicate head hash/);
});
