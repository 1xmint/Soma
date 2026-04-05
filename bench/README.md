# soma-heart benchmarks

Microbenchmarks for every major primitive. No framework — just
`process.hrtime.bigint()` with warmup, automatic calibration, and
median/p95/mean reporting.

```bash
pnpm bench              # run the full suite
pnpm tsx bench/index.ts # same thing
```

Each row reports:
- **median** — typical time per op (headline number)
- **p95** — 95th-percentile time (tail latency)
- **mean** — arithmetic mean (can be GC-skewed)
- **ops** — derived from median (ops/sec)

## What's measured

| Suite | Cases |
|-------|-------|
| Crypto primitives | sha256, ed25519 keygen/sign/verify, random |
| Delegation | create, create-heavy, verify, attenuate |
| Proof-of-possession | issueChallenge, proveChallenge, verifyProof |
| Revocation | create, verify, registry add/isRevoked |
| Key rotation (KERI) | incept, rotate, verifyChain |
| Spend receipts | append, signSpendHead, verifySpendHead, verify (10) |
| Mutual session | initiate, accept, confirm, verify |
| Threshold signing | keygen 3/5, sign 3/5, verify |
| Selective disclosure | createDoc, createProof, verifyProof |

## How to read the numbers

On modern hardware most signing/verify ops are in the tens of microseconds.
Hash-only operations land around 1–10µs. Anything labelled "verify" is
dominated by Ed25519 verification, which is the most expensive crypto
primitive here.

The calibration step runs the body enough times to reach ~50µs per sample,
so fast operations are batched automatically. Reported times are always
per-op (divided out).

## Stability

Results are machine- and load-dependent. Compare numbers from the same
machine, same load, same Node version. A 10% swing between runs is normal.

## A note on Ed25519 backend

The default crypto provider uses **tweetnacl** — pure-JS Ed25519. It's
zero-dependency and audited but ~10–20× slower than native libsodium or
noble-ed25519's native-bindings path. Expect Ed25519 sign ≈ 1–4ms and
verify ≈ 2–7ms on tweetnacl; swapping in a libsodium-backed provider
(via crypto-provider.ts) brings those under 100µs.

Everything above the signing floor (delegation, PoP, revocation, etc.)
is dominated by 1–3 signature ops, so the entire stack scales with the
underlying Ed25519 backend.
