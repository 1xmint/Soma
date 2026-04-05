# soma-heart examples

Runnable demos for every major primitive. Each example is a standalone
`tsx` script — no setup beyond `pnpm install`.

```bash
pnpm tsx examples/01-basic-delegation.ts
pnpm tsx examples/02-pop-challenge.ts
pnpm tsx examples/03-revocation.ts
pnpm tsx examples/04-key-rotation.ts
pnpm tsx examples/05-spend-budget.ts
pnpm tsx examples/06-mutual-session.ts
pnpm tsx examples/07-threshold-signing.ts
pnpm tsx examples/08-selective-disclosure.ts
```

Each example prints what it's doing as it runs. Read the source alongside
the output — that's where the protocol flow is explained in plain English.

| # | Example | Primitives |
|---|---------|------------|
| 01 | basic-delegation | delegation, attenuation, caveats |
| 02 | pop-challenge | proof-of-possession |
| 03 | revocation | RevocationRegistry |
| 04 | key-rotation | KERI-style KeyHistory |
| 05 | spend-budget | SpendLog, signed heads, double-spend detection |
| 06 | mutual-session | 3-way authenticated handshake |
| 07 | threshold-signing | 3-of-5 Ed25519 reconstruction |
| 08 | selective-disclosure | salted commitment root |

The attack harness (`tests/attacks/`) shows each primitive under adversary.
The examples here show each primitive in normal, honest use.
