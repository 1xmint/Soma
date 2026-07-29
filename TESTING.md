# Testing Soma end to end

Everything here runs offline. No network, no account, no server.

## Requirements

Node 22 or later. Nothing else.

```
cd js
npm ci --ignore-scripts
```

## The whole thing at once

```
npm run check
```

Origin lock verification, release integrity, then every suite. On Windows this
takes about twelve minutes, most of it in the controller-rotation concurrency
tests, which spawn a hundred concurrent writers on purpose.

## The trust loop, by hand

This is the property the system exists for: **an agent cannot fake trust
without the evidence being obvious.** Two agents, two keystores, one
attestation.

### 1. Create two agents

```bash
node bin/soma.mjs init --home /tmp/worker --recovery none --json
node bin/soma.mjs init --home /tmp/reviewer --recovery none --json
```

Each prints an `agent_did` of the form `did:key:z…`. That identifier **is** the
public key — nothing has to be trusted to distribute it, and nothing can be
substituted for it.

### 2. The reviewer attests to the worker's task

**Input files must be canonical JSON**, not pretty-printed: object keys sorted,
no insignificant whitespace, one trailing newline. `parseCanonicalJson` rejects
anything else with `JSON_NOT_CANONICAL`, deliberately — a file that can be
spelled two ways hashes two ways, and every identifier here is a hash of exact
bytes.

The examples below are shown indented for reading. Convert before use:

```bash
node -e "import('./src/canonicalize.mjs').then(m=>{
  const v=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
  process.stdout.write(m.canonicalize(v)+'
');
})" pretty.json > canonical.json
```

Write a request naming the worker as the subject:

```json
{
  "capability": "code-review",
  "claim_hash": "<64 hex characters>",
  "domain": "software",
  "observed_at": "2026-07-28T11:00:00Z",
  "outcome": "succeeded",
  "schema_version": "soma.work-receipt.provisional-v1",
  "subject_did": "<the worker's agent_did>",
  "task_id": "task-001"
}
```

Then issue it **from the reviewer's home**:

```bash
node bin/soma.mjs receipt issue \
  --home /tmp/reviewer \
  --input /abs/path/request.json \
  --out /abs/path/receipt.json --json
```

The attester is always the issuing home's own identity. It cannot be supplied,
so nobody can issue receipts in another agent's name.

`outcome` may be `succeeded`, `failed` or `disputed`. A system that can only
record success produces reputation meaningless by construction, because a
missing receipt cannot be told apart from work that went badly.

### 3. Anyone can verify it, with access to neither home

```bash
node bin/soma.mjs receipt verify --input /abs/path/receipt.json --json
```

The attester's key is recovered from the DID, so verification needs no registry
and no network. Note the reported `independence: unknown_without_lineage` — this
implementation has no lineage data and does not pretend to know whether the
attester is unrelated to the subject.

### 4. The worker records evidence citing the receipt

```json
{
  "schema_version": "soma.local-evidence-input.provisional-v1",
  "kind": "execution",
  "task_id": "task-001",
  "capability": "code.review",
  "domain": "software.security",
  "claim_hash": "<the same claim_hash>",
  "artifact_hashes": [],
  "receipts": [ <the full receipt object> ],
  "occurred_at": "2026-07-28T11:30:00.000Z",
  "supersedes": null
}
```

```bash
node bin/soma.mjs evidence record --home /tmp/worker --input /abs/path/evidence.json --json
node bin/soma.mjs evidence verify --home /tmp/worker --json
```

The recorded event carries `assurance:
"self_signed_with_verified_counter_signatures"` instead of
`"self_signed_attribution_only"`.

`receipts` carries whole receipts rather than identifiers, because an identifier
alone cannot be checked against anything.

### 5. Try to cheat

Each of these is refused, and each has a test:

| Attempt | Result |
|---|---|
| Issue a receipt about yourself | `RECEIPT_SELF_ATTESTED` |
| Cite a receipt naming a different subject | `EVIDENCE_RECEIPT_SUBJECT_MISMATCH` |
| Reuse a receipt earned on another task | `EVIDENCE_RECEIPT_TASK_MISMATCH` |
| Reuse one attesting to another claim | `EVIDENCE_RECEIPT_CLAIM_MISMATCH` |
| Alter any field of a receipt | `EVIDENCE_RECEIPT_INVALID` |
| Cite the same receipt twice | `EVIDENCE_RECEIPT_DUPLICATE` |

The task and claim bindings matter most. Without them the cheapest forgery in
the system needs no keys at all: earn one receipt on trivial work, then cite it
on everything.

The automated version of all of this is `test/e2e-trust-loop.test.mjs`, which
also asserts the network trace stayed empty throughout.

## What passing does not mean

A receipt records that **a named party said something**. It never establishes
that the something is true. Signatures prove attribution and integrity, which is
what `truth_claim` says in every artifact this implementation emits.

There is no score, tier or rank anywhere, and there never will be under this
identity model: keypairs are free, so any global aggregate can be inflated by
manufacturing attesters. Reputation is relative to whoever is evaluating.
See `RECEIPT-SPEC.md`.
