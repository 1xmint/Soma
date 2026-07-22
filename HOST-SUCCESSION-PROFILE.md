# Offline Vera Host Succession Preview

Status: **implemented inert local draft; confirmation, pin replacement, connection, consent, and send are absent**

This slice imports the ordinary Vera Host descriptor-succession contract from
Somavera Origin commit `07a4e89` and capsule root
`ee8bb4f2a851ecd103a84db988e24eb2241ec702c9f0743045a2e83008f89e7d`.
It can verify a successor against one existing controller-signed host pin and
store a controller-signed pending candidate. It performs zero network actions.

## Command

```text
soma host succession-preview --successor ABSOLUTE_DESCRIPTOR.json --proof ABSOLUTE_PROOF.json --home ABSOLUTE_HOME
```

Both inputs must be canonical UTF-8 JSON in local regular files. The command
does not fetch descriptors, follow redirects, contact the host, register
consent, create a session, retry a request, or place work in a queue.

## Required continuity proof

The verifier requires all of the following:

- the successor sequence is exactly prior sequence plus one;
- `previous_descriptor_id` is the recomputed prior descriptor ID;
- host DID, exact HTTPS origin, network lineage, execution context, discovery,
  TLS identity, release, policy, protocols, capabilities, disclosures, regions,
  subprocessors, retention, limits, and rotation policy are unchanged;
- each newly active signing or ingestion key appeared with identical key ID,
  role, suite, and public bytes as a live, bounded `overlap` key in the prior
  descriptor;
- replaced active keys become `retired`, historic keys remain present, and
  their lifecycle fields cannot be rewritten;
- every descriptor ID and active-key signature verifies;
- the proof ID recomputes under the Origin succession domain;
- prior and successor active signing keys verify distinct role-separated proof
  signatures;
- sequence, predecessor, descriptor IDs, active key IDs, exact change scope,
  issue time, expiry, and the no-authority statement all agree; and
- the proof is current, no longer than 900 seconds, and lies inside both
  descriptor validity intervals.

Revocation smuggling, an uncommitted key, multiple active keys, key-role reuse,
an expired overlap, an immutable-field change, a signature replay, or a
descriptor lifetime beyond its committed policy fails closed. Ordinary
succession cannot authorize emergency recovery after total compromise.

## Candidate record

One candidate per host is stored under `hosts/candidates/` using a filename
derived from the host DID. The closed record binds:

- the current controller-signed prior pin ID;
- prior and successor descriptor IDs;
- the complete successor descriptor and succession proof;
- succession ID and change scope;
- the successor active signing-key SHA-256;
- creation time and controller DID;
- `confirmed: false` and `connected: false`; and
- authority `offline_candidate_only_no_pin_replacement_no_connection_no_consent_no_send`.

The controller signs a domain-separated candidate ID. `doctor`, `status`, and
`host status` revalidate the candidate, its controller signature, current prior
pin binding, descriptors, proof, and content-derived storage path. Repeating
the exact preview is idempotent. A different pending candidate for the same
host conflicts instead of replacing it. A candidate whose proof window has
ended is reported `expired_inert`.

## Deliberately absent confirmation transition

This command is not confirmation. It never edits the host pin. The separately
designed confirmation transition must bind the exact candidate ID, display the
complete security-relevant change, require an explicit controller act, update
the expected active-key commitment, replace the pin atomically, retain prior
history, consume the candidate, and still grant no connection or consent.

Until that transition and its crash/race/rollback tests exist, the only usable
pin remains the prior descriptor and every changed descriptor continues to
fail through ordinary `soma host pin`.

## Security limits

- Dual signatures prove controlled continuity, not host honesty or safety.
- A compromised prior key plus compromised precommitted successor key can sign
  a malicious transition; immutable fields and human confirmation reduce but
  cannot erase that risk.
- Local controller signatures do not defeat a device attacker controlling both
  the filesystem and controller key without an independent external anchor.
- Local system time controls validity decisions; authenticated time is absent.
- No emergency recovery authority is implemented.
