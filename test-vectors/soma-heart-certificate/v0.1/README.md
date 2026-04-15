# Soma Heart Certificate v0.1 Test Vectors

This directory contains the Gate 5 vector corpus required by `SOMA-HEART-CERTIFICATE-SPEC.md` section 19.2.

- `manifest.json` is the normative vector file for v0.1.
- Vectors are authored against the canonical JSON rules in spec sections 9.2-9.5.
- `canonical_json` is the expected UTF-8 canonical byte output rendered as text. `canonical_utf8_hex` is the same byte output rendered as lowercase hex.
- `expected_certificate_id` is `lowercase_hex(sha256("soma-heart-certificate:v0.1:" || canonical_bytes))`.
- `signature_inputs[].input_sha256` hashes the role-prefixed signing input for each included signature.

The corpus is docs/test-vector material only. It does not define a package API, runtime verifier, ClawNet behaviour, pricing policy, routing, staking, token utility, or credential-rotation semantic change.
