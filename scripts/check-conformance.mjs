// Run the stable core first; it also loads the shared Soma/Vera wire checks.
await import("./check-conformance-core.mjs");

// Recovery/Phoenix authority, state-availability, death-policy, and adversarial checks.
await import("./lib/recovery-conformance.mjs");

// Exact noncircular recovery identifiers and signature-message projections.
await import("./lib/recovery-domain-conformance.mjs");

// Closed ordinary Soma controller-key rotation and adversarial lifecycle checks.
await import("./lib/controller-key-rotation-conformance.mjs");

// Closed ordinary Vera host descriptor succession and adversarial rotation checks.
await import("./lib/host-succession-conformance.mjs");

// Controller-signed inert pin-replacement confirmation and authority-exclusion checks.
await import("./lib/host-confirmation-conformance.mjs");

// Complete signed portable host-trust bytes with explicit non-anchor and non-restore authority.
await import("./lib/host-trust-capsule-conformance.mjs");

// Controller-history-capable portable host-trust bytes anchored to an independently expected initial key.
await import("./lib/host-trust-capsule-v2-conformance.mjs");

// Standards-complete JSON Schema 2020-12 validation for every schema/example pair.
await import("./lib/full-schema-conformance.mjs");

// Parse every Markdown fence labelled JSON so documentation examples cannot silently rot.
await import("./lib/document-json-conformance.mjs");
