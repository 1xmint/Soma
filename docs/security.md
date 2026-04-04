# Soma Security Model

## Security Model — Non-Negotiable Rules

These rules are the immune system. If you're writing code that violates any of them, STOP and redesign.

### Rule 1: Soma Is the Heart, Not a Wrapper
Soma is not middleware that sits beside the agent. Soma IS the execution pathway. The agent cannot compute without Soma. Every model call, tool call, and data retrieval passes through Soma. This is not optional — Soma manages the credentials and connections that make computation possible.

### Rule 2: Soma Never Speaks
There is NO message in the protocol that says "I am Soma" or "send me your data for verification." There is NO verification endpoint. The sensorium is a sense organ, not an entity. Genome commitments are exchanged via extensible metadata fields in the standard MCP handshake. If your design has a "Soma service" that agents talk to, you've already failed.

### Rule 3: All Observation Inside Encrypted Channels
The DID-authenticated encrypted channel (X25519 + NaCl secretbox) ensures the token stream only exists between the two communicating parties. Phenotype observation happens AFTER decryption, INSIDE the observer's own process. A MITM sees only ciphertext. There is nothing to intercept.

### Rule 4: The Sensorium Runs Locally
Inside the observer's own process. No central server. No data leaves your machine unless you explicitly opt in. The sensorium is your immune system — part of YOUR body, not a doctor you visit.

### Rule 5: Identity Is a Distribution, Not a Snapshot
An agent behaves differently on different tasks. That's not noise — the pattern of variation IS the identity. The sensorium builds a behavioral landscape over time. Gradual change = healthy development. Sudden unexplained change = suspicious. Announced change (genome mutation) = tracked continuity.

### Rule 6: Every Token Is Cryptographically Authenticated
Every token emitted by the heart carries an HMAC computed from the session key. The receiver verifies each HMAC individually. A single invalid HMAC means the token did not pass through this heart — immediate RED verdict. This is not statistical verification. It is cryptographic proof, per token, that the output was generated through the legitimate heart with the correct session binding. The dynamic seed mechanism provides an independent behavioral verification layer on top.

### Rule 7: Must be crypto-agile

---

## Deployment Model: Trusted Execution Environments

The heart's credential isolation is software-enforced in the default implementation. For adversarial operator threat models — where the operator themselves is the attacker — the heart is designed to run inside a Trusted Execution Environment (TEE).

**Why this matters:** In a standard Node.js process, a malicious operator with root access can inspect heap memory, monkey-patch the module loader, or use --inspect to extract private fields. The credential vault prevents accidental leakage and external attacks, but cannot prevent the machine owner from reading their own memory. No software can — that's a physical reality.

**TEEs solve this at the hardware level:**

- **AWS Nitro Enclaves:** The heart runs in an isolated VM with no persistent storage, no external networking, and no operator access. Credentials are sealed at enclave creation. The operator can send requests to the heart but cannot inspect its memory.
- **Intel SGX:** The heart runs in an encrypted memory enclave. Even the OS kernel cannot read enclave memory. Attestation proves the heart code is running unmodified.
- **ARM TrustZone:** Hardware-isolated secure world for credential storage and HMAC computation.
- **Azure Confidential Computing / GCP Confidential VMs:** Cloud-managed TEEs with attestation APIs.

The architecture already supports this. The heart's design — all credentials encapsulated with no public getters, all computation routed through generate/callTool/fetchData — maps directly to TEE attestation. The TEE proves the heart code is running unmodified. The heart code proves credentials are never exposed. Together: hardware-enforced credential isolation.

**Deployment tiers:**

- **Tier 1 (default):** Software-enforced. Protects against external attackers and lazy circumvention. Sufficient for most use cases.
- **Tier 2 (TEE):** Hardware-enforced. Protects against adversarial operators. Required for high-value agent commerce where the operator is not trusted.

The genome commitment includes a `deploymentTier` field so the observer's sensorium knows what level of isolation to expect. A Tier 2 claim can be verified through TEE attestation — the enclave produces a cryptographic proof that the heart is running inside the TEE.
