import path from "node:path";
import { readFile, writeFile } from "node:fs/promises";
import { canonicalize, parseCanonicalJson } from "./canonicalize.mjs";
import { privateKeyForRole } from "./crypto.mjs";
import { unprotectSecretBundle } from "./keystore.mjs";
import { SomaError } from "./errors.mjs";
import { RECEIPT_SCHEMA, createReceipt, verifyReceipt } from "./receipt.mjs";

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function secondPrecision(value) {
  return `${new Date(value).toISOString().slice(0, 19)}Z`;
}

async function loadSecretBundle(home) {
  const config = JSON.parse(await readFile(path.join(home, "config", "config.json"), "utf8"));
  return unprotectSecretBundle(config.keystore.backend, await readFile(path.join(home, "config", "keystore.blob")));
}

function eraseSecretBundle(bundle) {
  if (!bundle) return;
  for (const key of bundle.private_keys || []) key.private_key_pkcs8_base64 = "";
  if (Array.isArray(bundle.private_keys)) bundle.private_keys.length = 0;
  bundle.root_store_key_base64 = "";
}

/**
 * Issue a receipt attesting to another agent's work.
 *
 * The attester is always this home's own agent identity, taken from local state
 * rather than from the request. An attester field that could be supplied would
 * let a caller issue receipts in someone else's name, which the verifier would
 * then reject — confusing at best, and at worst an invitation to try.
 */
export async function issueReceipt(home, requestFile, outputFile) {
  if (!path.isAbsolute(requestFile)) throw new SomaError("--input must be an absolute path", 2, "RECEIPT_INPUT_PATH_RELATIVE");
  if (!path.isAbsolute(outputFile)) throw new SomaError("--out must be an absolute path", 2, "RECEIPT_OUTPUT_PATH_RELATIVE");

  const request = parseCanonicalJson(await readFile(requestFile, "utf8"), "receipt request");
  const identity = JSON.parse(await readFile(path.join(home, "identity", "identity.json"), "utf8"));

  const expected = ["basis", "capability", "claim_hash", "domain", "fault", "observed_at", "outcome", "schema_version", "subject_did", "task_id"];
  const present = Object.keys(request).sort();
  if (present.length !== expected.length || present.some((key, index) => key !== expected[index])) {
    throw new SomaError(`receipt request must carry exactly [${expected.join(", ")}]`, 2, "RECEIPT_REQUEST_SHAPE_INVALID");
  }
  if (request.schema_version !== RECEIPT_SCHEMA) {
    throw new SomaError("receipt request schema version is unsupported", 2, "RECEIPT_REQUEST_VERSION_UNSUPPORTED");
  }

  const issuedAt = secondPrecision(Date.now());
  const observedAt = ISO.test(request.observed_at) ? request.observed_at : secondPrecision(request.observed_at);

  let bundle = null;
  let receipt;
  try {
    bundle = await loadSecretBundle(home);
    const agentKey = privateKeyForRole(bundle, "agent_signing");
    receipt = createReceipt(
      {
        attester_did: identity.agent_did,
        basis: request.basis,
        capability: request.capability,
        claim_hash: request.claim_hash,
        domain: request.domain,
        fault: request.fault,
        issued_at: issuedAt,
        observed_at: observedAt,
        outcome: request.outcome,
        schema_version: RECEIPT_SCHEMA,
        subject_did: request.subject_did,
        task_id: request.task_id
      },
      agentKey.private_key_pkcs8_base64
    );
  } finally {
    eraseSecretBundle(bundle);
  }

  await writeFile(outputFile, `${canonicalize(receipt)}\n`, "utf8");

  return {
    local_mutation: false,
    remote_mutation: false,
    receipt_id: receipt.receipt_id,
    attester_did: receipt.attester_did,
    subject_did: receipt.subject_did,
    task_id: receipt.task_id,
    outcome: receipt.outcome,
    fault: receipt.fault,
    basis: receipt.basis,
    out: outputFile,
    truth_claim: "a receipt records that a named party said this, never that it is true"
  };
}

/**
 * Verify a receipt file. The attester's key comes from its DID, never from the
 * caller and never from local state, so this works offline for any attester.
 */
export async function verifyReceiptFile(receiptFile) {
  if (!path.isAbsolute(receiptFile)) throw new SomaError("--input must be an absolute path", 2, "RECEIPT_INPUT_PATH_RELATIVE");
  const receipt = parseCanonicalJson(await readFile(receiptFile, "utf8"), "receipt");
  const verified = verifyReceipt(receipt);
  return {
    local_mutation: false,
    remote_mutation: false,
    receipt_id: verified.receipt_id,
    attester_did: verified.attester_did,
    subject_did: verified.subject_did,
    task_id: verified.task_id,
    outcome: verified.outcome,
    fault: verified.fault,
    basis: verified.basis,
    independence: "unknown_without_lineage",
    truth_claim: "a receipt records that a named party said this, never that it is true"
  };
}
