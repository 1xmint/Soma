import { canonicalize } from "./canonicalize.mjs";
import { sha256, verifyEd25519 } from "./crypto.mjs";
import { SomaError } from "./errors.mjs";
import { controllerSigningKeyAt } from "./controller-rotation.mjs";

export const CONFIRMATION_SUBJECT_DOMAIN = "somavera:soma-host-succession-confirmation-subject:v1\n";
export const CONFIRMATION_ID_DOMAIN = "somavera:soma-host-succession-confirmation:v1\n";
export const CONFIRMATION_SIGNATURE_DOMAIN = "somavera:soma-host-succession-confirmation-signature:v1\n";
export const CONFIRMATION_DECISION = "replace_inert_pin_only";

const same = (left, right) => canonicalize(left) === canonicalize(right);
const keyById = (keys, id) => keys.find((key) => key.key_id === id);

export function confirmationSubjectCore(value) {
  return {
    network_lineage_id: value.network_lineage_id,
    execution_context_id: value.execution_context_id,
    host_did: value.host_did,
    origin: value.origin,
    prior_descriptor_id: value.prior_descriptor_id,
    prior_descriptor_sequence: value.prior_descriptor_sequence,
    successor_descriptor_id: value.successor_descriptor_id,
    successor_descriptor_sequence: value.successor_descriptor_sequence,
    succession_id: value.succession_id,
    change_scope: value.change_scope,
    successor_active_host_signing_key_id: value.successor_active_host_signing_key_id,
    successor_active_host_signing_key_sha256: value.successor_active_host_signing_key_sha256,
    successor_active_ingestion_key_id: value.successor_active_ingestion_key_id,
    successor_active_ingestion_key_sha256: value.successor_active_ingestion_key_sha256
  };
}

export function confirmationCore(value) {
  const { $schema, confirmation_id, signature, ...core } = value;
  return core;
}

export const deriveConfirmationSubjectId = (value) => sha256(Buffer.from(CONFIRMATION_SUBJECT_DOMAIN + canonicalize(confirmationSubjectCore(value))));
export const deriveConfirmationId = (value) => sha256(Buffer.from(CONFIRMATION_ID_DOMAIN + canonicalize(confirmationCore(value))));

export function successionSubject(prior, successor, proof) {
  const signing = keyById(successor.host_signing_keys || [], successor.active_host_signing_key_id);
  const ingestion = keyById(successor.ingestion_encryption_keys || [], successor.active_ingestion_key_id);
  if (!signing || !ingestion) throw new SomaError("successor active keys are unavailable", 8, "CONFIRMATION_SUCCESSOR_KEYS_INVALID");
  const subject = {
    network_lineage_id: proof.network_lineage_id,
    execution_context_id: proof.execution_context_id,
    host_did: proof.host_did,
    origin: proof.origin,
    prior_descriptor_id: prior.descriptor_id,
    prior_descriptor_sequence: prior.descriptor_sequence,
    successor_descriptor_id: successor.descriptor_id,
    successor_descriptor_sequence: successor.descriptor_sequence,
    succession_id: proof.succession_id,
    change_scope: proof.change_scope,
    successor_active_host_signing_key_id: successor.active_host_signing_key_id,
    successor_active_host_signing_key_sha256: sha256(Buffer.from(signing.public_key_base64, "base64")),
    successor_active_ingestion_key_id: successor.active_ingestion_key_id,
    successor_active_ingestion_key_sha256: sha256(Buffer.from(ingestion.public_key_base64, "base64"))
  };
  return { ...subject, subject_id: deriveConfirmationSubjectId(subject) };
}

export function validateHostSuccessionConfirmation(confirmation, prior, successor, proof, identity, { validationTime = Date.now() } = {}) {
  const errors = [];
  const subject = successionSubject(prior, successor, proof);
  for (const [field, expected] of Object.entries(confirmationSubjectCore(subject))) if (!same(confirmation[field], expected)) errors.push(`CONFIRMATION_BINDING_MISMATCH:${field}`);
  const controller = controllerSigningKeyAt(identity, confirmation.controller_signing_key_id, Date.parse(confirmation.confirmed_at));
  if (confirmation.controller_did !== identity.controller_did || !controller) errors.push("CONFIRMATION_CONTROLLER_MISMATCH");
  const issued = Date.parse(proof.issued_at), expires = Date.parse(proof.expires_at), confirmed = Date.parse(confirmation.confirmed_at);
  if (!(issued <= confirmed && confirmed <= expires) || !(issued <= validationTime && validationTime <= expires)) errors.push("CONFIRMATION_TIME_INVALID");
  if (confirmation.decision !== CONFIRMATION_DECISION) errors.push("CONFIRMATION_DECISION_INVALID");
  const authority = confirmation.authority || {};
  if (authority.authorizes_pin_replacement !== true || authority.authorizes_connection !== false || authority.authorizes_consent !== false || authority.authorizes_disclosure !== false || authority.authorizes_send !== false || authority.authorizes_emergency_recovery !== false) errors.push("CONFIRMATION_AUTHORITY_INVALID");
  if (deriveConfirmationSubjectId(confirmation) !== confirmation.subject_id) errors.push("CONFIRMATION_SUBJECT_ID_INVALID");
  if (deriveConfirmationId(confirmation) !== confirmation.confirmation_id) errors.push("CONFIRMATION_ID_INVALID");
  if (!controller || confirmation.signature?.suite !== "Ed25519-v1" || confirmation.signature?.key_id !== confirmation.controller_signing_key_id || !verifyEd25519(controller.public_key_multibase, Buffer.concat([Buffer.from(CONFIRMATION_SIGNATURE_DOMAIN), Buffer.from(confirmation.confirmation_id || "", "hex")]), confirmation.signature?.value || "")) errors.push("CONFIRMATION_SIGNATURE_INVALID");
  const violations = [...new Set(errors)];
  if (violations.length) throw new SomaError("host succession controller confirmation is invalid", 8, "HOST_SUCCESSION_CONFIRMATION_INVALID", { violations });
  return { confirmation_id: confirmation.confirmation_id, subject_id: subject.subject_id, successor_descriptor_id: successor.descriptor_id };
}
