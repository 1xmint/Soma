import { createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { SomaError } from "./errors.mjs";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC = Object.freeze({ Ed25519: Buffer.from([0xed, 0x01]), X25519: Buffer.from([0xec, 0x01]) });
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function base58btc(bytes) {
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  let encoded = "";
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = BASE58[remainder] + encoded;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded || "1";
}

function base58btcDecode(value) {
  if (typeof value !== "string" || !value.startsWith("z") || value.length < 2) {
    throw new SomaError("public key multibase is invalid", 7, "PUBLIC_KEY_MULTIBASE_INVALID");
  }
  let number = 0n;
  for (const character of value.slice(1)) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) throw new SomaError("public key multibase is invalid", 7, "PUBLIC_KEY_MULTIBASE_INVALID");
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let zeroes = 0;
  for (const character of value.slice(1)) {
    if (character !== "1") break;
    zeroes += 1;
  }
  if (zeroes) bytes = Buffer.concat([Buffer.alloc(zeroes), bytes]);
  return bytes;
}

function rawPublicKey(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32);
}

function createRole(role, algorithm) {
  const { publicKey, privateKey } = generateKeyPairSync(algorithm.toLowerCase());
  const raw = rawPublicKey(publicKey);
  const fingerprint = `z${base58btc(Buffer.concat([MULTICODEC[algorithm], raw]))}`;
  const did = `did:key:${fingerprint}`;
  return {
    publicRecord: {
      role,
      algorithm: `${algorithm}-v1`,
      did,
      key_id: `${did}#${fingerprint}`,
      public_key_multibase: fingerprint,
      status: "active"
    },
    privateRecord: {
      role,
      key_id: `${did}#${fingerprint}`,
      private_key_pkcs8_base64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")
    }
  };
}

export function createControllerKeyMaterial() {
  return createRole("controller_signing", "Ed25519");
}

export function publicRecordForPrivate(privateRecord, algorithm = "Ed25519") {
  const der = Buffer.from(privateRecord.private_key_pkcs8_base64 || "", "base64");
  try {
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const raw = rawPublicKey(createPublicKey(privateKey));
    const fingerprint = `z${base58btc(Buffer.concat([MULTICODEC[algorithm], raw]))}`;
    const did = `did:key:${fingerprint}`;
    return {
      role: privateRecord.role,
      algorithm: `${algorithm}-v1`,
      did,
      key_id: `${did}#${fingerprint}`,
      public_key_multibase: fingerprint,
      status: "active"
    };
  } catch {
    throw new SomaError("private key material is invalid", 7, "PRIVATE_KEY_INVALID");
  } finally {
    der.fill(0);
  }
}

export function createInitialKeyMaterial(createdAt) {
  const roles = [
    createRole("controller_signing", "Ed25519"),
    createRole("agent_signing", "Ed25519"),
    createRole("observer_signing", "Ed25519"),
    createRole("vera_private_reply_encryption", "X25519")
  ];
  const publicRoles = Object.fromEntries(roles.map((entry) => [entry.publicRecord.role, entry.publicRecord]));
  return {
    publicIdentity: {
      schema_version: "somavera.soma-local-identity.v1",
      created_at: createdAt,
      controller_did: publicRoles.controller_signing.did,
      agent_did: publicRoles.agent_signing.did,
      observer_did: publicRoles.observer_signing.did,
      assurance: "self_controlled_device_key_uncredentialed",
      keys: roles.map((entry) => entry.publicRecord)
    },
    secretBundle: {
      schema_version: "somavera.soma-secret-bundle.v1",
      created_at: createdAt,
      private_keys: roles.map((entry) => entry.privateRecord),
      root_store_key_base64: randomBytes(32).toString("base64")
    }
  };
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function signEd25519(privateKeyBase64, message) {
  const der = Buffer.from(privateKeyBase64, "base64");
  try {
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    return sign(null, Buffer.from(message), privateKey).toString("base64");
  } finally {
    der.fill(0);
  }
}

export function ed25519MultibaseSha256(publicKeyMultibase) {
  const decoded = base58btcDecode(publicKeyMultibase);
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(MULTICODEC.Ed25519)) throw new SomaError("public key is not canonical Ed25519 multibase", 7, "PUBLIC_KEY_MULTIBASE_INVALID");
  return sha256(decoded.subarray(2));
}

export function verifyEd25519(publicKeyMultibase, message, signatureBase64) {
  try {
    const decoded = base58btcDecode(publicKeyMultibase);
    if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(MULTICODEC.Ed25519)) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, decoded.subarray(2)]), format: "der", type: "spki" });
    const signature = Buffer.from(signatureBase64, "base64");
    if (signature.length !== 64 || signature.toString("base64") !== signatureBase64) return false;
    return verify(null, Buffer.from(message), publicKey, signature);
  } catch {
    return false;
  }
}

export function verifyEd25519RawBase64(publicKeyBase64, message, signatureBase64) {
  try {
    const raw = Buffer.from(publicKeyBase64, "base64");
    const signature = Buffer.from(signatureBase64, "base64");
    if (raw.length !== 32 || raw.toString("base64") !== publicKeyBase64 || signature.length !== 64 || signature.toString("base64") !== signatureBase64) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
    return verify(null, Buffer.from(message), publicKey, signature);
  } catch {
    return false;
  }
}

export function validateX25519RawBase64(publicKeyBase64) {
  try {
    const raw = Buffer.from(publicKeyBase64, "base64");
    if (raw.length !== 32 || raw.toString("base64") !== publicKeyBase64) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
    const ephemeral = generateKeyPairSync("x25519");
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey });
    return shared.length === 32 && !shared.equals(Buffer.alloc(32));
  } catch {
    return false;
  }
}

export function privateKeyForRole(secretBundle, role) {
  const record = secretBundle.private_keys?.find((entry) => entry.role === role);
  if (!record || typeof record.private_key_pkcs8_base64 !== "string") {
    throw new SomaError(`keystore lacks required ${role} key`, 7, "SIGNING_KEY_UNAVAILABLE");
  }
  return record;
}
