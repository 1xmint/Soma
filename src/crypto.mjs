import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC = Object.freeze({ Ed25519: Buffer.from([0xed, 0x01]), X25519: Buffer.from([0xec, 0x01]) });

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
    encoded = "1" + encoded;
  }
  return encoded || "1";
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

export function createInitialKeyMaterial(createdAt) {
  const roles = [
    createRole("controller_signing", "Ed25519"),
    createRole("agent_signing", "Ed25519"),
    createRole("observer_signing", "Ed25519"),
    createRole("vera_private_reply_encryption", "X25519")
  ];
  const publicRoles = Object.fromEntries(roles.map((entry) => [entry.publicRecord.role, entry.publicRecord]));
  const controllerDid = publicRoles.controller_signing.did;
  const agentDid = publicRoles.agent_signing.did;
  const observerDid = publicRoles.observer_signing.did;
  return {
    publicIdentity: {
      schema_version: "somavera.soma-local-identity.v1",
      created_at: createdAt,
      controller_did: controllerDid,
      agent_did: agentDid,
      observer_did: observerDid,
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
