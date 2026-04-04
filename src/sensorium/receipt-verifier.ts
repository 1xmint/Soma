/**
 * receipt-verifier.ts — Offline verification of ClawNet Soma Receipts
 *
 * Allows any agent running soma-sense to verify a ClawNet transaction receipt
 * without contacting ClawNet's API. Pure cryptographic verification using
 * the platform's Ed25519 public key from /.well-known/soma.json.
 *
 * This is the "trust but verify" primitive for the agent economy:
 * Agent A shows Agent B a Soma Receipt. Agent B verifies it locally.
 * No account needed, no API call, no trust in ClawNet's availability.
 *
 * @example
 * ```ts
 * import { verifyClawNetReceipt } from "soma-sense";
 *
 * const result = verifyClawNetReceipt(receiptJson, {
 *   publicKeyMultibase: "z6Mk...",  // from ClawNet's /.well-known/soma.json
 * });
 *
 * if (result.valid) {
 *   console.log("Receipt is authentic:", result.receiptId);
 * }
 * ```
 */

import { createHash, createPublicKey, verify } from "node:crypto";
import { getCryptoProvider } from "../core/crypto-provider.js";

// ─── Types ──────────────────────────────────────────────────────────────────

/** A ClawNet Soma Receipt as returned by /v1/soma/receipt/:id */
export interface SomaReceipt {
  id: string;
  requestId: string;
  paymentMethod: string;
  creditsCost: number;
  requestHash: string;
  responseHash: string;
  somaDataHash: string | null;
  heartbeatIndex: number | null;
  cached: boolean;
  signature: string;
  algorithm: string;
  hybridSignature?: {
    version: "2.0";
    algorithms: ["Ed25519", "ML-DSA-65"];
    ed25519: string;
    mlDsa65: string;
  };
  easUid: string | null;
  easScanUrl: string | null;
  createdAt: string;
  verification: {
    platformDid: string;
    publicKeyMultibase: string;
    attesterAddress: string | null;
    algorithm: string;
    hashAlgorithm: string;
  };
}

export interface ReceiptVerificationOptions {
  /** Platform's Ed25519 public key in multibase base58btc format (z...) */
  publicKeyMultibase: string;
}

export interface ReceiptVerificationResult {
  /** Whether the receipt signature is valid */
  valid: boolean;
  /** Receipt ID if valid */
  receiptId: string | null;
  /** Algorithm used for verification */
  algorithm: string;
  /** Error message if invalid */
  error?: string;
  /** Receipt details (only if valid) */
  details?: {
    paymentMethod: string;
    creditsCost: number;
    requestHash: string;
    responseHash: string;
    hasProvenance: boolean;
    easUid: string | null;
    createdAt: string;
  };
}

// ─── Base58btc decode ───────────────────────────────────────────────────────

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(encoded: string): Uint8Array {
  // Strip 'z' multibase prefix
  const str = encoded.startsWith("z") ? encoded.slice(1) : encoded;

  let num = 0n;
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }

  const hex = num.toString(16).padStart(2, "0");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  // Handle leading zeros
  let leadingZeros = 0;
  for (const char of str) {
    if (char === "1") leadingZeros++;
    else break;
  }

  if (leadingZeros > 0) {
    const result = new Uint8Array(leadingZeros + bytes.length);
    result.set(bytes, leadingZeros);
    return result;
  }

  return bytes;
}

// ─── JCS Canonicalization (RFC 8785) ────────────────────────────────────────

function jcsSerialize(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "boolean" || typeof obj === "number") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(jcsSerialize).join(",") + "]";
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    const entries = keys
      .filter((k) => (obj as Record<string, unknown>)[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + jcsSerialize((obj as Record<string, unknown>)[k]));
    return "{" + entries.join(",") + "}";
  }
  return String(obj);
}

// ─── Verification ───────────────────────────────────────────────────────────

/**
 * Verify a ClawNet Soma Receipt offline.
 *
 * Reconstructs the signed payload from the receipt fields, hashes it,
 * and verifies the Ed25519 signature against the platform's public key.
 *
 * No network calls needed — pure cryptographic verification.
 */
export function verifyClawNetReceipt(
  receipt: SomaReceipt,
  options: ReceiptVerificationOptions,
): ReceiptVerificationResult {
  try {
    // 1. Decode the public key from multibase
    const decoded = base58btcDecode(options.publicKeyMultibase);

    // Strip multikey prefix (0xed 0x01 for Ed25519)
    let rawKey: Uint8Array;
    if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
      rawKey = decoded.slice(2);
    } else if (decoded.length === 32) {
      rawKey = decoded;
    } else {
      return { valid: false, receiptId: null, algorithm: "unknown", error: "Invalid public key format" };
    }

    // 2. Reconstruct the payload that was signed (must match soma-receipt.ts)
    const receiptPayload: Record<string, unknown> = {
      id: receipt.id,
      requestId: receipt.requestId,
      paymentMethod: receipt.paymentMethod,
      paymentRef: null, // We don't have the raw ref — it was hashed before signing
      creditsCost: receipt.creditsCost,
      requestHash: receipt.requestHash,
      responseHash: receipt.responseHash,
      somaDataHash: receipt.somaDataHash || null,
      heartbeatIndex: receipt.heartbeatIndex ?? null,
      cached: receipt.cached ?? false,
      timestamp: receipt.createdAt,
    };

    // 3. JCS canonicalize + SHA-256 hash (eddsa-jcs-2022 pattern)
    const canonical = Buffer.from(jcsSerialize(receiptPayload), "utf-8");
    const hash = createHash("sha256").update(canonical).digest();

    // 4. Verify Ed25519 signature
    const signatureBuffer = Buffer.from(receipt.signature, "base64url");

    // Import the raw Ed25519 public key
    const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKeyObj = createPublicKey({ key: spki, format: "der", type: "spki" });

    const valid = verify(null, hash, publicKeyObj, signatureBuffer);

    if (!valid) {
      return { valid: false, receiptId: receipt.id, algorithm: receipt.algorithm, error: "Signature verification failed" };
    }

    return {
      valid: true,
      receiptId: receipt.id,
      algorithm: receipt.algorithm,
      details: {
        paymentMethod: receipt.paymentMethod,
        creditsCost: receipt.creditsCost,
        requestHash: receipt.requestHash,
        responseHash: receipt.responseHash,
        hasProvenance: !!receipt.somaDataHash,
        easUid: receipt.easUid,
        createdAt: receipt.createdAt,
      },
    };
  } catch (err) {
    return {
      valid: false,
      receiptId: receipt.id ?? null,
      algorithm: receipt.algorithm ?? "unknown",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Fetch a receipt from ClawNet and verify it offline.
 * Convenience wrapper — uses network to fetch, then verifies locally.
 */
export async function fetchAndVerifyReceipt(
  receiptId: string,
  options: ReceiptVerificationOptions & { apiBase?: string },
): Promise<ReceiptVerificationResult> {
  const base = options.apiBase || "https://api.claw-net.org";

  const res = await fetch(`${base}/v1/soma/receipt/${encodeURIComponent(receiptId)}`);
  if (!res.ok) {
    return { valid: false, receiptId, algorithm: "unknown", error: `HTTP ${res.status}: ${res.statusText}` };
  }

  const data = await res.json();
  const receipt = data.receipt as SomaReceipt;

  if (!receipt) {
    return { valid: false, receiptId, algorithm: "unknown", error: "No receipt in response" };
  }

  return verifyClawNetReceipt(receipt, options);
}
