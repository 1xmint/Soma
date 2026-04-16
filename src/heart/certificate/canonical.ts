import { createHash } from 'node:crypto';

const DOMAIN_PREFIX = 'soma-heart-certificate:v0.1:';
const DOMAIN_PREFIX_BYTES = Buffer.from(DOMAIN_PREFIX, 'ascii');

const MAX_SAFE_INTEGER = 2 ** 53 - 1;
const MIN_SAFE_INTEGER = -(2 ** 53 - 1);

export class CanonicalisationError extends Error {
  override readonly name = 'CanonicalisationError';
}

export type SignerRole = 'issuer' | 'counterparty' | 'witness' | 'participant';

const VALID_SIGNER_ROLES: ReadonlySet<string> = new Set<SignerRole>([
  'issuer',
  'counterparty',
  'witness',
  'participant',
]);

function validateRole(role: string): asserts role is SignerRole {
  if (!VALID_SIGNER_ROLES.has(role)) {
    throw new CanonicalisationError(
      `invalid signer role: ${JSON.stringify(role)}; ` +
      'must be one of: issuer, counterparty, witness, participant',
    );
  }
}

export function canonicalizePayload(
  certificate: Record<string, unknown>,
): Buffer {
  const filtered: Record<string, unknown> = {};
  for (const key of Object.keys(certificate)) {
    if (key === 'certificate_id' || key === 'signatures') continue;
    filtered[key] = certificate[key];
  }
  const json = canonicalStringify(filtered);
  return Buffer.from(json, 'utf8');
}

export function computeCertificateId(canonicalBytes: Buffer): string {
  const hash = createHash('sha256');
  hash.update(DOMAIN_PREFIX_BYTES);
  hash.update(canonicalBytes);
  return hash.digest('hex');
}

export function computeSignatureInput(
  canonicalBytes: Buffer,
  role: SignerRole,
): Buffer {
  validateRole(role);
  const prefix = Buffer.from(`${DOMAIN_PREFIX}${role}:`, 'ascii');
  return Buffer.concat([prefix, canonicalBytes]);
}

export function computeSignatureInputHash(
  canonicalBytes: Buffer,
  role: SignerRole,
): string {
  const input = computeSignatureInput(canonicalBytes, role);
  return createHash('sha256').update(input).digest('hex');
}

function canonicalStringify(value: unknown): string {
  return encodeValue(value);
}

function encodeValue(value: unknown): string {
  if (value === undefined) {
    throw new CanonicalisationError(
      'undefined is not allowed in canonical JSON',
    );
  }
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return encodeNumber(value);
  if (typeof value === 'string') return encodeString(value);
  if (ArrayBuffer.isView(value)) return encodeString(encodeBytes(value));
  if (Array.isArray(value)) return encodeArray(value);
  if (typeof value === 'object') return encodeObject(value as Record<string, unknown>);
  throw new CanonicalisationError(
    `unsupported type: ${typeof value}`,
  );
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new CanonicalisationError(
      'NaN and Infinity are not allowed in canonical JSON',
    );
  }
  if (!Number.isInteger(n)) {
    throw new CanonicalisationError(
      'floating-point numbers are not allowed in v0.1 canonical JSON',
    );
  }
  if (n < MIN_SAFE_INTEGER || n > MAX_SAFE_INTEGER) {
    throw new CanonicalisationError(
      `integer ${n} is outside the safe range [-(2^53-1), 2^53-1]`,
    );
  }
  return String(n);
}

function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i)!;
    if (cp >= 0x10000) {
      out += s[i] + s[i + 1];
      i++;
      continue;
    }
    const ch = s[i];
    if (ch === '"') { out += '\\"'; continue; }
    if (ch === '\\') { out += '\\\\'; continue; }
    if (cp <= 0x1f) {
      switch (ch) {
        case '\b': out += '\\b'; break;
        case '\f': out += '\\f'; break;
        case '\n': out += '\\n'; break;
        case '\r': out += '\\r'; break;
        case '\t': out += '\\t'; break;
        default:
          out += '\\u' + cp.toString(16).padStart(4, '0');
          break;
      }
      continue;
    }
    out += ch;
  }
  out += '"';
  return out;
}

function encodeArray(arr: unknown[]): string {
  const items = arr.map(encodeValue);
  return '[' + items.join(',') + ']';
}

function encodeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj);
  const sortedKeys = [...keys].sort(compareByCodePoint);

  const seen = new Set<string>();
  for (const key of sortedKeys) {
    if (seen.has(key)) {
      throw new CanonicalisationError(`duplicate key: ${key}`);
    }
    seen.add(key);
  }

  const entries: string[] = [];
  for (const key of sortedKeys) {
    const v = obj[key];
    entries.push(encodeString(key) + ':' + encodeValue(v));
  }
  return '{' + entries.join(',') + '}';
}

function encodeBytes(view: ArrayBufferView): string {
  const buf = Buffer.isBuffer(view)
    ? view
    : Buffer.from(view.buffer, view.byteOffset, view.byteLength);
  return buf.toString('base64');
}

function compareByCodePoint(a: string, b: string): number {
  const aPoints = Array.from(a);
  const bPoints = Array.from(b);
  const len = Math.min(aPoints.length, bPoints.length);
  for (let i = 0; i < len; i++) {
    const aCp = aPoints[i].codePointAt(0)!;
    const bCp = bPoints[i].codePointAt(0)!;
    if (aCp !== bCp) return aCp - bCp;
  }
  return aPoints.length - bPoints.length;
}
