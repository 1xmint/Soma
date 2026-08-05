/**
 * Self-certifying `did:key` identifiers, byte-compatible with Soma.
 *
 * Ported from js/src/crypto.mjs in hey-vera/soma, which is normative.
 *
 * Vera previously minted `did:soma:test-<random>` — an opaque identifier with
 * no relationship to the key, carried alongside it and trusted at registration.
 * That had two consequences:
 *
 *   1. It could not interoperate with Soma, whose identities are `did:key:z…`.
 *   2. Any key could be bound to any identifier, and the host then verified
 *      against whatever the registration happened to store. Attribution
 *      depended on the registry being right rather than on mathematics.
 *
 * A `did:key` identifier *is* the multicodec-tagged public key in base58btc.
 * The key is recoverable from the identifier, so nothing has to be trusted to
 * distribute it and nothing can be substituted for it.
 */

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);
const DID_KEY_PREFIX = 'did:key:';

function base58btc(bytes: Uint8Array): string {
  const hex = Buffer.from(bytes).toString('hex');
  let value = BigInt(`0x${hex || '0'}`);
  let encoded = '';
  while (value > 0n) {
    const remainder = Number(value % 58n);
    encoded = BASE58[remainder] + encoded;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded || '1';
}

function base58btcDecode(value: string): Uint8Array {
  let number = 0n;
  for (const character of value) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) throw new Error('invalid base58btc character');
    number = number * 58n + BigInt(digit);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = Buffer.from(hex === '0' ? '' : hex, 'hex');
  let leading = 0;
  for (const character of value) {
    if (character !== '1') break;
    leading += 1;
  }
  return Uint8Array.from(Buffer.concat([Buffer.alloc(leading), body]));
}

/** The multibase fingerprint an Ed25519 public key commits to. */
export function fingerprintFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, received ${publicKey.length}`);
  }
  return `z${base58btc(Uint8Array.from([...ED25519_MULTICODEC, ...publicKey]))}`;
}

/** The `did:key` identifier an Ed25519 public key commits to. */
export function didFromPublicKey(publicKey: Uint8Array): string {
  return `${DID_KEY_PREFIX}${fingerprintFromPublicKey(publicKey)}`;
}

/**
 * Recover the public key a `did:key` identifier commits to.
 *
 * Throws for any identifier whose key cannot be recovered. Callers must not
 * fall back to a separately supplied key: that would reintroduce exactly the
 * substitution this function exists to prevent.
 */
export function publicKeyFromDid(did: string): Uint8Array {
  if (typeof did !== 'string' || !did.startsWith(DID_KEY_PREFIX)) {
    throw new Error('not a did:key identifier; its key cannot be recovered');
  }
  const fingerprint = did.slice(DID_KEY_PREFIX.length);
  if (!fingerprint.startsWith('z')) throw new Error('did:key fingerprint is not base58btc multibase');

  const decoded = base58btcDecode(fingerprint.slice(1));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('did:key does not carry an Ed25519 public key');
  }
  return decoded.slice(2);
}

/** True when the identifier commits to exactly this key. */
export function didMatchesPublicKey(did: string, publicKey: Uint8Array): boolean {
  try {
    const committed = publicKeyFromDid(did);
    if (committed.length !== publicKey.length) return false;
    let equal = 0;
    for (let index = 0; index < committed.length; index += 1) {
      equal |= committed[index] ^ publicKey[index];
    }
    return equal === 0;
  } catch {
    return false;
  }
}
