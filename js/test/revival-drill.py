#!/usr/bin/env python3
"""
Clean-room revival drill.

Implements GENESIS.md sections 4-6 in Python, from the prose alone, and checks
the section 7 vectors. Shares no code with the JavaScript or Rust
implementations -- if this passes, the document is sufficient to rebuild the
layer everything else stands on.

A revival specification that has never been used to revive anything is a claim,
not a capability.
"""

import json
import math
import sys

# The vectors deliberately contain non-ASCII text, because two of the things
# being checked are UTF-16 code unit ordering and literal emission of non-ASCII.
# On a console whose default encoding cannot represent them -- Windows cp1252,
# among others -- printing a vector raises UnicodeEncodeError and the drill dies
# with a traceback instead of a verdict. A custodian would reasonably read that
# as the document being broken.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTICODEC = bytes([0xED, 0x01])

failures = []


def check(label, actual, expected):
    if actual == expected:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}\n          expected {expected!r}\n          actual   {actual!r}")
        failures.append(label)


# ── Section 4: base58btc ─────────────────────────────────────────────────────
def b58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = BASE58[rem] + out
    for byte in data:
        if byte != 0:
            break
        out = "1" + out
    return out or "1"


def b58_decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = BASE58.find(ch)
        if idx < 0:
            raise ValueError("character outside the base58btc alphabet")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = 0
    for ch in text:
        if ch != "1":
            break
        leading += 1
    return b"\x00" * leading + body


# ── Section 5: did:key ───────────────────────────────────────────────────────
def did_from_public_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return "did:key:z" + b58_encode(ED25519_MULTICODEC + key)


def public_key_from_did(did: str) -> bytes:
    if not did.startswith("did:key:"):
        raise ValueError("not a did:key identifier")
    fingerprint = did[len("did:key:"):]
    if not fingerprint.startswith("z"):
        raise ValueError("fingerprint is not multibase base58btc")
    decoded = b58_decode(fingerprint[1:])
    if len(decoded) != 34 or decoded[0:2] != ED25519_MULTICODEC:
        raise ValueError("does not carry an Ed25519 public key")
    return decoded[2:]


# ── Section 6: canonical JSON ────────────────────────────────────────────────
SHORT_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def canon_string(value: str) -> str:
    # Reject lone surrogates.
    units = []
    for ch in value:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    i = 0
    while i < len(units):
        u = units[i]
        if 0xD800 <= u <= 0xDBFF:
            if i + 1 >= len(units) or not (0xDC00 <= units[i + 1] <= 0xDFFF):
                raise ValueError("lone high surrogate")
            i += 2
            continue
        if 0xDC00 <= u <= 0xDFFF:
            raise ValueError("lone low surrogate")
        i += 1

    out = ['"']
    for ch in value:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif cp < 0x20:
            out.append(SHORT_ESCAPES.get(cp, f"\\u{cp:04x}"))
        else:
            out.append(ch)  # non-ASCII emitted literally; solidus not escaped
    out.append('"')
    return "".join(out)


def canon_number(value) -> str:
    if isinstance(value, bool):
        raise ValueError("bool is not a number here")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("non-finite number")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise ValueError("negative zero")
        if value.is_integer():
            value = int(value)
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("unsafe integer")
        return str(value)
    # Shortest round-tripping form, matching ECMAScript Number::toString.
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        exp = int(exponent)
        mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
        text = f"{mantissa}e{'+' if exp > 0 else '-'}{abs(exp)}"
    return text


def canonicalize(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return canon_string(value)
    if isinstance(value, (int, float)):
        return canon_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        # Sort by UTF-16 code unit.
        def utf16_key(k):
            return [ord(c) if ord(c) <= 0xFFFF else 0xD800 + ((ord(c) - 0x10000) >> 10) for c in k]
        keys = sorted(value.keys(), key=utf16_key)
        return "{" + ",".join(f"{canon_string(k)}:{canonicalize(value[k])}" for k in keys) + "}"
    raise ValueError(f"unsupported value: {type(value)}")


# ── Section 7: the vectors ───────────────────────────────────────────────────
print("REVIVAL DRILL — implemented from GENESIS.md alone\n")

print("7.1 identity")
KEY_HEX = "46b14b7854fede602d8b07841989db17bd7e710227163d0bdc4f5de6e83817e5"
DID = "did:key:z6MkjDDPGYQdTcFQ8ecCf7zwP1rKvG7cdH5d8kxYqy7kaNBN"
key = bytes.fromhex(KEY_HEX)
check("public key -> identifier", did_from_public_key(key), DID)
check("identifier -> public key", public_key_from_did(DID).hex(), KEY_HEX)
check("prefixed bytes", (ED25519_MULTICODEC + key).hex(), "ed01" + KEY_HEX)

print("\n7.3 canonicalization")
cases = [
    ({"b": 1, "a": 2, "C": 3, "ä": 4, "Z": 5}, '{"C":3,"Z":5,"a":2,"b":1,"ä":4}'),
    ({"z": {"b": 1, "a": 2}, "a": {"d": 3}}, '{"a":{"d":3},"z":{"a":2,"b":1}}'),
    ({"x": [3, 1, 2]}, '{"x":[3,1,2]}'),
    ({"n": 1.0}, '{"n":1}'),
    ({"n": 1e-7}, '{"n":1e-7}'),
    ({"n": 0.1}, '{"n":0.1}'),
    ({"n": 9007199254740991}, '{"n":9007199254740991}'),
    ({"s": "a/b"}, '{"s":"a/b"}'),
    ({"s": "\b\t\n\f\r"}, '{"s":"\\b\\t\\n\\f\\r"}'),
    ({"s": ""}, '{"s":"\\u0001\\u001f"}'),
    ({"s": "é日本語"}, '{"s":"é日本語"}'),
    ({"o": {}, "a": []}, '{"a":[],"o":{}}'),
    ({"a": None, "b": 1}, '{"a":null,"b":1}'),
]
for value, expected in cases:
    try:
        check(f"canonicalize {expected[:34]}", canonicalize(value), expected)
    except Exception as exc:  # noqa: BLE001
        check(f"canonicalize {expected[:34]}", f"<raised {exc}>", expected)

print("\n7.4 rejections")
rejects = [
    ("lone surrogate", lambda: canonicalize({"s": "\ud800"})),
    ("negative zero", lambda: canonicalize({"n": -0.0})),
    ("unsafe integer", lambda: canonicalize({"n": 9007199254740993})),
    ("1e20", lambda: canonicalize({"n": 1e20})),
    ("1e21", lambda: canonicalize({"n": 1e21})),
    ("infinity", lambda: canonicalize({"n": float("inf")})),
    ("nan", lambda: canonicalize({"n": float("nan")})),
    ("opaque did", lambda: public_key_from_did("did:soma:test-deadbeef")),
]
for label, fn in rejects:
    try:
        fn()
        print(f"  FAIL  {label} was accepted")
        failures.append(label)
    except Exception:  # noqa: BLE001
        print(f"  ok    {label} rejected")

print(f"\n{len(failures)} failure(s)")
if failures:
    print("The document is not sufficient to rebuild from. Each failure is a gap in GENESIS.md.")
    sys.exit(1)
print("GENESIS.md is sufficient to reconstruct identity and canonical bytes.")
