import { SomaError } from "./errors.mjs";

function assertUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("lone high surrogate");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("lone low surrogate");
    }
  }
}

export function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "string") {
    assertUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Object.is(value, -0)) throw new Error("negative zero");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("unsafe integer; encode exact quantities as decimal strings");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => {
      assertUnicode(key);
      if (value[key] === undefined) throw new Error("undefined object member");
      return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
    }).join(",")}}`;
  }
  throw new Error(`unsupported JSON value: ${typeof value}`);
}

export function parseCanonicalJson(text, source = "JSON input") {
  const raw = text.endsWith("\n") ? text.slice(0, -1) : text;
  if (!raw || raw.includes("\r") || raw.endsWith("\n")) {
    throw new SomaError(`${source} must be one canonical JSON value with at most one trailing LF`, 2, "JSON_NOT_CANONICAL");
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    throw new SomaError(`${source} is invalid JSON`, 2, "JSON_INVALID", { cause: error.message });
  }
  let canonical;
  try {
    canonical = canonicalize(value);
  } catch (error) {
    throw new SomaError(`${source} violates the Somavera I-JSON profile`, 2, "JSON_PROFILE_INVALID", { cause: error.message });
  }
  if (canonical !== raw) {
    throw new SomaError(`${source} is not canonical JSON (duplicate keys and non-canonical spellings are rejected)`, 2, "JSON_NOT_CANONICAL");
  }
  return value;
}
