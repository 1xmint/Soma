function assertUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error("lone high surrogate");
      }
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

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    if (Object.is(value, -0)) throw new Error("negative zero");
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new Error("unsafe integer; encode exact quantities as decimal strings");
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return "[" + value.map((entry) => canonicalize(entry)).join(",") + "]";
  }

  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const entries = keys.map((key) => {
      assertUnicode(key);
      if (value[key] === undefined) throw new Error("undefined object member");
      return JSON.stringify(key) + ":" + canonicalize(value[key]);
    });
    return "{" + entries.join(",") + "}";
  }

  throw new Error("unsupported JSON value: " + typeof value);
}

