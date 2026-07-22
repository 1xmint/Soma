import { canonicalize } from "./canonicalize.mjs";
import { SomaError } from "./errors.mjs";

function equal(left, right) {
  try { return canonicalize(left) === canonicalize(right); } catch { return false; }
}

function typeMatches(value, type) {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  if (type === "integer") return Number.isSafeInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return typeof value === type;
}

function resolveLocal(root, reference) {
  if (typeof reference !== "string" || !reference.startsWith("#/")) throw new Error("only local schema references are supported");
  return reference.slice(2).split("/").reduce((value, token) => value[token.replaceAll("~1", "/").replaceAll("~0", "~")], root);
}

export function assertJsonSchema(value, schema, { code = "JSON_SCHEMA_INVALID", label = "value" } = {}) {
  const root = schema;
  function reject(pointer, reason) {
    throw new SomaError(`${label} violates its closed schema at ${pointer}: ${reason}`, 2, code, { pointer, reason });
  }
  function visit(current, rule, pointer) {
    if (!rule || typeof rule !== "object") reject(pointer, "schema rule is invalid");
    if (rule.allOf) for (const candidate of rule.allOf) visit(current, candidate, pointer);
    if (rule.oneOf) {
      let matches = 0;
      for (const candidate of rule.oneOf) {
        try { visit(current, candidate, pointer); matches += 1; } catch (error) { if (!(error instanceof SomaError)) throw error; }
      }
      if (matches !== 1) reject(pointer, "value must match exactly one oneOf branch");
    }
    if (rule.if) {
      let condition = true;
      try { visit(current, rule.if, pointer); } catch (error) { if (!(error instanceof SomaError)) throw error; condition = false; }
      if (condition && rule.then) visit(current, rule.then, pointer);
      if (!condition && rule.else) visit(current, rule.else, pointer);
    }
    if (rule.$ref) return visit(current, resolveLocal(root, rule.$ref), pointer);
    if (Object.hasOwn(rule, "const") && !equal(current, rule.const)) reject(pointer, "constant value mismatch");
    if (rule.enum && !rule.enum.some((candidate) => equal(current, candidate))) reject(pointer, "value is not in the enum");
    if (rule.type) {
      const types = Array.isArray(rule.type) ? rule.type : [rule.type];
      if (!types.some((type) => typeMatches(current, type))) reject(pointer, `expected type ${types.join(" or ")}`);
    }
    if (typeof current === "string") {
      if (rule.minLength !== undefined && current.length < rule.minLength) reject(pointer, "string is too short");
      if (rule.maxLength !== undefined && current.length > rule.maxLength) reject(pointer, "string is too long");
      if (rule.pattern !== undefined && !(new RegExp(rule.pattern, "u")).test(current)) reject(pointer, "string pattern mismatch");
      if (rule.format === "date-time") {
        const validShape = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(current);
        const parsed = Date.parse(current);
        const normalized = Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
        if (!validShape || (current !== normalized && current !== normalized?.replace(".000Z", "Z"))) reject(pointer, "date-time must be a real canonical UTC timestamp");
      }
      if (rule.contentEncoding === "base64") {
        const decoded = Buffer.from(current, "base64");
        if (decoded.toString("base64") !== current) reject(pointer, "base64 is not canonical");
      }
    }
    if (typeof current === "number") {
      if (rule.minimum !== undefined && current < rule.minimum) reject(pointer, "number is below minimum");
      if (rule.maximum !== undefined && current > rule.maximum) reject(pointer, "number is above maximum");
    }
    if (Array.isArray(current)) {
      if (rule.minItems !== undefined && current.length < rule.minItems) reject(pointer, "array has too few items");
      if (rule.maxItems !== undefined && current.length > rule.maxItems) reject(pointer, "array has too many items");
      if (rule.uniqueItems && new Set(current.map((entry) => canonicalize(entry))).size !== current.length) reject(pointer, "array items are not unique");
      if (rule.items) current.forEach((entry, index) => visit(entry, rule.items, `${pointer}/${index}`));
    }
    if (current !== null && typeof current === "object" && !Array.isArray(current)) {
      for (const required of rule.required || []) if (!Object.hasOwn(current, required)) reject(pointer, `missing required property ${required}`);
      if (rule.additionalProperties === false) {
        for (const key of Object.keys(current)) if (!Object.hasOwn(rule.properties || {}, key)) reject(`${pointer}/${key}`, "unknown property");
      }
      for (const [key, childRule] of Object.entries(rule.properties || {})) if (Object.hasOwn(current, key)) visit(current[key], childRule, `${pointer}/${key}`);
    }
  }
  visit(value, schema, "$");
  return true;
}
