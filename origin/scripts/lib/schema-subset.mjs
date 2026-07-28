function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function valueType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  return typeof value;
}

function resolveLocalRef(root, reference) {
  if (!reference.startsWith("#/")) {
    throw new Error("only local JSON Schema references are supported: " + reference);
  }
  return reference
    .slice(2)
    .split("/")
    .reduce((current, segment) => {
      const decoded = segment.replaceAll("~1", "/").replaceAll("~0", "~");
      if (!current || !(decoded in current)) {
        throw new Error("unresolved JSON Schema reference: " + reference);
      }
      return current[decoded];
    }, root);
}

export function validateSchemaSubset(root, value) {
  const errors = [];

  function check(schema, candidate, location, target = errors) {
    if (schema === true) return;
    if (schema === false) {
      target.push(location + " is forbidden by schema");
      return;
    }
    if (!schema || typeof schema !== "object") {
      target.push(location + " has an invalid schema node");
      return;
    }

    if (schema.$ref) {
      check(resolveLocalRef(root, schema.$ref), candidate, location, target);
      return;
    }

    if (schema.oneOf) {
      const outcomes = schema.oneOf.map((branch) => {
        const branchErrors = [];
        check(branch, candidate, location, branchErrors);
        return branchErrors;
      });
      const successes = outcomes.filter((branchErrors) => branchErrors.length === 0);
      if (successes.length !== 1) {
        target.push(location + " must match exactly one oneOf branch");
      }
      if (successes.length !== 1) return;
    }

    if (schema.allOf) {
      for (const branch of schema.allOf) check(branch, candidate, location, target);
    }

    if (schema.if) {
      const ifErrors = [];
      check(schema.if, candidate, location, ifErrors);
      if (ifErrors.length === 0 && schema.then) {
        check(schema.then, candidate, location, target);
      } else if (ifErrors.length > 0 && schema.else) {
        check(schema.else, candidate, location, target);
      }
    }

    if ("const" in schema && !same(candidate, schema.const)) {
      target.push(location + " must equal the schema constant");
    }
    if (schema.enum && !schema.enum.some((entry) => same(entry, candidate))) {
      target.push(location + " is not in the allowed enum");
    }

    if (schema.type) {
      const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
      const actual = valueType(candidate);
      const numberMatchesInteger = actual === "integer" && allowed.includes("number");
      if (!allowed.includes(actual) && !numberMatchesInteger) {
        target.push(location + " has type " + actual + "; expected " + allowed.join("|"));
        return;
      }
    }

    if (typeof candidate === "string") {
      if (schema.minLength !== undefined && candidate.length < schema.minLength) {
        target.push(location + " is shorter than minLength");
      }
      if (schema.maxLength !== undefined && candidate.length > schema.maxLength) {
        target.push(location + " is longer than maxLength");
      }
      if (schema.pattern && !(new RegExp(schema.pattern).test(candidate))) {
        target.push(location + " does not match pattern " + schema.pattern);
      }
      if (schema.format === "date-time") {
        const hasZone = /(Z|[+-][0-9]{2}:[0-9]{2})$/.test(candidate);
        if (!hasZone || Number.isNaN(Date.parse(candidate))) {
          target.push(location + " is not a valid zoned date-time");
        }
      }
      if (schema.format === "uri") {
        try {
          const parsed = new URL(candidate);
          if (!parsed.protocol) throw new Error("missing protocol");
        } catch {
          target.push(location + " is not a valid absolute URI");
        }
      }
    }

    if (typeof candidate === "number") {
      if (schema.minimum !== undefined && candidate < schema.minimum) {
        target.push(location + " is below minimum");
      }
      if (schema.maximum !== undefined && candidate > schema.maximum) {
        target.push(location + " is above maximum");
      }
    }

    if (Array.isArray(candidate)) {
      if (schema.minItems !== undefined && candidate.length < schema.minItems) {
        target.push(location + " has fewer than minItems");
      }
      if (schema.maxItems !== undefined && candidate.length > schema.maxItems) {
        target.push(location + " has more than maxItems");
      }
      if (schema.uniqueItems) {
        const encoded = candidate.map((entry) => JSON.stringify(entry));
        if (new Set(encoded).size !== encoded.length) {
          target.push(location + " has duplicate items");
        }
      }
      if (schema.items) {
        candidate.forEach((entry, index) => check(schema.items, entry, location + "[" + index + "]", target));
      }
    }

    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      const properties = schema.properties || {};
      if (schema.required) {
        for (const key of schema.required) {
          if (!(key in candidate)) target.push(location + "." + key + " is required");
        }
      }
      for (const [key, entry] of Object.entries(candidate)) {
        if (key in properties) {
          check(properties[key], entry, location + "." + key, target);
        } else if (schema.additionalProperties === false) {
          target.push(location + "." + key + " is an unknown property");
        } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
          check(schema.additionalProperties, entry, location + "." + key, target);
        }
      }
    }
  }

  check(root, value, "$");
  return errors;
}

