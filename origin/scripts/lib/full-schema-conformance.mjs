import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const schemaDirectory = path.join(root, "schemas");
const exampleDirectory = path.join(root, "examples");

function fail(message) {
  throw new Error(`full JSON Schema conformance failed: ${message}`);
}

function formatErrors(errors = []) {
  return errors
    .map((entry) => `${entry.instancePath || "/"} ${entry.message ?? "is invalid"}`)
    .join("; ");
}

async function readJson(absolutePath) {
  return JSON.parse(await readFile(absolutePath, "utf8"));
}

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: true,
  validateSchema: true
});
addFormats(ajv);

const schemaFiles = (await readdir(schemaDirectory))
  .filter((name) => name.endsWith(".schema.json"))
  .sort();
const schemasByFile = new Map();

for (const fileName of schemaFiles) {
  const schema = await readJson(path.join(schemaDirectory, fileName));
  if (!ajv.validateSchema(schema)) {
    fail(`${fileName} is not a valid Draft 2020-12 schema: ${formatErrors(ajv.errors)}`);
  }
  try {
    ajv.addSchema(schema);
  } catch (error) {
    fail(`${fileName} could not be compiled: ${error.message}`);
  }
  schemasByFile.set(fileName, schema);
}

let positiveChecks = 0;
let negativeChecks = 0;
const exampleFiles = (await readdir(exampleDirectory))
  .filter((name) => name.endsWith(".example.json"))
  .sort();

for (const fileName of exampleFiles) {
  const example = await readJson(path.join(exampleDirectory, fileName));
  if (typeof example.$schema !== "string") fail(`${fileName} has no local $schema declaration`);
  const schemaFile = path.basename(example.$schema);
  const schema = schemasByFile.get(schemaFile);
  if (!schema) fail(`${fileName} references unknown schema ${example.$schema}`);
  const validate = ajv.getSchema(schema.$id);
  if (!validate) fail(`${fileName} schema ${schemaFile} was not compiled`);
  if (!validate(example)) fail(`${fileName} is invalid: ${formatErrors(validate.errors)}`);
  positiveChecks += 1;

  const structurallyInvalid = structuredClone(example);
  structurallyInvalid.__somavera_unexpected_property__ = true;
  if (validate(structurallyInvalid)) {
    fail(`${schemaFile} accepted an undeclared top-level property in ${fileName}`);
  }
  negativeChecks += 1;
}

if (exampleFiles.length !== schemaFiles.length) {
  fail(`expected one positive example per schema; found ${exampleFiles.length} examples and ${schemaFiles.length} schemas`);
}

console.log(
  `Full JSON Schema 2020-12 checks passed: ${schemaFiles.length} meta-validated schemas, ` +
  `${positiveChecks} positive examples, ${negativeChecks} structural negative cases.`
);
