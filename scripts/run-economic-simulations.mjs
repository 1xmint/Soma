import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runEconomicSimulation } from "./lib/economic-simulation.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const requested = process.argv[2] ?? "examples/economic-simulation-suite.example.json";
const suitePath = path.resolve(root, requested);
const relative = path.relative(root, suitePath);
if (relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
  throw new Error("simulation suite path must stay inside the Origin capsule");
}
const suite = JSON.parse(await readFile(suitePath, "utf8"));
process.stdout.write(JSON.stringify(runEconomicSimulation(suite), null, 2) + "\n");
