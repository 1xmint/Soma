import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runEconomicSimulation } from "./lib/economic-simulation.mjs";

const root = path.resolve(fileURLToPath(new URL("../", import.meta.url)));
const suitePath = path.join(root, "examples", "economic-simulation-suite.example.json");
const reportPath = path.join(root, "examples", "economic-simulation-report.example.json");
const suite = JSON.parse(await readFile(suitePath, "utf8"));
const report = runEconomicSimulation(suite);
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`Wrote ${path.relative(root, reportPath)}: ${report.report_hash}`);
console.log("Activation decision: reject_activation");
