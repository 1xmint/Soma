import { readFile, access, stat } from "node:fs/promises";
import { execSync } from "node:child_process";
import { dirname, extname } from "node:path";
import type { ObservationRecord, ActionRecord } from "../observation-reader.js";

export interface Layer0Result {
  compilationCheck: CompilationResult;
  testResults: TestResult | null;
  fileChecks: FileCheckResult[];
  score: number;
}

export interface CompilationResult {
  checked: boolean;
  passed: boolean;
  errors: string[];
  language: string | null;
}

export interface TestResult {
  ran: boolean;
  passed: number;
  failed: number;
  total: number;
  passRate: number;
  output: string;
}

export interface FileCheckResult {
  path: string;
  exists: boolean;
  sizeBytes: number;
  nonEmpty: boolean;
}

export async function evaluateLayer0(observation: ObservationRecord): Promise<Layer0Result> {
  const writtenFiles = observation.actions
    .filter(a => a.type === "file_write" && a.success && a.path)
    .map(a => a.path!);

  const commands = observation.actions.filter(a => a.type === "command");

  const fileChecks = await checkFiles(writtenFiles);
  const compilationCheck = await checkCompilation(writtenFiles, commands);
  const testResults = analyzeTests(commands);

  const score = computeScore(compilationCheck, testResults, fileChecks);

  return { compilationCheck, testResults: testResults, fileChecks, score };
}

async function checkFiles(paths: string[]): Promise<FileCheckResult[]> {
  const results: FileCheckResult[] = [];
  for (const path of paths) {
    try {
      const s = await stat(path);
      results.push({
        path,
        exists: true,
        sizeBytes: s.size,
        nonEmpty: s.size > 0,
      });
    } catch {
      results.push({ path, exists: false, sizeBytes: 0, nonEmpty: false });
    }
  }
  return results;
}

async function checkCompilation(
  files: string[],
  commands: ActionRecord[],
): Promise<CompilationResult> {
  if (files.length === 0) {
    return { checked: false, passed: false, errors: ["No files written"], language: null };
  }

  const extensions = files.map(f => extname(f).toLowerCase());
  const lang = detectLanguage(extensions);

  const buildCommands = commands.filter(c =>
    c.command && (
      c.command.includes("tsc") ||
      c.command.includes("npm run build") ||
      c.command.includes("node ") ||
      c.command.includes("python ") ||
      c.command.includes("go build")
    )
  );

  if (buildCommands.length > 0) {
    const allPassed = buildCommands.every(c => c.success);
    return {
      checked: true,
      passed: allPassed,
      errors: buildCommands.filter(c => !c.success).map(c => `Command failed: ${c.command}`),
      language: lang,
    };
  }

  // Try syntax check for JavaScript (TypeScript requires tsc, which is a build command)
  if (lang === "javascript") {
    try {
      for (const file of files.filter(f => f.endsWith(".js"))) {
        const content = await readFile(file, "utf-8");
        new Function(content.replace(/import\s+/g, "// import ").replace(/export\s+/g, "// export "));
      }
      return { checked: true, passed: true, errors: [], language: lang };
    } catch (err: any) {
      return { checked: true, passed: false, errors: [err.message], language: lang };
    }
  }

  return { checked: false, passed: false, errors: ["No compilation step detected"], language: lang };
}

function analyzeTests(commands: ActionRecord[]): TestResult | null {
  const testCommands = commands.filter(c =>
    c.command && (
      c.command.includes("test") ||
      c.command.includes("jest") ||
      c.command.includes("vitest") ||
      c.command.includes("mocha") ||
      c.command.includes("pytest")
    )
  );

  if (testCommands.length === 0) return null;

  const ran = testCommands.length > 0;
  const passed = testCommands.filter(c => c.success).length;
  const failed = testCommands.filter(c => !c.success).length;
  const total = testCommands.length;

  return {
    ran,
    passed,
    failed,
    total,
    passRate: total > 0 ? passed / total : 0,
    output: testCommands.map(c => `${c.command}: ${c.success ? "PASS" : "FAIL"}`).join("\n"),
  };
}

function detectLanguage(extensions: string[]): string | null {
  if (extensions.includes(".ts") || extensions.includes(".tsx")) return "typescript";
  if (extensions.includes(".js") || extensions.includes(".jsx")) return "javascript";
  if (extensions.includes(".py")) return "python";
  if (extensions.includes(".go")) return "go";
  if (extensions.includes(".rs")) return "rust";
  return null;
}

function computeScore(
  compilation: CompilationResult,
  tests: TestResult | null,
  files: FileCheckResult[],
): number {
  let score = 0;
  let weight = 0;

  // Files exist and are non-empty (30%)
  if (files.length > 0) {
    const existRate = files.filter(f => f.exists && f.nonEmpty).length / files.length;
    score += existRate * 0.3;
    weight += 0.3;
  }

  // Compilation passes (40%)
  if (compilation.checked) {
    score += compilation.passed ? 0.4 : 0;
    weight += 0.4;
  }

  // Tests pass (30%)
  if (tests?.ran) {
    score += tests.passRate * 0.3;
    weight += 0.3;
  }

  return weight > 0 ? score / weight : 0;
}
