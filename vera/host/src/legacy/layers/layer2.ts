import { readFile } from "node:fs/promises";
import { extname } from "node:path";
import type { ObservationRecord } from "../observation-reader.js";

export interface Layer2Result {
  files: FileAnalysis[];
  aggregateEntropy: number;
  aggregateComplexity: number;
  dependencyFlags: string[];
  score: number;
}

export interface FileAnalysis {
  path: string;
  language: string | null;
  entropy: number;
  complexity: number;
  lineCount: number;
  importCount: number;
  suspiciousImports: string[];
  nestingDepth: number;
}

export async function evaluateLayer2(observation: ObservationRecord): Promise<Layer2Result> {
  const writtenFiles = observation.actions
    .filter(a => a.type === "file_write" && a.success && a.path)
    .map(a => a.path!);

  const analyses: FileAnalysis[] = [];

  for (const path of writtenFiles) {
    try {
      const content = await readFile(path, "utf-8");
      analyses.push(analyzeFile(path, content));
    } catch {
      // File may have been deleted or moved
    }
  }

  const aggregateEntropy = analyses.length > 0
    ? analyses.reduce((sum, a) => sum + a.entropy, 0) / analyses.length
    : 0;

  const aggregateComplexity = analyses.length > 0
    ? analyses.reduce((sum, a) => sum + a.complexity, 0) / analyses.length
    : 0;

  const dependencyFlags = analyses.flatMap(a => a.suspiciousImports);

  const score = computeStructuralScore(analyses, aggregateEntropy, aggregateComplexity, dependencyFlags);

  return { files: analyses, aggregateEntropy, aggregateComplexity, dependencyFlags, score };
}

function analyzeFile(path: string, content: string): FileAnalysis {
  const ext = extname(path).toLowerCase();
  const language = detectLanguage(ext);
  const lines = content.split("\n");

  return {
    path,
    language,
    entropy: computeTokenEntropy(content),
    complexity: estimateCyclomaticComplexity(content),
    lineCount: lines.length,
    importCount: countImports(content, language),
    suspiciousImports: detectSuspiciousImports(content, language),
    nestingDepth: maxNestingDepth(content),
  };
}

function computeTokenEntropy(content: string): number {
  // Shannon entropy over token types (keywords, identifiers, operators, etc.)
  const tokens = content.match(/[a-zA-Z_]\w*|[{}()\[\]]|[+\-*/=<>!&|^~%]+|[0-9]+\.?[0-9]*|\S/g) || [];
  if (tokens.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const token of tokens) {
    const category = categorizeToken(token);
    freq.set(category, (freq.get(category) || 0) + 1);
  }

  let entropy = 0;
  const total = tokens.length;
  for (const count of freq.values()) {
    const p = count / total;
    if (p > 0) entropy -= p * Math.log2(p);
  }

  return entropy;
}

function categorizeToken(token: string): string {
  if (/^[0-9]/.test(token)) return "NUMBER";
  if (/^["'`]/.test(token)) return "STRING";
  if (/^[{}()\[\]]$/.test(token)) return token;
  if (/^[+\-*/=<>!&|^~%]+$/.test(token)) return "OPERATOR";
  if (KEYWORDS.has(token)) return "KEYWORD:" + token;
  return "IDENTIFIER";
}

const KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "break", "continue", "return",
  "function", "class", "const", "let", "var", "import", "export", "from", "async", "await",
  "try", "catch", "throw", "finally", "new", "this", "super", "typeof", "instanceof",
  "interface", "type", "enum", "extends", "implements", "abstract", "private", "public",
  "protected", "static", "readonly", "def", "self", "lambda", "yield",
]);

function estimateCyclomaticComplexity(content: string): number {
  // Count decision points as an approximation
  const patterns = [
    /\bif\b/g, /\belse\s+if\b/g, /\bfor\b/g, /\bwhile\b/g, /\bdo\b/g,
    /\bswitch\b/g, /\bcase\b/g, /\bcatch\b/g, /\?\?/g, /\?\./g,
    /&&/g, /\|\|/g, /\?[^?.:]/g,
  ];

  let complexity = 1;
  for (const pattern of patterns) {
    const matches = content.match(pattern);
    if (matches) complexity += matches.length;
  }

  return complexity;
}

function countImports(content: string, language: string | null): number {
  if (language === "typescript" || language === "javascript") {
    const imports = content.match(/^import\s+/gm) || [];
    const requires = content.match(/require\s*\(/g) || [];
    return imports.length + requires.length;
  }
  if (language === "python") {
    const imports = content.match(/^(import|from)\s+/gm) || [];
    return imports.length;
  }
  return 0;
}

function detectSuspiciousImports(content: string, language: string | null): string[] {
  const flags: string[] = [];

  // Check for potentially dangerous imports/requires
  const suspiciousModules = [
    "child_process", "eval", "vm", "net", "dgram",
    "os", "fs", "http", "https", "crypto",
    "subprocess", "shutil", "ctypes", "pickle",
  ];

  for (const mod of suspiciousModules) {
    const regex = new RegExp(`['"\`](?:node:)?${mod}['"\`]`);
    if (regex.test(content)) {
      flags.push(`imports ${mod}`);
    }
  }

  // Dynamic eval/exec patterns
  if (/\beval\s*\(/.test(content)) flags.push("uses eval()");
  if (/\bexec\s*\(/.test(content)) flags.push("uses exec()");
  if (/\bFunction\s*\(/.test(content)) flags.push("uses Function constructor");
  if (/process\.env/.test(content)) flags.push("accesses environment variables");

  return flags;
}

function maxNestingDepth(content: string): number {
  let maxDepth = 0;
  let current = 0;
  for (const ch of content) {
    if (ch === "{") {
      current++;
      if (current > maxDepth) maxDepth = current;
    } else if (ch === "}") {
      current = Math.max(0, current - 1);
    }
  }
  return maxDepth;
}

function detectLanguage(ext: string): string | null {
  const map: Record<string, string> = {
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
  };
  return map[ext] ?? null;
}

function computeStructuralScore(
  analyses: FileAnalysis[],
  entropy: number,
  complexity: number,
  flags: string[],
): number {
  if (analyses.length === 0) return 1.0;

  let score = 1.0;

  // Penalize very high entropy (potential obfuscation)
  if (entropy > 6.0) score -= 0.2;

  // Penalize very high complexity
  if (complexity > 50) score -= 0.15;
  else if (complexity > 30) score -= 0.05;

  // Penalize deep nesting
  const maxNest = Math.max(...analyses.map(a => a.nestingDepth));
  if (maxNest > 8) score -= 0.15;
  else if (maxNest > 5) score -= 0.05;

  // Penalize suspicious imports
  if (flags.length > 3) score -= 0.2;
  else if (flags.length > 0) score -= 0.05 * flags.length;

  return Math.max(0, Math.min(1, score));
}
