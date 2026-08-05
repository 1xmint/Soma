/**
 * vera-observer CLI entry point.
 *
 * Extracts git commits from a local repository, stores them in the local
 * SQLite observation database, and optionally submits to vera-knowledge.
 *
 * Usage:
 *   node dist/bin/observe.js <repo-path> [options]
 *   node dist/bin/observe.js --repo <repo-path> [options]
 *
 * Run with --help for full usage.
 */

import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { observeGitCommits } from '../lib/git-observer.js';
import { ObservationStore } from '../lib/store.js';
import { loadIdentity } from '../lib/identity.js';
import { runSubmissionPipeline } from '../lib/pipeline.js';

// ── Usage string ──────────────────────────────────────────────────────────────

const USAGE = `\
Usage:
  observe <repo-path> [options]
  observe --repo <repo-path> [options]

Extracts git commits from a local git repository and stores them in the
local observation database. Optionally submits to vera-knowledge.

Arguments:
  <repo-path>            Path to the git repository (required)

Options:
  --repo <path>          Alternative way to specify the repository path
  --limit <n>            Max commits to extract (default: 50)
  --db <path>            SQLite DB file path (default: ./observations.db)
  --submit               Also submit observations to vera-knowledge
  --url <url>            vera-knowledge base URL (required if --submit)
                         Falls back to VERA_KNOWLEDGE_URL env var
  --help                 Print this help message and exit

Environment variables (required if --submit is set):
  SOMA_DID               Your Soma DID (e.g. did:soma:abc...)
  SOMA_PUBLIC_KEY_B64    Ed25519 public key, base64-encoded
  SOMA_SECRET_KEY_B64    Ed25519 secret key, base64-encoded
  VERA_KNOWLEDGE_URL     Default vera-knowledge URL (overridden by --url)

Examples:
  observe /path/to/repo
  observe /path/to/repo --limit 100 --db ./my.db
  observe /path/to/repo --submit --url http://localhost:3100
  observe --repo /path/to/repo --submit`;

// ── Helpers ───────────────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(USAGE);
}

function exitOk(): never {
  process.exit(0);
}

function exitError(message: string): never {
  console.error(`Error: ${message}`);
  console.error('');
  printUsage();
  process.exit(1);
}

// Wrapper so TypeScript control-flow sees a `never` return on parse failure.
function parseCLIArgs(argv: string[]): {
  values: {
    repo: string | undefined;
    limit: string | undefined;
    db: string | undefined;
    submit: boolean;
    url: string | undefined;
    help: boolean;
  };
  positionals: string[];
} {
  try {
    const result = parseArgs({
      args: argv,
      options: {
        repo:   { type: 'string' },
        limit:  { type: 'string' },
        db:     { type: 'string' },
        submit: { type: 'boolean', default: false },
        url:    { type: 'string' },
        help:   { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });

    return {
      values: {
        repo:   result.values['repo']   as string | undefined,
        limit:  result.values['limit']  as string | undefined,
        db:     result.values['db']     as string | undefined,
        submit: (result.values['submit'] as boolean | undefined) ?? false,
        url:    result.values['url']    as string | undefined,
        help:   (result.values['help']  as boolean | undefined) ?? false,
      },
      positionals: result.positionals,
    };
  } catch (err: unknown) {
    exitError(err instanceof Error ? err.message : String(err));
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  // No args → show usage and exit cleanly (not an error)
  if (argv.length === 0) {
    printUsage();
    exitOk();
  }

  const { values, positionals } = parseCLIArgs(argv);

  // --help
  if (values.help) {
    printUsage();
    exitOk();
  }

  // Resolve repo path: first positional arg takes precedence over --repo
  const repoRaw = positionals[0] ?? values.repo;
  if (!repoRaw) {
    exitError('repository path is required (provide as positional arg or --repo <path>)');
  }
  const repoPath = resolve(repoRaw);

  // --limit
  const limitRaw = values.limit;
  const limit = limitRaw !== undefined ? parseInt(limitRaw, 10) : 50;
  if (isNaN(limit) || limit < 1) {
    exitError(`--limit must be a positive integer, got: ${String(limitRaw)}`);
  }

  // --db
  const dbPath = resolve(values.db ?? './observations.db');

  // --submit + --url
  const doSubmit = values.submit;
  const veraUrl = values.url ?? process.env['VERA_KNOWLEDGE_URL'];

  // Validate --submit requirements up-front
  if (doSubmit) {
    const missing: string[] = [];
    if (!process.env['SOMA_DID'])              missing.push('SOMA_DID');
    if (!process.env['SOMA_PUBLIC_KEY_B64'])   missing.push('SOMA_PUBLIC_KEY_B64');
    if (!process.env['SOMA_SECRET_KEY_B64'])   missing.push('SOMA_SECRET_KEY_B64');
    if (missing.length > 0) {
      exitError(`--submit requires these environment variables to be set: ${missing.join(', ')}`);
    }
    if (!veraUrl) {
      exitError('--submit requires --url <url> or the VERA_KNOWLEDGE_URL environment variable');
    }
  }

  // ── Step 1: Extract git commits ──────────────────────────────────────────────

  let extractCount: number;
  let observations: ReturnType<typeof observeGitCommits>['observations'];

  try {
    const result = observeGitCommits({ repoPath, limit });
    extractCount = result.count;
    observations = result.observations;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(1);
  }

  console.log(`Commits found:        ${extractCount}`);

  // ── Step 2: Store in local DB ────────────────────────────────────────────────

  let stored: number;
  let store: ObservationStore;

  try {
    store = await ObservationStore.open(dbPath);
    stored = store.insertMany(observations, repoPath);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error writing to store at ${dbPath}: ${msg}`);
    process.exit(1);
  }

  const skipped = extractCount - stored;
  console.log(`New observations:     ${stored} stored, ${skipped} duplicate(s) skipped`);
  console.log(`DB:                   ${dbPath}`);

  // ── Step 3: Optionally submit to vera-knowledge ──────────────────────────────

  if (doSubmit) {
    // Close store here — runSubmissionPipeline opens its own handle
    store.close();

    const identity = loadIdentity({
      somaDid:       process.env['SOMA_DID']!,
      publicKeyB64:  process.env['SOMA_PUBLIC_KEY_B64']!,
      secretKeyB64:  process.env['SOMA_SECRET_KEY_B64']!,
    });

    const pipelineResult = await runSubmissionPipeline({
      dbPath,
      veraKnowledgeUrl: veraUrl!,
      identity,
    });

    if (pipelineResult.error) {
      console.error(`Submission error:     ${pipelineResult.error}`);
    }

    const batchSuffix = pipelineResult.batchId ? `, batch: ${pipelineResult.batchId}` : '';
    console.log(
      `Submitted:            ${pipelineResult.submitted} ok, ${pipelineResult.failed} failed${batchSuffix}`
    );

    if (pipelineResult.failed > 0 && pipelineResult.submitted === 0) {
      process.exit(1);
    }
  } else {
    store.close();
  }
}

main().catch((err: unknown) => {
  console.error(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
