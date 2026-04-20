#!/usr/bin/env node
/**
 * CLI wrapper for the offline fork ceremony — establishes cryptographic
 * parent-child lineage between two Soma hearts.
 *
 * Secrets are read exclusively from environment variables (never CLI args).
 * No network requests are made. All key material is wiped by the underlying
 * ceremony library after use.
 *
 * @module soma-heart-fork
 */

import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { forkCeremony } from '../fork-ceremony.js';

const USAGE = `Usage: soma-heart-fork [options]

Establish cryptographic parent-child lineage between two Soma hearts.

Options:
  --parent-blob <path>         Path to parent heart blob file
  --parent-secret-env <name>   Name of env var holding parent secret
  --child-blob <path>          Path to child heart blob file (optional if --child-new)
  --child-new                  Create a fresh child heart instead of using existing blob
  --child-secret-env <name>    Name of env var holding child secret
  --capabilities <caps>        Comma-separated capability strings
  --ttl <duration>             Duration string: 90d, 24h, 1h, none
  --budget <number>            Budget credits
  --output <path>              Output path for patched child blob (defaults to --child-blob path)
  --help                       Print usage and exit
`;

function parseTtl(s: string): number | undefined {
  if (s === 'none') return undefined;
  const m = s.match(/^(\d+)(d|h|m|s)$/);
  if (!m) throw new Error(`invalid ttl format: ${s} (use 90d, 24h, 30m, 60s, or none)`);
  const n = parseInt(m[1], 10);
  const unit = m[2];
  const multipliers: Record<string, number> = { d: 86400000, h: 3600000, m: 60000, s: 1000 };
  return n * multipliers[unit];
}

try {
  const { values } = parseArgs({
    options: {
      'parent-blob': { type: 'string' },
      'parent-secret-env': { type: 'string' },
      'child-blob': { type: 'string' },
      'child-new': { type: 'boolean', default: false },
      'child-secret-env': { type: 'string' },
      'capabilities': { type: 'string' },
      'ttl': { type: 'string' },
      'budget': { type: 'string' },
      'output': { type: 'string' },
      'help': { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values['help']) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  // Validate required flags
  if (!values['parent-blob']) {
    process.stderr.write('error: --parent-blob is required\n');
    process.exit(1);
  }
  if (!values['parent-secret-env']) {
    process.stderr.write('error: --parent-secret-env is required\n');
    process.exit(1);
  }
  if (!values['child-secret-env']) {
    process.stderr.write('error: --child-secret-env is required\n');
    process.exit(1);
  }
  if (!values['child-blob'] && !values['child-new']) {
    process.stderr.write('error: either --child-blob or --child-new is required\n');
    process.exit(1);
  }
  if (values['child-new'] && !values['output'] && !values['child-blob']) {
    process.stderr.write('error: --output is required when using --child-new\n');
    process.exit(1);
  }

  // Read secrets from env vars
  const parentSecret = process.env[values['parent-secret-env']!];
  if (!parentSecret) {
    process.stderr.write(`error: env var ${values['parent-secret-env']} is not set\n`);
    process.exit(1);
  }

  const childSecret = process.env[values['child-secret-env']!];
  if (!childSecret) {
    process.stderr.write(`error: env var ${values['child-secret-env']} is not set\n`);
    process.exit(1);
  }

  // Read blobs from disk
  const parentBlob = readFileSync(values['parent-blob']!, 'utf8');
  const childBlob = values['child-blob'] ? readFileSync(values['child-blob']!, 'utf8') : undefined;

  // Parse optional flags
  const ttl = values['ttl'] ? parseTtl(values['ttl']!) : undefined;

  const capabilities = values['capabilities']
    ? values['capabilities']!.split(',').filter(s => s.length > 0)
    : [];

  let budget: number | undefined;
  if (values['budget']) {
    budget = parseInt(values['budget']!, 10);
    if (isNaN(budget) || budget <= 0) {
      process.stderr.write(`error: --budget must be a positive number, got: ${values['budget']}\n`);
      process.exit(1);
    }
  }

  // Run ceremony
  const result = forkCeremony({
    parentBlob,
    parentSecret,
    childBlob,
    childSecret,
    capabilities: capabilities.length > 0 ? capabilities : undefined,
    ttl,
    budgetCredits: budget,
  });

  // Write output
  const outputPath = values['output'] ?? values['child-blob']!;
  writeFileSync(outputPath, result.childBlob, 'utf8');

  // Print summary
  process.stdout.write([
    `parentDid:     ${result.parentDid}`,
    `childDid:      ${result.childDid}`,
    `rootDid:       ${result.rootDid}`,
    `chainLength:   ${result.chainLength}`,
    `certificateId: ${result.certificateId}`,
    `output:        ${outputPath}`,
    '',
  ].join('\n'));
} catch (err) {
  process.stderr.write(`error: ${(err as Error).message}\n`);
  process.exit(1);
}
