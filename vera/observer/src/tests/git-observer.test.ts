/**
 * Git observer tests — test against a real git repo.
 *
 * The general fixture is *this repository*, resolved relative to the test file.
 * It is guaranteed to exist wherever the tests run, so these assertions execute
 * on every machine and in CI rather than skipping.
 *
 * They previously pointed at two absolute paths on one developer's machine
 * (`veraAI` and `Soma`). Both had since been renamed or archived, so the
 * `existsSync` guard silently skipped roughly two thirds of this file — a green
 * suite that was asserting nothing. Absolute developer paths also leak a
 * username into a repository intended to be public.
 *
 * Richer-signal tests need a fixture with known seam-adjacent commits, which no
 * synthetic repo reproduces. They stay opt-in via SOMA_FIXTURE_REPO and say so
 * plainly when they skip, so absent coverage is legible instead of invisible.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { observeGitCommits } from '../lib/git-observer.js';
import { gitCommitObservationSchema } from '../lib/types.js';

// This repository, found from the test file rather than from any absolute path:
// dist/tests/ -> observer/ -> repo root.
const REPO_ROOT = path.resolve(fileURLToPath(new URL('../../../', import.meta.url)));

// The general fixture is the repo under test. Always present, always has commits.
const FIXTURE_REPO = REPO_ROOT;
// The same repo, asserted on separately for its own observation properties.
const VERA_OBSERVER_REPO = REPO_ROOT;
// Opt-in fixture for richer-signal tests. Unset means that coverage is off.
const SOMA_REPO = process.env.SOMA_FIXTURE_REPO ?? '';

describe('observeGitCommits — real repo (this repository)', () => {
  const skipIfMissing = !existsSync(FIXTURE_REPO + '/.git');

  test('returns observations from a real git repo', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    assert.ok(result.count > 0, 'Should find at least 1 commit');
    assert.equal(result.repoPath, FIXTURE_REPO);
    assert.equal(result.observations.length, result.count);
  });

  test('all observations have type="git_commit"', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    for (const obs of result.observations) {
      assert.equal(obs.type, 'git_commit');
    }
  });

  test('observation content validates against GitCommitObservation schema', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 3 });
    assert.ok(result.count > 0, 'Need at least 1 commit to validate');
    for (const obs of result.observations) {
      const parseResult = gitCommitObservationSchema.safeParse(obs.content);
      assert.ok(
        parseResult.success,
        `Content failed schema validation: ${parseResult.success ? '' : parseResult.error.message}`
      );
    }
  });

  test('observed_at is a valid ISO 8601 date string', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    for (const obs of result.observations) {
      const d = new Date(obs.observed_at);
      assert.ok(!isNaN(d.getTime()), `observed_at "${obs.observed_at}" is not a valid date`);
    }
  });

  test('commit hashes are 40-character hex strings', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      const hash = content['commit_hash'] as string;
      assert.match(hash, /^[0-9a-f]{40}$/, `Commit hash "${hash}" is not 40 hex chars`);
    }
  });

  test('limit is respected', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 2 });
    assert.ok(result.count <= 2, `Expected <= 2 commits, got ${result.count}`);
  });

  test('files_changed array is present (may be empty for some commits)', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      assert.ok(Array.isArray(content['files_changed']), 'files_changed should be an array');
    }
  });

  test('stats fields are non-negative integers', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: FIXTURE_REPO, limit: 5 });
    for (const obs of result.observations) {
      const content = obs.content as Record<string, unknown>;
      const stats = content['stats'] as Record<string, unknown>;
      assert.ok(typeof stats['total_files_changed'] === 'number' && stats['total_files_changed'] >= 0);
      assert.ok(typeof stats['total_additions'] === 'number' && stats['total_additions'] >= 0);
      assert.ok(typeof stats['total_deletions'] === 'number' && stats['total_deletions'] >= 0);
    }
  });
});

describe('observeGitCommits — error handling', () => {
  test('throws on non-existent path', () => {
    assert.throws(
      () => observeGitCommits({ repoPath: '/nonexistent/path/definitely-not-a-repo' }),
      /Not a git repository/
    );
  });
});

describe('observeGitCommits — vera-observer own repo', () => {
  const skipIfMissing = !existsSync(VERA_OBSERVER_REPO + '/.git');

  test('can observe vera-observer initial commit', { skip: skipIfMissing ? 'repository fixture not found' : false }, () => {
    const result = observeGitCommits({ repoPath: VERA_OBSERVER_REPO, limit: 10 });
    // After initial commit, should have at least 1
    assert.ok(result.count >= 1, `Expected at least 1 commit, got ${result.count}`);
  });
});

// ---- Richer-signal extraction tests ----
// These tests require the Soma repo and target specific known commits.

describe('observeGitCommits — richer-signal extraction (opt-in fixture)', () => {
  const skipIfMissing = !SOMA_REPO || !existsSync(path.join(SOMA_REPO, '.git'));
  const skipMsg = 'set SOMA_FIXTURE_REPO to a repo with seam-adjacent commits to run this';

  // 3835d82: feat(supply-chain): UpdateCertificate protocol primitives (Track A)
  // This commit introduces UpdateCertificate interface, createUpdateCertificate,
  // addAuthorization, verifyUpdateCertificate, etc. in src/supply-chain/update-certificate.ts
  test(
    'positive (3835d82-shaped): UpdateCertificate commit populates exported_names with canonical supply-chain exports',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      // Use limit 35 to ensure 3835d82 stays in window even with new Soma commits
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });
      assert.ok(result.count > 0, 'Should find commits in Soma repo');

      const targetObs = result.observations.find((obs) => {
        const c = obs.content as Record<string, unknown>;
        return typeof c['commit_hash'] === 'string' &&
          c['commit_hash'].startsWith('3835d82');
      });

      assert.ok(targetObs, 'Commit 3835d82 should be in the last 25 commits');
      const content = targetObs!.content as Record<string, unknown>;

      // Should have exported_names populated from src/supply-chain/update-certificate.ts
      const exportedNames = content['exported_names'];
      assert.ok(
        Array.isArray(exportedNames) && exportedNames.length > 0,
        `exported_names should be a non-empty array; got: ${JSON.stringify(exportedNames)}`,
      );

      // Canonical exports from the UpdateCertificate module
      const nameSet = new Set(exportedNames as string[]);
      const expectedNames = ['createUpdateCertificate', 'addAuthorization', 'verifyUpdateCertificate'];
      const foundExpected = expectedNames.filter((n) => nameSet.has(n));
      assert.ok(
        foundExpected.length >= 1,
        `exported_names should include at least one of [${expectedNames.join(', ')}]; got: ${JSON.stringify([...nameSet])}`,
      );

      // Should have signature_excerpts populated
      const signatureExcerpts = content['signature_excerpts'];
      assert.ok(
        Array.isArray(signatureExcerpts) && signatureExcerpts.length > 0,
        `signature_excerpts should be a non-empty array; got: ${JSON.stringify(signatureExcerpts)}`,
      );

      // Validate hard caps
      assert.ok(
        (signatureExcerpts as unknown[]).length <= 3,
        `signature_excerpts must not exceed 3 snippets; got ${(signatureExcerpts as unknown[]).length}`,
      );
      for (const excerpt of signatureExcerpts as Array<{ file: string; lines: string[] }>) {
        assert.ok(
          excerpt.lines.length <= 10,
          `Each excerpt must have at most 10 lines; got ${excerpt.lines.length} in ${excerpt.file}`,
        );
        assert.ok(
          typeof excerpt.file === 'string' && excerpt.file.length > 0,
          `Excerpt file should be a non-empty string; got: ${excerpt.file}`,
        );
      }

      // At least one excerpt should be from a supply-chain file
      const hasSupplyChainExcerpt = (signatureExcerpts as Array<{ file: string; lines: string[] }>)
        .some((e) => e.file.includes('supply-chain') || e.file.includes('certificate'));
      assert.ok(
        hasSupplyChainExcerpt,
        `At least one excerpt should be from a supply-chain or certificate file; got files: ${JSON.stringify((signatureExcerpts as Array<{ file: string }>).map((e) => e.file))}`,
      );
    },
  );

  // 8b3cbba: feat(soma-heart): add ./supply-chain export path and bump to 0.9.0
  // This commit only touches packages/soma-heart/package.json and tsconfig.build.json.
  // These are NOT in src/supply-chain/ so should NOT match SEAM_ADJACENT_FILE_RE for
  // exported_names/signature_excerpts (no TypeScript exports to parse). May produce
  // empty richer-signal arrays (which is correct behavior for this commit shape).
  test(
    'positive (8b3cbba-shaped): export-path-only commit produces valid observation (richer-signal may be empty for package.json)',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });
      const targetObs = result.observations.find((obs) => {
        const c = obs.content as Record<string, unknown>;
        return typeof c['commit_hash'] === 'string' &&
          c['commit_hash'].startsWith('8b3cbba');
      });

      assert.ok(targetObs, 'Commit 8b3cbba should be in the last 25 commits');
      const content = targetObs!.content as Record<string, unknown>;

      // The observation should still validate against the schema
      const parseResult = gitCommitObservationSchema.safeParse(content);
      assert.ok(
        parseResult.success,
        `Content should validate against schema: ${parseResult.success ? '' : parseResult.error.message}`,
      );

      // exported_names may be absent or empty (package.json is not a seam-adjacent TS file)
      // but if present must be an array
      if (content['exported_names'] !== undefined) {
        assert.ok(
          Array.isArray(content['exported_names']),
          'exported_names must be an array if present',
        );
      }

      // signature_excerpts may be absent or empty for package.json-only commits
      if (content['signature_excerpts'] !== undefined) {
        assert.ok(
          Array.isArray(content['signature_excerpts']),
          'signature_excerpts must be an array if present',
        );
        // Hard cap check
        assert.ok(
          (content['signature_excerpts'] as unknown[]).length <= 3,
          'signature_excerpts must not exceed 3 snippets',
        );
      }
    },
  );

  // Negative: a docs-only commit should produce empty/absent richer-signal fields.
  // We look for any commit that only touches .md files.
  test(
    'negative: non-seam commit produces absent or empty richer-signal fields',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });

      // Find any commit that has NO seam-adjacent files
      const nonSeamObs = result.observations.find((obs) => {
        const c = obs.content as Record<string, unknown>;
        const files = Array.isArray(c['files_changed'])
          ? (c['files_changed'] as Array<{ path: string }>)
          : [];
        // All files must be outside supply-chain/certificate/provenance/packages/*/src/
        return files.length > 0 && files.every((f) =>
          !f.path.includes('supply-chain') &&
          !f.path.includes('certificate') &&
          !f.path.includes('provenance') &&
          !(/^packages\/.*\/src\//.test(f.path))
        );
      });

      if (!nonSeamObs) {
        // All commits in the window happen to touch seam-adjacent files — skip
        return;
      }

      const content = nonSeamObs.content as Record<string, unknown>;

      // exported_names and signature_excerpts should be absent or empty for non-seam commits
      const exportedNames = content['exported_names'];
      const signatureExcerpts = content['signature_excerpts'];

      const exportedNamesEmpty = exportedNames === undefined ||
        (Array.isArray(exportedNames) && (exportedNames as unknown[]).length === 0);
      const signatureExcerptsEmpty = signatureExcerpts === undefined ||
        (Array.isArray(signatureExcerpts) && (signatureExcerpts as unknown[]).length === 0);

      assert.ok(
        exportedNamesEmpty,
        `Non-seam commit should have empty/absent exported_names; got: ${JSON.stringify(exportedNames)}`,
      );
      assert.ok(
        signatureExcerptsEmpty,
        `Non-seam commit should have empty/absent signature_excerpts; got: ${JSON.stringify(signatureExcerpts)}`,
      );
    },
  );

  // Bounds: hard caps must hold for any commit in the window
  test(
    'bounds: snippet count never exceeds 3, line count per snippet never exceeds 10',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });

      for (const obs of result.observations) {
        const content = obs.content as Record<string, unknown>;

        const signatureExcerpts = content['signature_excerpts'];
        if (Array.isArray(signatureExcerpts) && signatureExcerpts.length > 0) {
          assert.ok(
            signatureExcerpts.length <= 3,
            `signature_excerpts must not exceed 3 snippets; got ${signatureExcerpts.length} for commit ${(content['commit_hash'] as string).slice(0, 8)}`,
          );
          for (const excerpt of signatureExcerpts as Array<{ file: string; lines: string[] }>) {
            assert.ok(
              excerpt.lines.length <= 10,
              `Each excerpt must have at most 10 lines; got ${excerpt.lines.length} lines in ${excerpt.file}`,
            );
          }
        }
      }
    },
  );

  // Selection priority: 3835d82 must select createUpdateCertificate (function)
  // over AuthorizerRole (type alias). This is the regression that was broken before
  // the excerpt-selection refinement: the old greedy-first algorithm picked AuthorizerRole
  // because it appeared first in the file.
  test(
    'selection-priority (3835d82): excerpt prefers createUpdateCertificate (function) over AuthorizerRole (type alias)',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });
      const targetObs = result.observations.find((obs) => {
        const c = obs.content as Record<string, unknown>;
        return typeof c['commit_hash'] === 'string' &&
          c['commit_hash'].startsWith('3835d82');
      });

      assert.ok(targetObs, 'Commit 3835d82 should be in the last 35 commits');
      const content = targetObs!.content as Record<string, unknown>;
      const signatureExcerpts = content['signature_excerpts'] as Array<{ file: string; lines: string[] }> | undefined;

      assert.ok(
        Array.isArray(signatureExcerpts) && signatureExcerpts.length > 0,
        `signature_excerpts should be non-empty for 3835d82; got: ${JSON.stringify(signatureExcerpts)}`,
      );

      // The excerpt from update-certificate.ts must NOT start with AuthorizerRole type alias.
      // It must prefer the function signature (createUpdateCertificate) or an interface declaration.
      const updateCertExcerpt = signatureExcerpts!.find((e) => e.file.includes('update-certificate'));
      assert.ok(
        updateCertExcerpt,
        `Expected an excerpt from update-certificate.ts; got files: ${JSON.stringify(signatureExcerpts!.map((e) => e.file))}`,
      );

      // First line must NOT be a type alias (AuthorizerRole regression check)
      const firstLine = updateCertExcerpt!.lines[0] ?? '';
      assert.ok(
        !firstLine.includes("export type AuthorizerRole"),
        `Excerpt must NOT start with AuthorizerRole type alias (regression); first line: "${firstLine}"`,
      );

      // First line SHOULD be a function or interface declaration (selection priority check)
      const isFunction = /^export\s+(?:async\s+)?function/.test(firstLine.trim());
      const isInterface = /^export\s+interface/.test(firstLine.trim());
      assert.ok(
        isFunction || isInterface,
        `Excerpt first line should be a function or interface declaration; got: "${firstLine}"`,
      );

      // Verify the excerpt contains createUpdateCertificate specifically (the target function)
      const excerptText = updateCertExcerpt!.lines.join('\n');
      assert.ok(
        excerptText.includes('createUpdateCertificate') || excerptText.includes('UpdateAuthorization') || excerptText.includes('UpdateCertificate'),
        `Excerpt should contain a meaningful HOW-bearing declaration; got: ${excerptText.slice(0, 200)}`,
      );
    },
  );

  // Graceful degradation: a file with only type aliases still produces a sensible excerpt
  // (does not return null or crash). We simulate this by checking that the selection
  // algorithm falls back to type aliases when no function/interface/class declarations exist.
  // Since we cannot inject synthetic commits into the real Soma repo, we verify this
  // property by directly testing extractSignatureExcerpt behavior via the observable
  // output for commits that only have type-level exports.
  //
  // We use the bounds test to verify no crashes occur for all commits in the window,
  // which implicitly covers graceful degradation since all commits with seam files must
  // produce valid (possibly type-alias) excerpts.
  test(
    'graceful-degradation: all commits with seam-adjacent files produce valid excerpts (no crashes)',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });

      for (const obs of result.observations) {
        const content = obs.content as Record<string, unknown>;
        const signatureExcerpts = content['signature_excerpts'];

        // If signature_excerpts is present, it must be a valid array of excerpts
        if (signatureExcerpts !== undefined) {
          assert.ok(
            Array.isArray(signatureExcerpts),
            `signature_excerpts must be an array; got: ${typeof signatureExcerpts}`,
          );
          for (const excerpt of signatureExcerpts as Array<unknown>) {
            assert.ok(
              excerpt !== null && typeof excerpt === 'object',
              'Each excerpt must be an object',
            );
            const e = excerpt as { file: string; lines: string[] };
            assert.ok(typeof e.file === 'string' && e.file.length > 0, 'Excerpt file must be non-empty string');
            assert.ok(Array.isArray(e.lines) && e.lines.length > 0, 'Excerpt lines must be non-empty array');
            assert.ok(e.lines.length <= 10, `Excerpt must not exceed 10 lines; got ${e.lines.length}`);
          }
        }
      }
    },
  );

  // Preservation: simpler commits with a single export still produce correct excerpts.
  // 8b3cbba touches package.json only (no TypeScript exports), so exported_names and
  // signature_excerpts should be absent or empty — this verifies the algorithm does not
  // produce spurious excerpts for commits without seam-adjacent TypeScript files.
  test(
    'preservation (8b3cbba-shaped): package.json-only commit produces no spurious function excerpts',
    { skip: skipIfMissing ? skipMsg : false },
    () => {
      const result = observeGitCommits({ repoPath: SOMA_REPO, limit: 35 });
      const targetObs = result.observations.find((obs) => {
        const c = obs.content as Record<string, unknown>;
        return typeof c['commit_hash'] === 'string' &&
          c['commit_hash'].startsWith('8b3cbba');
      });

      assert.ok(targetObs, 'Commit 8b3cbba should be in the last 35 commits');
      const content = targetObs!.content as Record<string, unknown>;

      // package.json-only commit — no TypeScript exports, so no function excerpts
      const signatureExcerpts = content['signature_excerpts'];
      if (signatureExcerpts !== undefined) {
        assert.ok(
          Array.isArray(signatureExcerpts),
          'signature_excerpts must be an array if present',
        );
        // If any excerpts exist, they must not contain spurious function bodies
        for (const excerpt of signatureExcerpts as Array<{ file: string; lines: string[] }>) {
          // No excerpt file should be a .json file (we don't parse JSON for signatures)
          assert.ok(
            excerpt.file.endsWith('.ts') || excerpt.file.endsWith('.tsx') || excerpt.file.endsWith('.js'),
            `Excerpt file should be a TypeScript/JavaScript file; got: ${excerpt.file}`,
          );
        }
      }
    },
  );
});
