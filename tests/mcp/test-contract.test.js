'use strict';

/**
 * Test contract meta-test (Phase 7, MCPO-06, D-11/D-13).
 *
 * Turns two review-catch failure classes into CI failures:
 *
 *   1. A NEW module dropped under lib/mcp/**\/*.js (excluding index.js
 *      registries — covered by their own registry-contract test files)
 *      without a matching tests/mcp/**\/*.test.js file — "silently
 *      untested module".
 *   2. A NEW tests/mcp/ subdirectory that contains test files but is not
 *      matched by any glob token in package.json's scripts.test — "test
 *      files CI silently never runs".
 *
 * Mapping convention (per 07-CONTEXT.md Claude's Discretion: filename-
 * based match is fine): lib/mcp/<subpath>/<name>.js must have a matching
 * tests/mcp/<subpath>/<name>.test.js.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const LIB_MCP_DIR = path.join(__dirname, '..', '..', 'lib', 'mcp');
const TESTS_MCP_DIR = __dirname;

// Mirrors lib/mcp/detectors/index.js's own `SKIP = new Set(['index.js'])`
// registry-skip convention (also lib/agents/index.js): registries are
// auto-discovery entry points, not units with their own fixture-driven
// tests — they're covered by tests/mcp/detectors/index.test.js instead.
const SKIP = new Set(['index.js']);

/**
 * Recursively collects every .js file under `dir`, excluding filenames in
 * `skipNames` (matched by basename, not full path — mirrors the registry
 * loader's literal-filename skip convention). Adapted from
 * lib/mcp/detectors/index.js's `fs.readdirSync(dir, { withFileTypes:true })`
 * + filter idiom, generalized to recurse into subdirectories.
 */
function collectJsFiles(dir, skipNames) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      out.push(...collectJsFiles(path.join(dir, entry.name), skipNames));
    } else if (entry.isFile() && entry.name.endsWith('.js') && !skipNames.has(entry.name)) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/**
 * Recursively collects every directory (including `rootDir` itself) under
 * `rootDir` that directly contains at least one `*.test.js` file.
 */
function collectTestDirs(rootDir) {
  const dirs = [];
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });
  const hasTestFileHere = entries.some(e => e.isFile() && e.name.endsWith('.test.js'));
  if (hasTestFileHere) dirs.push(rootDir);
  for (const entry of entries) {
    if (entry.isDirectory()) {
      dirs.push(...collectTestDirs(path.join(rootDir, entry.name)));
    }
  }
  return dirs;
}

describe('test contract (MCPO-06): every lib/mcp/**/*.js module has a matching test file', () => {
  it('every module under lib/mcp/ (excluding index.js registries) has a corresponding tests/mcp/** test file', () => {
    const modules = collectJsFiles(LIB_MCP_DIR, SKIP);
    assert.ok(modules.length > 0, 'sanity: expected at least one module under lib/mcp/');

    const missing = [];
    for (const modulePath of modules) {
      const relFromLibMcp = path.relative(LIB_MCP_DIR, modulePath); // e.g. detectors/typosquat.js
      const parsed = path.parse(relFromLibMcp);
      const expectedRel = path.join(parsed.dir, `${parsed.name}.test.js`); // e.g. detectors/typosquat.test.js
      const expectedTestPath = path.join(TESTS_MCP_DIR, expectedRel);
      if (!fs.existsSync(expectedTestPath)) {
        missing.push(`lib/mcp/${relFromLibMcp} -> expected tests/mcp/${expectedRel} (MISSING)`);
      }
    }

    assert.deepStrictEqual(missing, [],
      `every lib/mcp module needs a matching test file. Missing mappings:\n${missing.join('\n')}`);
  });

  it('package.json test glob covers every directory under tests/mcp/ that contains a .test.js file', () => {
    const pkg = require('../../package.json');
    const testScript = pkg.scripts && pkg.scripts.test;
    assert.strictEqual(typeof testScript, 'string', 'expected package.json scripts.test to be a string');

    const testDirs = collectTestDirs(TESTS_MCP_DIR);
    assert.ok(testDirs.length > 0, 'sanity: expected at least one tests/mcp subdirectory with test files');

    const projectRoot = path.join(__dirname, '..', '..');
    const uncovered = [];
    for (const dir of testDirs) {
      // e.g. "" (tests/mcp itself), "detectors", "parsers"
      const relFromProjectTestsMcp = path.relative(TESTS_MCP_DIR, dir);
      const globToken = relFromProjectTestsMcp === ''
        ? 'tests/mcp/*.test.js'
        : `tests/mcp/${relFromProjectTestsMcp.split(path.sep).join('/')}/*.test.js`;
      if (!testScript.includes(globToken)) {
        uncovered.push(`${path.relative(projectRoot, dir)} -> expected glob token "${globToken}" in scripts.test (MISSING)`);
      }
    }

    assert.deepStrictEqual(uncovered, [],
      `every tests/mcp subdirectory with test files must be covered by a package.json scripts.test glob token. Uncovered:\n${uncovered.join('\n')}`);
  });
});
