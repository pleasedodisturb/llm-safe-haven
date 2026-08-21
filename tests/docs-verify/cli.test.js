'use strict';

// Tests for scripts/docs-verify.js -- process-boundary behaviour (G-1570).
// Mirrors tests/traverse/validate-wave-spec.test.js's spawnSync pattern.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'docs-verify.js');
const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'mcp-rule-ids');
const EMPTY_CORPUS = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'empty-corpus');

function run(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('scripts/docs-verify.js -- process-boundary behaviour', () => {
  it('clean fixture root: exit 0, no line beginning with "fail"', () => {
    const res = run(['--root', path.join(FIXTURES_ROOT, 'clean')]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.ok(!/^fail\b/m.test(res.stdout), res.stdout);
  });

  it('defect fixture root: exit 1, stdout names the missing rule ID', () => {
    const res = run(['--root', path.join(FIXTURES_ROOT, 'defect')]);
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.ok(res.stdout.includes('fixture-detector/broad-inheritance'), res.stdout);
  });

  it('empty-corpus root: exit 2, incomplete reason names no-markdown-discovered', () => {
    const res = run(['--root', EMPTY_CORPUS]);
    assert.equal(res.status, 2, res.stdout + res.stderr);
    assert.ok(res.stdout.includes('no-markdown-discovered'), res.stdout);
  });

  it('unresolved-dynamic fixture root: exit 2, names an unresolved dynamic rule id', () => {
    const res = run(['--root', path.join(FIXTURES_ROOT, 'unresolved-dynamic')]);
    assert.equal(res.status, 2, res.stdout + res.stderr);
    assert.ok(/unresolved/i.test(res.stdout), res.stdout);
  });

  it('no-rules fixture root: exit 2 -- a zero-suffix detector must never present as clean', () => {
    const res = run(['--root', path.join(FIXTURES_ROOT, 'no-rules')]);
    assert.equal(res.status, 2, res.stdout + res.stderr);
  });

  it('null-detector-id fixture root: exit 2, names an unparseable detector id (WR-01, 21-REVIEW.md)', () => {
    const res = run(['--root', path.join(FIXTURES_ROOT, 'null-detector-id')]);
    assert.equal(res.status, 2, res.stdout + res.stderr);
    assert.ok(/could not determine the detector id/i.test(res.stdout), res.stdout);
    assert.ok(!/\bnull\//.test(res.stdout), `must never fabricate a null/<suffix> finding, got: ${res.stdout}`);
  });

  it('an unrecognized flag exits 2 and does not run a sweep', () => {
    const res = run(['--not-a-real-flag']);
    assert.equal(res.status, 2, res.stdout + res.stderr);
  });

  it('requiring the module sets no exitCode and exports { main, parseArgs }', () => {
    const res = spawnSync(
      process.execPath,
      ['-e', `const m=require('${SCRIPT.replace(/\\/g, '\\\\')}');if(typeof m.main!=='function'||typeof m.parseArgs!=='function')throw new Error('exports missing');`],
      { encoding: 'utf8', timeout: 10_000 }
    );
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});

describe('lib/docs-verify -- no subprocess or network primitive anywhere in production code', () => {
  it('scans lib/docs-verify/** and scripts/docs-verify.js for banned primitives', () => {
    const bad = /child_process|execSync|execFileSync|spawnSync|https?\.request|fetch\(/;
    function walk(dir) {
      return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        const p = path.join(dir, e.name);
        return e.isDirectory() ? walk(p) : [p];
      });
    }
    const files = [...walk(path.join(__dirname, '..', '..', 'lib', 'docs-verify')), SCRIPT];
    assert.ok(files.length >= 5, `non-vacuity: expected at least 5 scanned files, got ${files.length}`);
    for (const f of files) {
      const text = fs.readFileSync(f, 'utf8');
      assert.ok(!bad.test(text), `subprocess or network primitive found in ${f}`);
    }
  });
});

describe('lib/docs-verify/index.js -- loadChecks() registry', () => {
  const { loadChecks } = require('../../lib/docs-verify/index.js');

  it('returns { checks, errors }, non-vacuous, byte-sorted by id, no load errors against the real registry', () => {
    const r = loadChecks();
    assert.ok(!Array.isArray(r), 'loadChecks must return {checks,errors}, not a bare array');
    assert.ok(Array.isArray(r.checks) && Array.isArray(r.errors));
    assert.ok(r.checks.length > 0, 'non-vacuity: no checks loaded');
    assert.deepEqual(r.errors, [], `unexpected check load errors: ${JSON.stringify(r.errors)}`);
    const ids = r.checks.map((c) => c.id);
    const sorted = ids.slice().sort();
    assert.deepEqual(ids, sorted, `registry ids are not byte-sorted: ${ids.join(',')}`);
  });

  it('a candidate .js that throws on require() is recorded in errors, never silently skipped', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-docs-verify-registry-'));
    try {
      fs.writeFileSync(path.join(tmp, 'broken.js'), "throw new Error('boom, this module is deliberately broken');\n");
      fs.writeFileSync(
        path.join(tmp, 'good.js'),
        "module.exports = { id: 'good-check', run: () => [] };\n"
      );
      const r = loadChecks(tmp);
      assert.equal(r.checks.length, 1, `expected exactly 1 valid check loaded, got ${r.checks.length}`);
      assert.equal(r.checks[0].id, 'good-check');
      assert.equal(r.errors.length, 1, `expected exactly 1 load error, got ${JSON.stringify(r.errors)}`);
      assert.equal(r.errors[0].file, 'broken.js');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
