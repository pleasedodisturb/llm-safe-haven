'use strict';

// Tests for lib/docs-verify/count-claims.js (Check 7, G-1570, GUARD-01, D-05).
//
// Pinned grammar: see .planning/phases/21-doc-drift-guard/21-04-PLAN.md,
// Task 2. Read that section before editing this file.
//
// D-05: the 7th check, added so DOC-06 is mechanically graded. Grades
// count claims against canonical repository counts (agent modules, MCP
// parsers, MCP detectors, hardening-guide files) via a FROZEN ALLOWLIST of
// bindable claim shapes -- never a blocklist of phrasings to ignore. An
// unbindable claim in a scoped doc is a warn, never a fail. File-role
// scoping (SCOPED_DOCS) exempts third-party catalogue and narrative docs.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const countClaims = require('../../lib/docs-verify/count-claims.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'count-claims');
const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'docs-verify.js');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [countClaims]);
}

function runCli(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('count-claims.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(countClaims.id, 'count-claims');
    assert.equal(typeof countClaims.run, 'function');
    assert.equal(typeof countClaims.wordToNumber, 'function');
    assert.ok(Array.isArray(countClaims.CLAIM_REGISTRY));
    assert.ok(countClaims.CLAIM_REGISTRY.length > 0, 'non-vacuity: claim registry must not be empty');
    assert.ok(Array.isArray(countClaims.SCOPED_DOCS));
    assert.ok(countClaims.SCOPED_DOCS.length > 0, 'non-vacuity: scoped-docs list must not be empty');
    assert.ok(countClaims.CANONICAL_SOURCES && typeof countClaims.CANONICAL_SOURCES === 'object');
    assert.ok(Object.keys(countClaims.CANONICAL_SOURCES).length > 0, 'non-vacuity: canonical sources must not be empty');
  });

  it('never runs a documented command or opens a network connection', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'count-claims.js'), 'utf8');
    const bad = /child_process|execSync|execFileSync|spawnSync|spawn\(|https?\.request|fetch\(/;
    assert.ok(!bad.test(src), 'count-claims.js must contain no subprocess or network primitive');
  });
});

describe('count-claims.js -- wordToNumber', () => {
  it('maps a digit string', () => {
    assert.equal(countClaims.wordToNumber('7'), 7);
  });

  it('maps an English number word', () => {
    assert.equal(countClaims.wordToNumber('seven'), 7);
  });

  it('is case-insensitive for a number word', () => {
    assert.equal(countClaims.wordToNumber('Eight'), 8);
  });

  it('returns null for an unknown token', () => {
    assert.equal(countClaims.wordToNumber('elevendy'), null);
  });

  it('returns null for a non-number prose word', () => {
    assert.equal(countClaims.wordToNumber('the'), null);
  });
});

describe('count-claims.js -- SCOPED_DOCS file-role scoping', () => {
  it('includes the root README', () => {
    assert.ok(countClaims.SCOPED_DOCS.includes('README.md'));
  });

  it('excludes the third-party catalogue doc', () => {
    assert.ok(!countClaims.SCOPED_DOCS.includes('docs/references.md'));
  });
});

describe('count-claims.js -- fixture pair (defect)', () => {
  it('Defect A: an MCP agent count claim that differs from the canonical MCP-parser count', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'count-claims' && f.severity === 'fail' && f.message.includes("'5'"));
    assert.ok(hit, `Defect A finding missing, got: ${JSON.stringify(findings)}`);
  });

  it('Defect B: an English-number-word hardening-guide count claim that differs from the canonical count', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'count-claims' && f.severity === 'fail' && f.message.includes('seven'));
    assert.ok(hit, `Defect B finding missing, got: ${JSON.stringify(findings)}`);
  });

  it('never reports the third-party catalogue doc (Control B, file-role scoping)', () => {
    const { findings } = sweep('defect');
    assert.ok(!findings.some((f) => f.file === 'docs/references.md'), 'third-party catalogue must never be graded');
  });
});

describe('count-claims.js -- fixture pair (clean, must-still-pass controls)', () => {
  it('Control A: matching claims produce zero fail findings', () => {
    const { findings } = sweep('clean');
    const fails = findings.filter((f) => f.check === 'count-claims' && f.severity === 'fail');
    assert.deepEqual(fails, [], `clean fixture must have zero fail findings, got: ${JSON.stringify(fails)}`);
  });

  it('Control B: the third-party catalogue doc is never graded', () => {
    const { findings } = sweep('clean');
    assert.ok(!findings.some((f) => f.file === 'docs/references.md'));
  });

  it('unbindable claim: produces a warn, not a fail, and does not drive a nonzero exit alone', () => {
    const { findings, incomplete } = sweep('clean');
    const warn = findings.find((f) => f.check === 'count-claims' && f.severity === 'warn');
    assert.ok(warn, `expected an unbindable-claim warn finding, got: ${JSON.stringify(findings)}`);
    const { tallySeverities, computeExit } = require('../../lib/docs-verify/index.js');
    const severityCounts = tallySeverities(findings);
    assert.equal(computeExit({ severityCounts, incomplete }), 0, 'a root whose only finding is a warn must exit 0');
  });
});

describe('count-claims.js -- zero and one canonical counts (synthetic context)', () => {
  function fakeContext({ mdFiles, listing }) {
    return {
      root: '/fake',
      pkg: { name: 'fake', version: '0.0.0' },
      mdFiles,
      readText: () => ({ text: '' }),
      listFiles: (dir) => listing(dir),
      errors: [],
    };
  }

  it('a canonical source that counts zero files still produces a real comparison (fail), never a silent skip', () => {
    const doc = {
      path: 'README.md',
      abs: '/fake/README.md',
      text: '`llm-safe-haven-fixture` detects and hardens 1 agents.',
    };
    const ctx = fakeContext({
      mdFiles: [doc],
      listing: (dir) => (dir === 'lib/agents' ? { files: [] } : { files: [] }),
    });
    const findings = countClaims.run(ctx);
    const hit = findings.find((f) => f.severity === 'fail');
    assert.ok(hit, `a zero-count canonical source must still be reported against, got: ${JSON.stringify(findings)}`);
    assert.ok(hit.message.includes('0'), `message must name the actual zero count, got: ${hit.message}`);
  });

  it('a claim of one against a canonical count of one passes', () => {
    const doc = {
      path: 'README.md',
      abs: '/fake/README.md',
      text: 'detects and hardens 1 agents.',
    };
    const ctx = fakeContext({
      mdFiles: [doc],
      listing: (dir) => (dir === 'lib/agents' ? { files: ['lib/agents/only.js'] } : { files: [] }),
    });
    const findings = countClaims.run(ctx);
    assert.deepEqual(findings, []);
  });
});

describe('count-claims.js -- number words and digits are equivalent', () => {
  function fakeContext(text, listing) {
    return {
      root: '/fake',
      pkg: { name: 'fake', version: '0.0.0' },
      mdFiles: [{ path: 'README.md', abs: '/fake/README.md', text }],
      readText: () => ({ text: '' }),
      listFiles: (dir) => listing(dir),
      errors: [],
    };
  }

  it('grades a digit claim and a word claim identically against the same canonical count', () => {
    const listing = (dir) => (dir === 'lib/agents' ? { files: ['lib/agents/a.js', 'lib/agents/b.js'] } : { files: [] });
    const digitFindings = countClaims.run(fakeContext('detects and hardens 2 agents.', listing));
    const wordFindings = countClaims.run(fakeContext('detects and hardens two agents.', listing));
    assert.deepEqual(digitFindings, []);
    assert.deepEqual(wordFindings, []);
  });
});

describe('count-claims.js -- CANONICAL_SOURCES: a directory that cannot be listed throws (incomplete, never a guessed zero)', () => {
  it('run() throws when a canonical source directory cannot be listed', () => {
    const ctx = {
      root: '/fake',
      pkg: { name: 'fake', version: '0.0.0' },
      mdFiles: [{ path: 'README.md', abs: '/fake/README.md', text: 'detects and hardens 2 agents.' }],
      readText: () => ({ text: '' }),
      listFiles: () => ({ error: 'EACCES' }),
      errors: [],
    };
    assert.throws(() => countClaims.run(ctx), /count-claims/);
  });
});

describe('count-claims.js -- CLI process-boundary behaviour', () => {
  it('the defect fixture: exit 1, stdout names the "count-claims" check', () => {
    const res = runCli(['--root', path.join(FIXTURES_ROOT, 'defect')]);
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /\bcount-claims\b/);
  });

  it('the clean fixture: exit 0', () => {
    const res = runCli(['--root', path.join(FIXTURES_ROOT, 'clean')]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});

describe("count-claims.js -- registry membership (never exactly-seven -- that is 21-05's)", () => {
  it('loadChecks() includes both "commands" and "count-claims" with zero load errors', () => {
    const { loadChecks } = require('../../lib/docs-verify/index.js');
    const { checks, errors } = loadChecks();
    assert.deepEqual(errors, []);
    assert.ok(checks.length > 0, 'non-vacuity: registry must not be empty');
    const ids = checks.map((c) => c.id);
    for (const want of ['commands', 'count-claims']) {
      assert.ok(ids.includes(want), `missing check: ${want}, got: ${ids.join(',')}`);
    }
  });
});
