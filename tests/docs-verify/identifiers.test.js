'use strict';

// Tests for lib/docs-verify/identifiers.js (Check 1, G-1570, GUARD-01).
//
// Pinned grammar (see .planning/phases/21-doc-drift-guard/21-02-PLAN.md,
// Task 1): "exists" means raw source-text presence in hooks/**/*.js and
// lib/**/*.js -- never require()-and-inspect-exports (21-RESEARCH.md
// Pitfall 2). Scoping is by file role (SCOPED_DOCS), never a hand-
// maintained token blocklist (21-RESEARCH.md Pitfall 1). The function-call
// grammar accepts ANY argument list, not only an empty one -- an
// empty-parens-only grammar would silently ungrade `main(argv)`-style
// claims, which is the documented common form in this repo.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const identifiers = require('../../lib/docs-verify/identifiers.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'identifiers');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [identifiers]);
}

describe('identifiers.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(identifiers.id, 'identifiers');
    assert.equal(typeof identifiers.run, 'function');
    assert.equal(typeof identifiers.extractClaims, 'function');
    assert.equal(typeof identifiers.identifierExistsInSource, 'function');
    assert.ok(Array.isArray(identifiers.SCOPED_DOCS));
  });
});

describe('identifiers.js -- extractClaims grammar', () => {
  it('extracts an UPPER_SNAKE_CASE claim', () => {
    const claims = identifiers.extractClaims('edit the `BLOCKED_PATTERNS` array');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].identifier, 'BLOCKED_PATTERNS');
    assert.equal(claims[0].line, 1);
  });

  it('rejects an UPPER_SNAKE_CASE-shaped token shorter than 3 characters', () => {
    const claims = identifiers.extractClaims('the `OK` flag');
    assert.equal(claims.length, 0, 'a 2-character token must not be graded as a UPPER_SNAKE_CASE claim');
  });

  it('accepts a function-call claim with an empty argument list', () => {
    const claims = identifiers.extractClaims('call `walk()` to start');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].identifier, 'walk');
  });

  it('strips a non-empty argument list from a function-call claim, keeping only the identifier', () => {
    const claims = identifiers.extractClaims(
      'call `main(argv)` then `computeExit({ severityCounts, incomplete })` and `walk()`'
    );
    assert.equal(claims.length, 3, `expected 3 claims, got ${JSON.stringify(claims)}`);
    const got = claims.map((c) => c.identifier).join(',');
    assert.equal(got, 'main,computeExit,walk', 'argument lists must be discarded, never matched against source');
  });

  it('produces no claim for a nested-parenthesis call, not a corrupt one', () => {
    const claims = identifiers.extractClaims('nested `f(g(x))` here');
    assert.equal(claims.length, 0, 'a nested-paren call is deliberately out of grammar');
  });

  it('produces no claim for a bare parenthesis with no leading identifier', () => {
    const claims = identifiers.extractClaims('bare `(argv)` here');
    assert.equal(claims.length, 0, 'a parenthesis with no identifier before it is not a claim');
  });

  it('produces no claim for a bash `$(cmd)` command-substitution span', () => {
    // Regression: a loose identifier-char-class allowing a bare `$` as the
    // FIRST character would match bash's `$(cmd)` syntax highlighted
    // inside backticks (seen for real in docs/hardening/github-copilot.md)
    // as a claim naming the identifier "$". `$` is a valid identifier
    // character in this grammar only after a leading letter/underscore.
    const claims = identifiers.extractClaims('nested `$(cmd)` within `${...}` bypassed this check');
    assert.equal(claims.length, 0, `$(cmd) must not be graded as a function-call claim, got: ${JSON.stringify(claims)}`);
  });

  it('does not extract a claim spanning a line break', () => {
    const claims = identifiers.extractClaims('open `main(\nargv)` close');
    assert.equal(claims.length, 0, 'a backtick span with no closing backtick on the same line is not a claim');
  });
});

describe('identifiers.js -- identifierExistsInSource', () => {
  it('a declared-but-unexported const counts as existing (source-text presence, never export-inspection)', () => {
    const src = ['const REQUIRED_SECTIONS = [];'];
    assert.ok(identifiers.identifierExistsInSource('REQUIRED_SECTIONS', src));
  });

  it('a partial-word match does not count', () => {
    const src = ['const REQUIRED_SECTIONS = [];'];
    assert.ok(!identifiers.identifierExistsInSource('REQUIRED_SECTION', src));
  });

  it('escapes regex metacharacters in the identifier instead of interpreting them, and never throws', () => {
    assert.doesNotThrow(() => {
      const found = identifiers.identifierExistsInSource('a.b*c', ['literal']);
      assert.equal(found, false);
    });
  });
});

describe('identifiers.js -- run() tolerates a missing hooks/ or lib/ directory', () => {
  // Regression: not every root this check is swept against (via the real
  // CLI's loadChecks() registry, which runs every check against ANY
  // --root target) has both a hooks/ and a lib/ top-level directory --
  // e.g. this repo's own pre-existing tests/fixtures/docs-verify/
  // mcp-rule-ids/{clean,defect,...}/ roots (built for Check 2, no hooks/
  // dir). A missing directory is zero source there, not a broken sweep;
  // only a genuine read error (not ENOENT) should force incomplete.
  function contextWithListFiles(listFilesImpl, mdFiles) {
    return {
      root: '.',
      errors: [],
      mdFiles: mdFiles || [],
      readText: () => ({ text: '' }),
      listFiles: listFilesImpl,
    };
  }

  it('does not throw when hooks/ does not exist (ENOENT), treating it as zero source files', () => {
    const ctx = contextWithListFiles((dir) => (dir === 'hooks' ? { error: 'ENOENT' } : { files: [] }));
    assert.doesNotThrow(() => identifiers.run(ctx));
  });

  it('does not throw when lib/ does not exist (ENOENT), treating it as zero source files', () => {
    const ctx = contextWithListFiles((dir) => (dir === 'lib' ? { error: 'ENOENT' } : { files: [] }));
    assert.doesNotThrow(() => identifiers.run(ctx));
  });

  it('still throws on a non-ENOENT listing error (e.g. permission denied)', () => {
    const ctx = contextWithListFiles(() => ({ error: 'EACCES' }));
    assert.throws(() => identifiers.run(ctx));
  });

  it('a scoped doc claim still resolves against source found via the surviving directory when the other is missing', () => {
    const ctx = contextWithListFiles(
      (dir) => (dir === 'hooks' ? { error: 'ENOENT' } : { files: ['lib/a.js'] }),
      [{ path: 'docs/hardening/x.md', text: 'see `REAL_ID` here' }]
    );
    const withRead = { ...ctx, readText: () => ({ text: 'const REAL_ID = 1;' }) };
    const findings = identifiers.run(withRead);
    assert.deepEqual(findings, [], 'a claim backed by the surviving directory must still resolve as existing');
  });
});

describe('identifiers.js -- SCOPED_DOCS constant', () => {
  it('contains no hand-maintained blocklist of known-not-code tokens', () => {
    const serialized = JSON.stringify(identifiers.SCOPED_DOCS);
    for (const token of ['ANTHROPIC_API_KEY', 'DATABASE_URL', 'GITHUB_TOKEN', 'NPM_TOKEN', 'AKIA']) {
      assert.ok(!serialized.includes(token), `token blocklist detected in SCOPED_DOCS: ${token}`);
    }
  });
});

describe('identifiers.js -- Check 1 sweep against the real repo (DOC-01 identifier half)', () => {
  it('finds the BLOCKED_PATTERNS claim in docs/hardening/claude-code.md', () => {
    const root = path.join(__dirname, '..', '..');
    const context = buildContext(root);
    const { findings, incomplete } = runAll(context, [identifiers]);
    assert.deepEqual(incomplete, [], `sweep must complete cleanly against the real repo: ${JSON.stringify(incomplete)}`);
    const messages = findings.map((f) => f.message).join('\n');
    assert.ok(messages.includes('BLOCKED_PATTERNS'), `expected a BLOCKED_PATTERNS finding, got: ${JSON.stringify(findings)}`);
    assert.ok(findings.every((f) => f.file === 'docs/hardening/claude-code.md'), JSON.stringify(findings));
  });
});

describe('identifiers.js -- fixture pair (planted defect + 3 must-still-pass controls)', () => {
  it('non-vacuity: the defect fixture doc actually contains backticked claims', () => {
    const docText = fs.readFileSync(
      path.join(FIXTURES_ROOT, 'defect', 'docs', 'hardening', 'fixture-agent.md'),
      'utf8'
    );
    const claims = identifiers.extractClaims(docText);
    assert.ok(claims.length > 0, 'non-vacuity: claim list must not be empty -- an empty list would iterate nothing and pass silently');
  });

  it('defect: exactly one finding, naming the missing identifier and its doc line', () => {
    const { findings, incomplete } = sweep('defect');
    assert.deepEqual(incomplete, []);
    assert.equal(findings.length, 1, `expected exactly 1 finding, got: ${JSON.stringify(findings)}`);
    assert.equal(findings[0].file, 'docs/hardening/fixture-agent.md');
    assert.ok(findings[0].message.includes('MISSING_IDENTIFIER'), findings[0].message);
  });

  it('Control A (valid claim): the clean root reports zero findings, zero incomplete', () => {
    const { findings, incomplete } = sweep('clean');
    assert.deepEqual(incomplete, []);
    assert.deepEqual(findings, []);
  });

  it('Control B (scoping guard): the exempted narrative doc never produces a finding in either root', () => {
    for (const fixture of ['defect', 'clean']) {
      const { findings } = sweep(fixture);
      const fromThreatModel = findings.filter((f) => f.file === 'docs/threat-model.md');
      assert.deepEqual(fromThreatModel, [], `docs/threat-model.md must never be scoped, root=${fixture}`);
    }
  });

  it('Control C (non-export): the clean root does not flag the declared-but-unexported UNEXPORTED_CONST', () => {
    const { findings } = sweep('clean');
    const unexportedFindings = findings.filter((f) => f.message.includes('UNEXPORTED_CONST'));
    assert.deepEqual(unexportedFindings, [], 'a declared-but-unexported const must not be reported');
  });
});
