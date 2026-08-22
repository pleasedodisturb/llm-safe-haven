'use strict';

// Tests for lib/docs-verify/version.js (Check 5, G-1570, GUARD-01).
//
// Pinned grammar (see .planning/phases/21-doc-drift-guard/21-02-PLAN.md,
// Task 2): scope to UNAMBIGUOUSLY self-referential forms only --
// `<pkg>@<version>`, `<pkg> v<version>`, `npx <pkg>@<version>` -- never a
// bare vX.Y.Z token (21-RESEARCH.md Pitfall 4: this repo's docs cite
// several third-party tools' own semver strings in narrative prose, none
// of which are claims about this package's version). Comparison is exact
// string equality against context.pkg.version -- a caret, tilde, or
// range operator is a mismatch, never silently accepted.
//
// Honest scope (21-02-PLAN.md "Honest scope"): this plan's own research
// (21-RESEARCH.md:544) claimed no tracked document states a
// self-referential llm-safe-haven version. That claim was independently
// re-verified during this task's implementation and found INCORRECT --
// research/top100-mcp/DRAFT.md:179 pinned `npx llm-safe-haven@0.4.0` inside
// a fenced install-instruction code block, which was stale against
// package.json's 0.7.0. This was real, on-spec drift (an npx-pinned
// install instruction gone stale is exactly the class Check 5 exists to
// catch), not a false positive from an over-broad pattern. Recorded as a
// deviation in 21-02-SUMMARY.md.
//
// UPDATE (22-04, G-1671, D-18): the pin was bumped to 0.7.0, so the real
// repo now sweeps clean under this check -- see the "real repo" describe
// block below, which asserts the fixed state directly against the live
// tree rather than re-asserting the drift that motivated writing it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const version = require('../../lib/docs-verify/version.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'version');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [version]);
}

describe('version.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(version.id, 'version');
    assert.equal(typeof version.run, 'function');
    assert.equal(typeof version.extractVersionClaims, 'function');
    assert.ok(Array.isArray(version.SELF_VERSION_PATTERNS));
  });
});

describe('version.js -- extractVersionClaims grammar', () => {
  it('extracts a `<pkg>@<version>` claim', () => {
    const claims = version.extractVersionClaims('run llm-safe-haven@0.7.0 today', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.7.0');
  });

  it('extracts a `<pkg> v<version>` claim without the leading v in the captured value', () => {
    const claims = version.extractVersionClaims('llm-safe-haven v0.7.0 is live', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.7.0', 'the leading v must be excluded so comparison is apples-to-apples');
  });

  it('extracts an `npx <pkg>@<version>` claim inside a fenced code block line', () => {
    const claims = version.extractVersionClaims('npx llm-safe-haven@0.4.0 scan --mcp', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.4.0');
  });

  it('captures a leading caret/tilde as part of the value, never normalizing it away', () => {
    const claims = version.extractVersionClaims('npx llm-safe-haven@^1.2.3 today', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '^1.2.3');
  });

  it('does not extract a claim from a bare vX.Y.Z token with no package name attached', () => {
    const claims = version.extractVersionClaims('Infisical v0.10.0 and another tool v0.25.0', 'llm-safe-haven');
    assert.equal(claims.length, 0, `bare third-party semver must never be extracted, got: ${JSON.stringify(claims)}`);
  });

  it('does not extract a claim from a non-numeric placeholder like `pkg@x.y.z`', () => {
    const claims = version.extractVersionClaims('recommend npx llm-safe-haven@x.y.z', 'llm-safe-haven');
    assert.equal(claims.length, 0, `a placeholder that does not start with a digit must not be extracted, got: ${JSON.stringify(claims)}`);
  });

  it('deduplicates an npx-invocation match counted by both the @-form and the npx-form patterns', () => {
    const claims = version.extractVersionClaims('run npx llm-safe-haven@0.7.0 now', 'llm-safe-haven');
    assert.equal(claims.length, 1, `a single occurrence must not be double-counted across overlapping patterns, got: ${JSON.stringify(claims)}`);
  });
});

describe('version.js -- trailing sentence punctuation must never be captured as part of the version (F3, Codex review PR #105)', () => {
  it('a version claim at the end of a sentence excludes the trailing period', () => {
    const claims = version.extractVersionClaims('Install llm-safe-haven@0.7.0. Then run it.', 'llm-safe-haven');
    assert.equal(claims.length, 1, `expected exactly 1 claim, got: ${JSON.stringify(claims)}`);
    assert.equal(claims[0].value, '0.7.0', `trailing sentence period must not be swallowed into the captured version, got: ${JSON.stringify(claims)}`);
  });

  it('control: a version claim followed by a comma already excludes the comma', () => {
    const claims = version.extractVersionClaims('llm-safe-haven v0.7.0, and more', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.7.0');
  });

  it('control: a version claim followed by a semicolon already excludes the semicolon', () => {
    const claims = version.extractVersionClaims('llm-safe-haven@0.7.0; next sentence', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.7.0');
  });

  it('control: a version claim followed by a colon already excludes the colon', () => {
    const claims = version.extractVersionClaims('llm-safe-haven@0.7.0: colon case', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.7.0');
  });

  it('control: the real repo pin (npx llm-safe-haven@0.4.0, mid-sentence, no trailing punctuation) is unaffected', () => {
    const claims = version.extractVersionClaims('npx llm-safe-haven@0.4.0 scan --mcp', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '0.4.0');
  });

  it('control: prerelease + build metadata (1.2.3-beta.1) is still captured in full, mid-sentence', () => {
    const claims = version.extractVersionClaims('npx llm-safe-haven@1.2.3-beta.1 today', 'llm-safe-haven');
    assert.equal(claims.length, 1);
    assert.equal(claims[0].value, '1.2.3-beta.1');
  });

  it('control: a non-numeric placeholder (x.y.z) is still never extracted', () => {
    const claims = version.extractVersionClaims('recommend npx llm-safe-haven@x.y.z', 'llm-safe-haven');
    assert.deepEqual(claims, []);
  });
});

describe('version.js -- run() incompleteness guard', () => {
  it('throws when context.pkg is null (canonical version unreadable)', () => {
    assert.throws(() => {
      version.run({ pkg: null, mdFiles: [], readText: () => ({ text: '' }), listFiles: () => ({ files: [] }), root: '.', errors: [] });
    });
  });

  it('throws when context.pkg.version is missing', () => {
    assert.throws(() => {
      version.run({
        pkg: { name: 'llm-safe-haven' },
        mdFiles: [],
        readText: () => ({ text: '' }),
        listFiles: () => ({ files: [] }),
        root: '.',
        errors: [],
      });
    });
  });
});

describe('version.js -- run() comparison semantics', () => {
  it('reports a range operator as a mismatch, never accepted as satisfying the range', () => {
    const ctx = {
      pkg: { name: 'llm-safe-haven', version: '1.2.3' },
      mdFiles: [{ path: 'd.md', text: 'run npx llm-safe-haven@^1.2.3 today' }],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
      root: '.',
      errors: [],
    };
    const findings = version.run(ctx);
    assert.equal(findings.length, 1, `a range operator must be reported as a mismatch, got ${findings.length} findings`);
  });

  it('never compares a third-party semver mention in prose', () => {
    const ctx = {
      pkg: { name: 'llm-safe-haven', version: '1.2.3' },
      mdFiles: [{ path: 'd.md', text: 'Infisical v0.10.0 and another tool v0.25.0 were affected' }],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
      root: '.',
      errors: [],
    };
    const findings = version.run(ctx);
    assert.equal(findings.length, 0, `third-party semver in prose must not be compared, got ${findings.length} findings`);
  });
});

// G-1672 WR-02 (22-REVIEW.md): this "real repo" describe block is a DELIBERATE
// defense-in-depth duplicate of the blocking `docs:verify` CI step
// (.github/workflows/ci.yml, G-1670) -- not an accidental copy. It will go red at
// every release bump (or any other change that drifts a live doc, e.g. the
// self-version pin in AGENTS.md / research/top100-mcp/DRAFT.md) until the drift is
// fixed, independently of whether the dedicated CI step has already caught it. This
// is intentional: `npm test` and `docs:verify` are two separate enforcement
// surfaces guarding the same guarantee. Do not delete this block to "de-duplicate"
// it. Moving it (and its two siblings in identifiers.test.js and mcp-rule-ids.test.js)
// into a single shared `describe('live-repo drift guard (redundant with docs:verify
// CI step)')` block is tracked as a follow-up, not done here.
describe('version.js -- Check 5 sweep against the real repo (honest scope)', () => {
  it('finds zero self-referential version findings (the one real drift, research/top100-mcp/DRAFT.md pinned to 0.4.0, was fixed to package.json\'s live version by 22-04/G-1671/D-18)', () => {
    const root = path.join(__dirname, '..', '..');
    const context = buildContext(root);
    const { findings, incomplete } = runAll(context, [version]);
    assert.deepEqual(incomplete, [], `sweep must complete cleanly against the real repo: ${JSON.stringify(incomplete)}`);
    assert.equal(
      findings.length,
      0,
      `expected zero real findings after 22-04's DRAFT.md pin bump (D-18); a non-zero count here means either a new ` +
        `self-referential pin has drifted stale or the fix regressed, got: ${JSON.stringify(findings)}`
    );
  });

  it('does not extract a claim from CLAUDE.md\'s literal `npx llm-safe-haven@x.y.z` placeholder', () => {
    const claudeMdPath = path.join(__dirname, '..', '..', 'CLAUDE.md');
    const text = fs.readFileSync(claudeMdPath, 'utf8');
    const claims = version.extractVersionClaims(text, 'llm-safe-haven');
    assert.deepEqual(claims, [], `CLAUDE.md's x.y.z placeholder must never be extracted, got: ${JSON.stringify(claims)}`);
  });
});

describe('version.js -- fixture pair (planted defect + must-still-pass controls)', () => {
  it('non-vacuity: the defect fixture doc actually contains a version claim', () => {
    const docText = fs.readFileSync(path.join(FIXTURES_ROOT, 'defect', 'docs', 'install.md'), 'utf8');
    const claims = version.extractVersionClaims(docText, 'docs-verify-fixture-version-defect');
    assert.ok(claims.length > 0, 'non-vacuity: claim list must not be empty');
  });

  it('defect: exactly one finding, naming both the claimed and canonical values', () => {
    const { findings, incomplete } = sweep('defect');
    assert.deepEqual(incomplete, []);
    assert.equal(findings.length, 1, `expected exactly 1 finding, got: ${JSON.stringify(findings)}`);
    assert.equal(findings[0].file, 'docs/install.md');
    assert.ok(findings[0].message.includes('2.5.1'), findings[0].message);
    assert.ok(findings[0].message.includes('2.5.0'), findings[0].message);
  });

  it('Control A: the clean root reports zero findings, zero incomplete', () => {
    const { findings, incomplete } = sweep('clean');
    assert.deepEqual(incomplete, []);
    assert.deepEqual(findings, []);
  });

  it('Control B: the third-party-semver threat-model doc never produces a finding in either root', () => {
    for (const fixture of ['defect', 'clean']) {
      const { findings } = sweep(fixture);
      const fromThreatModel = findings.filter((f) => f.file === 'docs/threat-model.md');
      assert.deepEqual(fromThreatModel, [], `docs/threat-model.md must never be flagged, root=${fixture}`);
    }
  });
});
