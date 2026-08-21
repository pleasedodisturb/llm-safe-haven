'use strict';

// Tests for lib/docs-verify/mcp-rule-ids.js (Check 2, G-1570).
//
// Pinned grammar (see .planning/phases/21-doc-drift-guard/21-01-PLAN.md
// "Check 2 grammar"): per-detector suffix comparison, row-scoped, brace
// alternation expanded, backslash-escaped-pipe cells split correctly. The
// composed `<detector-id>/<rule>` form never appears verbatim in
// docs/mcp-security.md — a whole-document substring test would produce
// ~20 false findings on the real corpus.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll, tallySeverities, computeExit } = require('../../lib/docs-verify/index.js');
const mcpRuleIds = require('../../lib/docs-verify/mcp-rule-ids.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'mcp-rule-ids');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [mcpRuleIds]);
}

describe('mcp-rule-ids.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(mcpRuleIds.id, 'mcp-rule-ids');
    assert.equal(typeof mcpRuleIds.run, 'function');
    assert.equal(typeof mcpRuleIds.splitTableRow, 'function');
    assert.equal(typeof mcpRuleIds.expandBraceAlternation, 'function');
    assert.equal(typeof mcpRuleIds.documentedRuleSuffixes, 'function');
    assert.equal(typeof mcpRuleIds.emittedRuleSuffixes, 'function');
  });
});

describe('mcp-rule-ids.js -- splitTableRow', () => {
  it('does not split on a backslash-escaped pipe', () => {
    const cells = mcpRuleIds.splitTableRow(
      '| `unpinned-execution` | `{npx\\|uvx}-no-version`, `url-no-version-binding` | medium |'
    );
    assert.equal(cells[1].replace(/`/g, ''), 'unpinned-execution');
    assert.ok(cells[2].includes('url-no-version-binding'), `escaped pipe split the row: ${JSON.stringify(cells)}`);
    assert.ok(cells[2].includes('{npx|uvx}-no-version'), `escaped pipe not preserved: ${JSON.stringify(cells)}`);
  });

  it('splits a row with no escaped pipes into the expected cell count', () => {
    const cells = mcpRuleIds.splitTableRow('| `credential-passthrough` | `inlined-secret` | critical |');
    assert.equal(cells.length, 5); // '', cell1, cell2, cell3, ''
  });
});

describe('mcp-rule-ids.js -- expandBraceAlternation', () => {
  it('expands a brace group into one token per alternative', () => {
    assert.deepEqual(mcpRuleIds.expandBraceAlternation('{npx|uvx}-no-version'), ['npx-no-version', 'uvx-no-version']);
  });

  it('returns a non-brace token unchanged', () => {
    assert.deepEqual(mcpRuleIds.expandBraceAlternation('plain-http'), ['plain-http']);
  });
});

describe('mcp-rule-ids.js -- documentedRuleSuffixes against the real corpus', () => {
  const fs = require('fs');
  const docText = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'mcp-security.md'), 'utf8');
  const map = mcpRuleIds.documentedRuleSuffixes(docText);

  it('non-vacuity: at least one detector row was parsed', () => {
    assert.ok(map.size > 0, 'documentedRuleSuffixes must not return an empty map against the real doc');
  });

  it('expands the brace-alternation + escaped-pipe unpinned-execution row correctly', () => {
    const suffixes = map.get('unpinned-execution');
    assert.ok(suffixes, 'unpinned-execution row not parsed');
    assert.ok(suffixes.has('npx-no-version'));
    assert.ok(suffixes.has('uvx-no-version'));
    assert.ok(suffixes.has('url-no-version-binding'));
  });

  it('the real DOC-02 defect is present: credential-passthrough documents exactly 3 suffixes, missing high-entropy-literal', () => {
    const suffixes = map.get('credential-passthrough');
    assert.ok(suffixes);
    assert.equal(suffixes.size, 3, `expected 3 documented suffixes, got ${suffixes ? suffixes.size : 'none'}`);
    assert.ok(!suffixes.has('high-entropy-literal'), 'DOC-02 defect is gone from main — this fixture is stale');
  });
});

describe('mcp-rule-ids.js -- emittedRuleSuffixes against the real corpus', () => {
  const fs = require('fs');

  it('resolves the real ${bin} interpolation from unpinned-execution.js', () => {
    const source = fs.readFileSync(
      path.join(__dirname, '..', '..', 'lib', 'mcp', 'detectors', 'unpinned-execution.js'),
      'utf8'
    );
    const result = mcpRuleIds.emittedRuleSuffixes(source);
    assert.equal(result.unresolved.length, 0, `unexpected unresolved sites: ${JSON.stringify(result.unresolved)}`);
    const suffixes = result.suffixes.map((s) => s.suffix);
    assert.ok(suffixes.includes('npx-no-version'));
    assert.ok(suffixes.includes('uvx-no-version'));
    assert.ok(suffixes.includes('url-no-version-binding'));
  });

  it('extracts exactly the 4 literal suffixes from credential-passthrough.js', () => {
    const source = fs.readFileSync(
      path.join(__dirname, '..', '..', 'lib', 'mcp', 'detectors', 'credential-passthrough.js'),
      'utf8'
    );
    const result = mcpRuleIds.emittedRuleSuffixes(source);
    assert.equal(result.detectorId, 'credential-passthrough');
    const suffixes = result.suffixes.map((s) => s.suffix).sort();
    assert.deepEqual(suffixes, ['broad-inheritance', 'high-entropy-literal', 'inlined-secret', 'sensitive-name-literal']);
  });
});

describe('mcp-rule-ids.js -- Check 2 sweep against the real repo (RED against main by design)', () => {
  it('finds exactly one drift finding: credential-passthrough/high-entropy-literal', () => {
    const root = path.join(__dirname, '..', '..');
    const context = buildContext(root);
    const { findings, incomplete } = runAll(context, [mcpRuleIds]);
    assert.deepEqual(incomplete, [], `sweep must complete cleanly against the real repo: ${JSON.stringify(incomplete)}`);
    assert.equal(findings.length, 1, `expected exactly 1 finding, got: ${JSON.stringify(findings)}`);
    assert.ok(findings[0].message.includes('credential-passthrough/high-entropy-literal'));
  });
});

describe('mcp-rule-ids.js -- emittedRuleSuffixes on a double-quoted const id declaration', () => {
  // WR-01 precondition (unchanged by the fix): ID_CONST_RE is single-quote
  // only, so a double-quoted `const id` declaration resolves to
  // detectorId === null even though suffixes ARE extracted -- this is the
  // exact state run() must guard against.
  it('detectorId is null (ID_CONST_RE does not match double quotes), suffixes still extracted', () => {
    const src =
      "'use strict';\nconst id = \"weird-detector\";\nfunction run(){ return [{ id: `${id}/some-suffix` }]; }\nmodule.exports = { id, run };\n";
    const result = mcpRuleIds.emittedRuleSuffixes(src);
    assert.equal(result.detectorId, null);
    assert.equal(result.unresolved.length, 0);
    assert.equal(result.suffixes.length, 1);
    assert.equal(result.suffixes[0].suffix, 'some-suffix');
  });
});

describe('mcp-rule-ids.js -- fixture pair (planted defect + must-still-pass control)', () => {
  it('clean control: zero findings, zero incomplete', () => {
    const { findings, incomplete } = sweep('clean');
    assert.deepEqual(incomplete, []);
    assert.deepEqual(findings, []);
  });

  it('defect case: exactly two findings naming the missing rule IDs', () => {
    const { findings, incomplete } = sweep('defect');
    assert.deepEqual(incomplete, []);
    assert.equal(findings.length, 2, `expected 2 findings, got: ${JSON.stringify(findings)}`);
    const messages = findings.map((f) => f.message).join('\n');
    assert.ok(messages.includes('fixture-detector/broad-inheritance'), messages);
    assert.ok(messages.includes('fixture-detector/uvx-no-version'), messages);
  });

  it('unresolved-dynamic case: sweep is incomplete, never a finding, never a silent skip', () => {
    const { findings, incomplete } = sweep('unresolved-dynamic');
    assert.deepEqual(findings, []);
    assert.ok(incomplete.length > 0, 'unresolved dynamic interpolation must force an incomplete sweep');
    const exitCode = computeExit({ severityCounts: tallySeverities(findings), incomplete });
    assert.equal(exitCode, 2);
    const reasons = incomplete.map((i) => i.reason).join('\n');
    assert.ok(/unresolved/i.test(reasons), reasons);
  });

  it('no-rules case: zero rule IDs extracted forces incomplete, never a clean pass', () => {
    const { findings, incomplete } = sweep('no-rules');
    assert.deepEqual(findings, []);
    assert.ok(incomplete.length > 0, 'zero-suffix detector module must force an incomplete sweep');
    const exitCode = computeExit({ severityCounts: tallySeverities(findings), incomplete });
    assert.equal(exitCode, 2);
  });

  it('null-detector-id case (WR-01): sweep is incomplete, never a fabricated "null/..." finding', () => {
    const { findings, incomplete } = sweep('null-detector-id');
    assert.deepEqual(findings, [], `must never fabricate a null/<suffix> finding, got: ${JSON.stringify(findings)}`);
    assert.ok(
      incomplete.length > 0,
      'a detector module whose const id declaration cannot be parsed must force an incomplete sweep'
    );
    const exitCode = computeExit({ severityCounts: tallySeverities(findings), incomplete });
    assert.equal(exitCode, 2);
    const reasons = incomplete.map((i) => i.reason).join('\n');
    assert.ok(/could not determine the detector id/i.test(reasons), reasons);
  });
});
