'use strict';

// Tests for lib/docs-verify/anchors.js (Check 4, G-1570, 21-03 Task 3).
//
// Check 4 is the check that names DOC-03b: docs/credential-management.md
// links to a supply-chain-defense.md fragment describing a Bitwarden CLI
// case study, and the only Shai-Hulud heading in that file is the
// "Sustained npm Supply Chain Campaign" one -- the linked text describes a
// different heading entirely, so it fails under any reasonable slug
// implementation. This suite exercises the check's own contract via
// fixtures and hand-built contexts; it deliberately does NOT invoke the
// guard against the live repository (that verification is run manually
// and recorded in 21-03-SUMMARY.md, per the executor's sequential-mode
// instructions -- a committed live-repo assertion is exactly what
// tests/docs-verify/cli.test.js had to drop in d08d88a).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const anchors = require('../../lib/docs-verify/anchors.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'anchors');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [anchors]);
}

describe('anchors.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(anchors.id, 'anchors');
    assert.equal(typeof anchors.run, 'function');
  });

  it('is registered by loadChecks() (membership + non-vacuity only -- 21-05 owns exactly-seven)', () => {
    const { loadChecks } = require('../../lib/docs-verify/index.js');
    const { checks, errors } = loadChecks();
    assert.deepEqual(errors, []);
    assert.ok(checks.length > 0, 'non-vacuity: registry is empty');
    assert.ok(checks.map((c) => c.id).includes('anchors'), 'anchors check not registered');
  });
});

describe('anchors.js -- no subprocess or network primitive, and no private decoder', () => {
  it('negative source scan (comment lines and trailing comments stripped first)', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'anchors.js'), 'utf8');
    const code = raw
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .map((l) => l.replace(/\s\/\/.*$/, ''))
      .join('\n');

    const badExec = /child_process|execSync|execFileSync|spawnSync|https?\.request|fetch\(/;
    assert.equal(badExec.test(code), false, 'subprocess or network primitive found in anchors.js');

    assert.equal(
      /decodeURIComponent/.test(code),
      false,
      'anchors.js must reuse the links module guarded decoder, not call the platform decoder directly'
    );
    assert.ok(/decodeTargetOrNull/.test(code), 'anchors.js does not use the shared guarded decoder at all');
  });
});

describe('run() -- in-page and cross-file resolution', () => {
  it('a cross-file anchor matching no heading in the target document is exactly one finding', () => {
    const target = { path: 't.md', text: '# Ok\n' };
    const src = { path: 's.md', text: '[bad](t.md#nope)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(f.length, 1, `expected exactly one finding, got: ${JSON.stringify(f)}`);
    assert.match(f[0].message, /nope/);
  });

  it('a cross-file anchor that matches a heading exactly produces zero findings', () => {
    const target = { path: 't.md', text: '# Ok\n' };
    const src = { path: 's.md', text: '[good](t.md#ok)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    assert.deepEqual(anchors.run(ctx), []);
  });

  it('an in-page anchor resolves against the LINKING document, not a different one', () => {
    const target = { path: 't.md', text: '# Unrelated\n' };
    const src = { path: 's.md', text: '# Self\n\n[self](#self)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    assert.deepEqual(anchors.run(ctx), []);
  });
});

describe('run() -- percent-decoding, NFC-then-lowercase, in that order', () => {
  it('a percent-encoded fragment and its plain twin both resolve against a precomposed heading', () => {
    const target = { path: 't.md', text: '# Café Notes\n' };
    const src = { path: 's.md', text: '[enc](t.md#caf%C3%A9-notes) and [plain](t.md#café-notes)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(f.length, 0, `a percent-encoded fragment and its plain twin must both resolve, got: ${JSON.stringify(f)}`);
  });

  it('a genuinely DECOMPOSED-Unicode anchor spelling resolves against a PRECOMPOSED heading, and the reverse', () => {
    // Precomposed-decode-only percent-decoding (the case above) does not
    // exercise NFC normalization at all: UTF-8 bytes C3 A9 decode straight
    // to precomposed U+00E9, never through a decomposed intermediate. This
    // case uses explicit codepoints so decomposed vs precomposed spellings
    // genuinely differ byte-wise, proving normalize('NFC') is load-bearing.
    const precomposed = 'é'; // é as a single precomposed codepoint
    const decomposed = 'é'; // e + combining acute accent (U+0301)
    assert.notEqual(precomposed, decomposed, 'sanity: the two spellings must differ byte-wise');

    const precomposedTarget = { path: 't1.md', text: `# Caf${precomposed} Notes\n` };
    const decomposedSrc = { path: 's1.md', text: `[a](t1.md#caf${decomposed}-notes)` };
    const decomposedTarget = { path: 't2.md', text: `# Caf${decomposed} Notes\n` };
    const precomposedSrc = { path: 's2.md', text: `[a](t2.md#caf${precomposed}-notes)` };

    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [decomposedSrc, precomposedTarget, precomposedSrc, decomposedTarget],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(
      f.length,
      0,
      `a decomposed anchor must resolve against a precomposed heading and vice versa, got: ${JSON.stringify(f)}`
    );
  });

  it('a malformed percent escape in a fragment is exactly one finding, and the walk continues', () => {
    const target = { path: 't.md', text: '# Ok\n' };
    const src = { path: 's.md', text: '[bad](t.md#a%zz) and [good](t.md#ok)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(f.length, 1, `a malformed escape must produce exactly one finding and must not abort the walk, got ${f.length}: ${JSON.stringify(f)}`);
    assert.match(f[0].message, /malformed/i);
  });
});

describe('run() -- adjacency (duplicate-heading suffixes)', () => {
  it('both the bare and the -1-suffixed anchor resolve', () => {
    const target = { path: 't.md', text: '# Dup\n\n# Dup\n' };
    const src = { path: 's.md', text: '[one](t.md#dup) and [two](t.md#dup-1)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(f.length, 0, `both duplicate-heading anchors must resolve, got: ${JSON.stringify(f)}`);
  });
});

describe('run() -- no double-report with Check 3', () => {
  it('a link to a nonexistent file with a fragment produces zero anchor findings (Check 3 owns the missing-file finding)', () => {
    const src = { path: 's.md', text: '[x](missing.md#whatever)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const f = anchors.run(ctx);
    assert.equal(f.length, 0, `anchors must not double-report a missing target file, got ${f.length} findings`);
  });

  it('same case, asserting BOTH halves in one place: zero anchor findings AND one link finding from the sibling check', () => {
    const links = require('../../lib/docs-verify/links.js');
    const src = { path: 's.md', text: '[x](missing.md#whatever)' };
    const ctx = {
      root: path.join(FIXTURES_ROOT, 'defect'), // any real root; missing.md genuinely absent
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    const anchorFindings = anchors.run(ctx);
    const linkFindings = links.run(ctx);
    assert.equal(anchorFindings.length, 0, 'deleting the anchor check would not make this pass without the link-findings half');
    assert.equal(linkFindings.length, 1, 'Check 3 must still report the missing file exactly once');
  });
});

describe('run() -- boundary cases', () => {
  it('a link with no fragment is skipped entirely', () => {
    const target = { path: 't.md', text: '# Ok\n' };
    const src = { path: 's.md', text: '[nofrag](t.md)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src, target],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    assert.deepEqual(anchors.run(ctx), []);
  });

  it('an anchor on an external link is ignored', () => {
    const src = { path: 's.md', text: '[ext](https://example.com#whatever)' };
    const ctx = {
      root: '.',
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      mdFiles: [src],
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
    };
    assert.deepEqual(anchors.run(ctx), []);
  });
});

describe('run() -- fixture sweep: defect root', () => {
  const result = sweep('defect');

  it('non-vacuity: the slug map and the extracted link list are both non-empty before comparison', () => {
    const context = buildContext(path.join(FIXTURES_ROOT, 'defect'));
    const entry = context.mdFiles.find((f) => f.path === 'docs/entry.md');
    const target = context.mdFiles.find((f) => f.path === 'docs/target.md');
    assert.ok(entry && target, 'entry.md / target.md not discovered');
    const { headingSlugs } = require('../../lib/docs-verify/helpers/slug.js');
    assert.ok(headingSlugs(target.text).length > 0, 'non-vacuity: target.md has zero headings');
    const { extractLinks } = require('../../lib/docs-verify/links.js');
    assert.ok(extractLinks(entry.text).length > 0, 'non-vacuity: entry.md has zero extracted links');
  });

  it('reports exactly the planted dangling cross-file anchor', () => {
    assert.equal(result.incomplete.length, 0, `unexpected incomplete: ${JSON.stringify(result.incomplete)}`);
    assert.equal(result.findings.length, 1, `expected 1 finding, got: ${JSON.stringify(result.findings)}`);
    assert.match(result.findings[0].message, /does-not-exist/);
  });
});

describe('run() -- fixture sweep: clean root (in-page, cross-file, Unicode, and adjacency controls)', () => {
  const result = sweep('clean');

  it('produces zero findings', () => {
    assert.equal(result.incomplete.length, 0, `unexpected incomplete: ${JSON.stringify(result.incomplete)}`);
    assert.equal(result.findings.length, 0, `expected zero findings, got: ${JSON.stringify(result.findings)}`);
  });
});

describe('CLI -- process-boundary exit codes', () => {
  const { spawnSync } = require('child_process');
  const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'docs-verify.js');

  function runCli(root) {
    return spawnSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8', timeout: 30_000 });
  }

  it('defect root: exit 1, stdout contains "anchors"', () => {
    const res = runCli(path.join(FIXTURES_ROOT, 'defect'));
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /anchors/);
  });

  it('clean root: exit 0', () => {
    const res = runCli(path.join(FIXTURES_ROOT, 'clean'));
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});
