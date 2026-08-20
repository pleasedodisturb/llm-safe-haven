'use strict';

// Tests for lib/docs-verify/links.js (Check 3, G-1570, 21-03 Task 2).
//
// Pinned grammar: see .planning/phases/21-doc-drift-guard/21-03-PLAN.md
// "Pinned link grammar (Check 3 / Check 4)". Graded shapes each get a
// planted-defect case AND a must-still-pass control; the three named
// out-of-scope shapes (reference-style, nested-parenthesis, fenced) each
// get their own "produces zero findings" case so the boundary is pinned
// by a test, not by whichever regex shipped.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const links = require('../../lib/docs-verify/links.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'links');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [links]);
}

describe('links.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(links.id, 'links');
    assert.equal(typeof links.run, 'function');
    assert.equal(typeof links.extractLinks, 'function');
    assert.equal(typeof links.isExternal, 'function');
    assert.equal(typeof links.decodeTargetOrNull, 'function');
  });

  it('is registered by loadChecks() (membership + non-vacuity only -- 21-05 owns exactly-seven)', () => {
    const { loadChecks } = require('../../lib/docs-verify/index.js');
    const { checks, errors } = loadChecks();
    assert.deepEqual(errors, []);
    assert.ok(checks.length > 0, 'non-vacuity: registry is empty');
    assert.ok(checks.map((c) => c.id).includes('links'), 'links check not registered');
  });
});

describe('links.js -- no subprocess or network primitive', () => {
  it('negative source scan', () => {
    const bad = /child_process|execSync|execFileSync|spawnSync|https?\.request|fetch\(/;
    const src = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'links.js'), 'utf8');
    assert.equal(bad.test(src), false, 'subprocess or network primitive found in links.js');
  });
});

describe('extractLinks -- grammar coverage (graded shapes)', () => {
  it('extracts title, angle-bracket, image and autolink shapes, stripping title/brackets', () => {
    const g = links.extractLinks('[a](x.md "T") [b](<y z.md>) ![c](i.png) <./r.md>');
    assert.equal(g.length, 4, `expected 4 links, got ${g.length}: ${JSON.stringify(g.map((v) => v.target))}`);
    assert.equal(g[0].target, 'x.md', `title not stripped: ${g[0].target}`);
    assert.equal(g[1].target, 'y z.md', `angle brackets not stripped: ${g[1].target}`);
    assert.equal(g[2].target, 'i.png');
    assert.equal(g[3].target, './r.md');
  });

  it('splits target and fragment before any filesystem work', () => {
    const l = links.extractLinks('see [x](a/b.md#frag) and [y](d.md)');
    assert.equal(l.length, 2, `expected 2 links, got ${l.length}`);
    assert.equal(l[0].target, 'a/b.md');
    assert.equal(l[0].anchor, 'frag');
    assert.equal(l[1].target, 'd.md');
    assert.equal(l[1].anchor, null);
  });
});

describe('extractLinks -- grammar boundary (out of scope, zero claims)', () => {
  it('reference-style [t][ref] + [ref]: target produces no claim', () => {
    assert.equal(links.extractLinks('[t][ref]\n\n[ref]: gone.md').length, 0);
  });

  it('a nested-parenthesis target produces no claim rather than a truncated one', () => {
    assert.equal(links.extractLinks('[t](a(b).md)').length, 0);
  });

  it('a link inside a fenced code block is a documented example, not a live link', () => {
    const fence = '```';
    assert.equal(links.extractLinks(`${fence}\n[t](gone.md)\n${fence}`).length, 0);
  });

  it('a tilde-fenced link is also out of scope', () => {
    assert.equal(links.extractLinks('~~~\n[t](gone.md)\n~~~').length, 0);
  });
});

describe('isExternal', () => {
  it('classifies scheme, protocol-relative and mailto targets as external', () => {
    const ext = ['mailto:someone', 'https://example.com', 'http://example.com', '//example.com'];
    for (const t of ext) assert.ok(links.isExternal(t), `must be external: ${t}`);
  });

  it('classifies relative targets as internal', () => {
    for (const t of ['./a.md', '../b/c.md', 'd.md']) {
      assert.equal(links.isExternal(t), false, `must be internal: ${t}`);
    }
  });
});

describe('decodeTargetOrNull', () => {
  it('percent-decodes a valid escape', () => {
    assert.equal(links.decodeTargetOrNull('a%20b.md'), 'a b.md');
  });

  it('returns null for a malformed percent escape rather than throwing or passing through', () => {
    assert.equal(links.decodeTargetOrNull('a%zz.md'), null);
  });
});

describe('run() -- directory rule (Agreed Concern 5 / Amendment 5(a))', () => {
  it('an existing directory target produces zero findings; a missing directory is a finding', () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-dirlink-'));
    fs.mkdirSync(path.join(tmpRoot, 'sub'), { recursive: true });
    fs.writeFileSync(path.join(tmpRoot, 'sub', 'x.md'), '# x');
    const ctx = {
      root: tmpRoot,
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
      mdFiles: [{ path: 'a.md', abs: path.join(tmpRoot, 'a.md'), text: 'see [dir](sub) and [gone](nosuchdir)' }],
    };
    const f = links.run(ctx);
    const messages = f.map((x) => x.message || '').join(' ');
    assert.equal(/\bsub\b/.test(messages), false, `an existing directory must NOT be a finding: ${messages}`);
    assert.equal(f.length, 1, `expected exactly the missing-directory finding, got ${f.length}: ${messages}`);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });
});

describe('run() -- out-of-tree targets are reported without being read (probe-recording proof)', () => {
  it('the escaping absolute path never reaches the filesystem probe; the in-tree path does', () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-outoftree-'));
    fs.mkdirSync(path.join(tmpRoot, 'docs'), { recursive: true });
    fs.writeFileSync(path.join(tmpRoot, 'docs', 'ok.md'), '# ok');

    const probed = [];
    const originalStatPath = links.statPath;
    links.statPath = (absPath) => {
      probed.push(absPath);
      return originalStatPath(absPath);
    };

    try {
      const ctx = {
        root: tmpRoot,
        errors: [],
        pkg: { name: 'x', version: '0.0.0' },
        readText: () => ({ text: '' }),
        listFiles: () => ({ files: [] }),
        mdFiles: [
          {
            path: 'docs/entry.md',
            abs: path.join(tmpRoot, 'docs', 'entry.md'),
            text: 'see [escape](../../../etc/passwd) and [inside](ok.md)',
          },
        ],
      };
      const f = links.run(ctx);
      const escapeAbs = path.resolve(tmpRoot, '..', '..', 'etc', 'passwd');
      assert.equal(
        probed.includes(escapeAbs),
        false,
        `an out-of-tree target must never be opened; probed list: ${JSON.stringify(probed)}`
      );
      const insideAbs = path.join(tmpRoot, 'docs', 'ok.md');
      assert.ok(probed.includes(insideAbs), 'the in-tree target should have been probed');
      const outOfTreeFinding = f.find((x) => /out-of-tree/.test(x.message));
      assert.ok(outOfTreeFinding, `expected an out-of-tree finding, got: ${JSON.stringify(f)}`);
    } finally {
      links.statPath = originalStatPath;
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe('run() -- percent-encoded targets', () => {
  it('resolves a percent-encoded space against the decoded path', () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-percent-'));
    fs.writeFileSync(path.join(tmpRoot, 'a b.md'), '# a b');
    const ctx = {
      root: tmpRoot,
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
      mdFiles: [{ path: 'entry.md', abs: path.join(tmpRoot, 'entry.md'), text: 'see [x](a%20b.md)' }],
    };
    const f = links.run(ctx);
    assert.equal(f.length, 0, `percent-encoded target must resolve, got: ${JSON.stringify(f)}`);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('a malformed percent escape is a finding, and the sweep does not abort on it', () => {
    const tmpRoot = fs.mkdtempSync(path.join(require('os').tmpdir(), 'lsh-malformed-'));
    fs.writeFileSync(path.join(tmpRoot, 'ok.md'), '# ok');
    const ctx = {
      root: tmpRoot,
      errors: [],
      pkg: { name: 'x', version: '0.0.0' },
      readText: () => ({ text: '' }),
      listFiles: () => ({ files: [] }),
      mdFiles: [{ path: 'entry.md', abs: path.join(tmpRoot, 'entry.md'), text: 'see [bad](a%zz.md) and [good](ok.md)' }],
    };
    const f = links.run(ctx);
    assert.equal(f.length, 1, `expected exactly one malformed-escape finding, got ${f.length}: ${JSON.stringify(f)}`);
    assert.match(f[0].message, /malformed/i);
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });
});

describe('run() -- fixture sweep: defect root', () => {
  const result = sweep('defect');

  it('non-vacuity: the extracted link list is non-empty before comparison', () => {
    const context = buildContext(path.join(FIXTURES_ROOT, 'defect'));
    const entry = context.mdFiles.find((f) => f.path === 'docs/entry.md');
    assert.ok(entry, 'entry.md not discovered');
    assert.ok(links.extractLinks(entry.text).length > 0, 'non-vacuity: extracted zero links from the defect fixture');
  });

  it('reports the missing sibling, out-of-tree, malformed-escape, and missing-directory findings', () => {
    assert.equal(result.incomplete.length, 0, `unexpected incomplete: ${JSON.stringify(result.incomplete)}`);
    assert.equal(result.findings.length, 4, `expected 4 findings, got ${JSON.stringify(result.findings)}`);
    const messages = result.findings.map((f) => f.message).join('\n');
    assert.match(messages, /missing\.md/);
    assert.match(messages, /out-of-tree/);
    assert.match(messages, /malformed/i);
    assert.match(messages, /nosuchdir/);
  });
});

describe('run() -- fixture sweep: clean root (full control battery)', () => {
  const result = sweep('clean');

  it('produces zero findings across every graded and boundary shape', () => {
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

  it('defect root: exit 1, stdout contains "links"', () => {
    const res = runCli(path.join(FIXTURES_ROOT, 'defect'));
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /links/);
  });

  it('clean root: exit 0', () => {
    const res = runCli(path.join(FIXTURES_ROOT, 'clean'));
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});
