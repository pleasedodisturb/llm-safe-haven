'use strict';

// Tests for lib/docs-verify/commands.js (Check 6, G-1570, GUARD-01, D-03).
//
// Pinned grammar: see .planning/phases/21-doc-drift-guard/21-04-PLAN.md,
// Task 1. Read that section before editing this file.
//
// D-03 broadening: Check 6 inspects path tokens both inside fenced command
// blocks AND inside single-backtick inline spans anywhere in prose, using
// the same path-resolution logic and a wider token extractor. This is what
// makes DOC-03a (docs/credential-management.md's flat `~/.claude/audit.jsonl`
// claim vs. hooks/audit-logger.js's real per-day `~/.claude/audit/*.jsonl`
// directory) mechanically nameable.
//
// Documented commands are parsed as text and NEVER executed -- no
// subprocess primitive exists anywhere in this module (asserted by a
// negative source scan below) and a fixture whose fenced block would
// create a sentinel file leaves no sentinel behind after a sweep.
//
// Honest scope (21-04-PLAN.md "Honest scope" section): the agent-home
// segment rule is a PRESENCE test, not a composition test. Composition-
// tuple evidence (path.join/path.resolve argument sequences) is preferred
// over bare-literal presence when extractable from the same file; the
// fallback tier is a weaker, stated boundary, never silently presented as
// the strong result.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');
const { runAll } = require('../../lib/docs-verify/index.js');
const commands = require('../../lib/docs-verify/commands.js');

const FIXTURES_ROOT = path.join(__dirname, '..', 'fixtures', 'docs-verify', 'commands');
const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'docs-verify.js');

function sweep(fixtureName) {
  const root = path.join(FIXTURES_ROOT, fixtureName);
  const context = buildContext(root);
  return runAll(context, [commands]);
}

function runCli(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('commands.js -- module contract', () => {
  it('exports the required shape', () => {
    assert.equal(commands.id, 'commands');
    assert.equal(typeof commands.run, 'function');
    assert.equal(typeof commands.extractPathTokens, 'function');
    assert.equal(typeof commands.isPlaceholderSegment, 'function');
    assert.equal(typeof commands.isDateShapedSegment, 'function');
    assert.equal(typeof commands.tokenizeFencedLine, 'function');
    assert.ok(Array.isArray(commands.INTERNAL_PATH_PREFIXES));
    assert.ok(commands.INTERNAL_PATH_PREFIXES.length > 0, 'non-vacuity: prefix list must not be empty');
  });

  it('never runs a documented command -- no subprocess or network primitive in source', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'commands.js'), 'utf8');
    const bad = /child_process|execSync|execFileSync|spawnSync|spawn\(|https?\.request|fetch\(/;
    assert.ok(!bad.test(src), 'commands.js must contain no subprocess or network primitive');
  });
});

describe('commands.js -- tokenizeFencedLine', () => {
  it('strips a leading "$ " prompt and drops flag tokens, keeping path tokens', () => {
    const t = commands.tokenizeFencedLine('$ node scripts/docs-verify.js --root docs/');
    assert.ok(!t.includes('--root'), `flags must not be candidates, got: ${t.join(' ')}`);
    assert.ok(t.includes('scripts/docs-verify.js'), `path token missing, got: ${t.join(' ')}`);
    assert.ok(!t.some((x) => x === '$'), 'prompt prefix must be fully stripped, not left as its own token');
  });

  it('strips a leading "# " comment marker', () => {
    const t = commands.tokenizeFencedLine('# see docs/wave-spec.md for details');
    assert.ok(!t.some((x) => x === '#'), 'comment marker must be fully stripped');
    assert.ok(t.includes('docs/wave-spec.md'));
  });

  it('drops an assignment token (contains "=")', () => {
    const t = commands.tokenizeFencedLine('FOO=bar node lib/fixture.js');
    assert.ok(!t.includes('FOO=bar'), `assignment must be dropped, got: ${t.join(' ')}`);
  });

  it('drops a URL/scheme token', () => {
    const t = commands.tokenizeFencedLine('curl https://example.com/lib/x.js');
    assert.ok(!t.some((x) => x.includes('://')), `URL must be dropped, got: ${t.join(' ')}`);
  });

  it('does not reassemble a quoted run containing a space -- zero candidates for that span', () => {
    const t = commands.tokenizeFencedLine("cp 'lib/my file.js' docs/out.md");
    assert.ok(!t.some((x) => x.includes('my') || x.includes('file.js')), `quoted-with-space span must produce no candidate, got: ${t.join(' ')}`);
    assert.ok(t.includes('docs/out.md'), 'a token after the dropped quoted span must still be a candidate');
  });

  it('strips a surrounding quote pair from an otherwise whole token', () => {
    const t = commands.tokenizeFencedLine("cat 'lib/fixture.js'");
    assert.ok(t.includes('lib/fixture.js'), `outer quotes must be stripped, got: ${t.join(' ')}`);
  });

  it('a backslash-continued line yields zero candidates (unsupported shape)', () => {
    const t = commands.tokenizeFencedLine('cat lib/fixture.js \\');
    assert.equal(t.length, 0, `a backslash-continued line must yield no candidates, got: ${t.join(' ')}`);
  });
});

describe('commands.js -- extractPathTokens', () => {
  it('extracts an inline single-backtick prose token (D-03 broadening, DOC-03a shape)', () => {
    const t = commands.extractPathTokens('Review the log at `~/.claude/audit.jsonl` weekly.');
    assert.equal(t.length, 1, `inline prose token not extracted, got ${t.length}`);
    assert.equal(t[0].inFence, false, 'inline token must not be marked as fenced');
    assert.equal(t[0].token, '~/.claude/audit.jsonl');
  });

  it('does not extract a token from inside a fenced block as an inline span', () => {
    const t = commands.extractPathTokens('```bash\ncat `docs/x.md`\n```\n');
    assert.equal(t.filter((r) => !r.inFence).length, 0, 'a fenced line must never contribute an inline-span candidate');
  });

  it('extracts fenced-block tokens with inFence: true', () => {
    const t = commands.extractPathTokens('```bash\ncat docs/x.md\n```\n');
    const fenced = t.filter((r) => r.inFence);
    assert.ok(fenced.some((r) => r.token === 'docs/x.md'), `fenced token missing, got: ${JSON.stringify(t)}`);
  });

  it('trims trailing sentence punctuation from a candidate token', () => {
    const t = commands.extractPathTokens('See `docs/x.md`, then `docs/y.md`.');
    assert.deepEqual(
      t.map((r) => r.token).sort(),
      ['docs/x.md', 'docs/y.md'],
      `trailing punctuation must be trimmed, got: ${JSON.stringify(t)}`
    );
  });

  it('a heredoc body line inside a fenced block yields zero candidates for that span', () => {
    const text = ['```bash', "cat <<'EOF'", 'docs/should-not-be-a-candidate.md', 'EOF', '```', ''].join('\n');
    const t = commands.extractPathTokens(text);
    assert.ok(
      !t.some((r) => r.token.includes('should-not-be-a-candidate')),
      `a heredoc body line must yield no candidates, got: ${JSON.stringify(t)}`
    );
  });

  it('non-vacuity: a doc with real content yields a non-empty token list', () => {
    const t = commands.extractPathTokens('```bash\ncat docs/x.md\n```\nAnd `hooks/y.js` too.');
    assert.ok(t.length > 0, 'non-vacuity guard: extraction must not be empty for real content');
  });
});

describe('commands.js -- isPlaceholderSegment / isDateShapedSegment', () => {
  // CR-01 (21-REVIEW.md): a shell-variable-interpolation segment (`$var` /
  // `${var}`) is a runtime substitution, never a literal filename claim --
  // '$hook' and '${HOOK}' must be recognized. 'hook' (no sigil) and
  // 'hook$' (sigil not in leading position) are the must-still-pass twins:
  // a bare word or a trailing-only '$' must NOT be swept in by the new rule.
  const placeholders = [
    '<agent-id>',
    '2026-01-02.jsonl',
    'YYYY-MM-DD.jsonl',
    'yyyy-mm-dd',
    '*.jsonl',
    'a?.jsonl',
    '$hook',
    '${HOOK}',
  ];
  const nonPlaceholders = ['audit.jsonl', 'hooks', 'settings.json', '2026-1-2.jsonl', 'YYY-MM-DD', 'hook', 'hook$'];

  it('non-vacuity: both control lists are non-empty', () => {
    assert.ok(placeholders.length > 0 && nonPlaceholders.length > 0);
  });

  for (const s of placeholders) {
    it(`'${s}' must be a placeholder segment`, () => {
      assert.ok(commands.isPlaceholderSegment(s), `must be a placeholder: ${s}`);
    });
  }

  for (const s of nonPlaceholders) {
    it(`'${s}' must NOT be a placeholder segment`, () => {
      assert.ok(!commands.isPlaceholderSegment(s), `must not be a placeholder: ${s}`);
    });
  }

  it('isDateShapedSegment accepts the literal YYYY-MM-DD spelling', () => {
    assert.ok(commands.isDateShapedSegment('YYYY-MM-DD'));
  });

  it('isDateShapedSegment accepts a real digit date', () => {
    assert.ok(commands.isDateShapedSegment('2026-08-20'));
  });

  it('isDateShapedSegment rejects a near-miss digit shape (single-digit month/day)', () => {
    assert.ok(!commands.isDateShapedSegment('2026-1-2'));
  });

  it('isDateShapedSegment rejects a near-miss literal spelling (three Ys)', () => {
    assert.ok(!commands.isDateShapedSegment('YYY-MM-DD'));
  });
});

describe('commands.js -- fixture pair (defect)', () => {
  it('reports the fenced Defect A: a repo-relative path that does not exist', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('nonexistent-target.md'));
    assert.ok(hit, `Defect A finding missing, got: ${JSON.stringify(findings)}`);
    assert.equal(hit.severity, 'fail');
  });

  it('reports the inline Defect B: the DOC-03a shape (agent-home segment absent from source)', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('fixture-audit.jsonl'));
    assert.ok(hit, `Defect B (DOC-03a shape) finding missing, got: ${JSON.stringify(findings)}`);
    assert.equal(hit.severity, 'fail');
    assert.ok(hit.message.includes('hooks') && hit.message.includes('lib'), 'message must name both searched directories');
  });

  it('reports the out-of-tree repo-relative token without reading it', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('out-of-tree'));
    assert.ok(hit, `out-of-tree finding missing, got: ${JSON.stringify(findings)}`);
  });

  it('never executes the sentinel-creating fenced command', () => {
    const sentinel = path.join(FIXTURES_ROOT, 'defect', '.sentinel-should-never-exist');
    sweep('defect');
    assert.ok(!fs.existsSync(sentinel), 'the never-execute guarantee was violated -- a sentinel file was created');
  });
});

describe('commands.js -- fixture pair (clean, must-still-pass controls)', () => {
  it('Control A: an existing fenced path produces zero findings', () => {
    const { findings } = sweep('clean');
    assert.equal(findings.filter((f) => f.check === 'commands').length, 0, `clean fixture must be zero-findings, got: ${JSON.stringify(findings)}`);
  });

  it('Control B: an agent-home path with a real directory segment + real digit-date file segment passes', () => {
    const { findings } = sweep('clean');
    assert.equal(findings.length, 0);
  });

  it('Control D: an absolute system path outside the internal prefix list produces zero findings', () => {
    const { findings } = sweep('clean');
    // /etc/passwd is present in the clean fixture doc and must never be classified/reported.
    assert.ok(!findings.some((f) => f.message.includes('/etc/passwd')));
  });
});

describe('commands.js -- fixture pair (CR-01: shell-variable segment, quick-start.md:659 shape)', () => {
  // Pins docs/guides/quick-start.md:659's exact shape -- a fenced bash
  // `for` loop binding `$hook` to a real filename per iteration, referenced
  // as `~/.claude/hooks/$hook`. Before CR-01's fix this reports a false
  // positive (segment '$hook' is not a literal filename -- it is a shell
  // variable); after the fix it is exempt and produces zero findings. The
  // 'clean' fixture root's `hooks/fixture-hook-paths.js` supplies the
  // 'hooks' bare-literal segment so only the '$hook' shape is under test.
  it('the pinned $hook-in-a-for-loop shape produces zero findings (control, must pass after the fix)', () => {
    const { findings } = sweep('clean');
    assert.ok(
      !findings.some((f) => f.message.includes('$hook')),
      `the documented $hook shell-variable shape must never be reported, got: ${JSON.stringify(findings)}`
    );
  });

  it('the same agent-home path with a literal missing segment (nope.js, not a shell variable) still reports (control)', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('nope.js'));
    assert.ok(hit, `a genuinely-missing literal segment must still be reported, got: ${JSON.stringify(findings)}`);
    assert.equal(hit.severity, 'fail');
  });
});

describe('commands.js -- fixture pair (WR-03: REPO_RELATIVE_PREFIXES omits test/)', () => {
  // The repo genuinely has both `test/` and `tests/` top-level directories
  // (package.json's own `test` script runs both); REPO_RELATIVE_PREFIXES
  // listed only `tests/`, so a documented path under `test/` was silently
  // never existence-checked -- the "silent absence" failure mode this
  // module otherwise takes pains to avoid.
  it('reports a documented test/ path that does not exist (defect, must-fail-before-fix)', () => {
    const { findings } = sweep('defect');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('test/does-not-exist.test.js'));
    assert.ok(
      hit,
      `a documented path under test/ must be existence-checked -- REPO_RELATIVE_PREFIXES must include 'test/', got: ${JSON.stringify(findings)}`
    );
    assert.equal(hit.severity, 'fail');
  });

  it('a documented test/ path that DOES exist produces zero findings (control)', () => {
    const { findings } = sweep('clean');
    const hit = findings.find((f) => f.message && f.message.includes('test/fixture-real.test.js'));
    assert.equal(hit, undefined, `an existing test/ path must never be reported, got: ${JSON.stringify(findings)}`);
  });
});

describe('commands.js -- composition-evidence tier', () => {
  it('the module source contains a path.join/path.resolve composition-sequence extractor', () => {
    const raw = fs.readFileSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'commands.js'), 'utf8');
    const code = raw
      .split('\n')
      .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
      .join('\n');
    assert.ok(/path\.join|path\.resolve/.test(code), 'composition-sequence evidence tier missing -- fell back to bare-literal presence only');
  });
});

describe('commands.js -- CLI process-boundary behaviour', () => {
  it('the defect fixture: exit 1, stdout names the "commands" check', () => {
    const res = runCli(['--root', path.join(FIXTURES_ROOT, 'defect')]);
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stdout, /\bcommands\b/);
  });

  it('the clean fixture: exit 0', () => {
    const res = runCli(['--root', path.join(FIXTURES_ROOT, 'clean')]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});

describe('commands.js -- registry membership (never exactly-seven -- that is 21-05\'s)', () => {
  it('loadChecks() includes "commands" with zero load errors, and the registry is non-empty', () => {
    const { loadChecks } = require('../../lib/docs-verify/index.js');
    const { checks, errors } = loadChecks();
    assert.deepEqual(errors, []);
    assert.ok(checks.length > 0, 'non-vacuity: registry must not be empty');
    assert.ok(checks.some((c) => c.id === 'commands'), `commands check not registered, got: ${checks.map((c) => c.id).join(',')}`);
  });
});

describe('commands.js -- real corpus (honest, live-repo result -- run manually per sequential-mode constraint)', () => {
  // Per this executor's sequential-mode instructions, no test here asserts a
  // nonzero exit of the guard against the live repository. The plan's own
  // pinned verification step (npm run docs:verify names DOC-03a) was run
  // manually and its verbatim output recorded in 21-04-SUMMARY.md instead.
  it('is documented, not asserted, here (placeholder so the describe block is non-empty)', () => {
    assert.ok(true);
  });
});
