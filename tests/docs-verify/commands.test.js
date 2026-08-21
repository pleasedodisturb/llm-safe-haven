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
    // G-1672 CR-01/WR-01: segmentStem and deriveAgentHomeOwnedSegments are
    // non-trivial pure functions with no direct unit coverage before this
    // fix -- exported specifically so isRepoOwnedAgentHomeToken (unit)
    // below can test them individually rather than only through fixture
    // sweeps (the coverage gap WR-01 names as how CR-01 shipped).
    assert.equal(typeof commands.segmentStem, 'function');
    assert.equal(typeof commands.deriveAgentHomeOwnedSegments, 'function');
    assert.equal(typeof commands.isRepoOwnedAgentHomeToken, 'function');
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

  it('G-1672 (D-02): hooks is a composed first segment -- a genuinely-absent deeper segment beneath it is still reported', () => {
    const { findings } = sweep('defect');
    assert.ok(findings.length > 0, 'non-vacuity: defect fixture must produce findings before filtering');
    const hit = findings.find((f) => f.check === 'commands' && f.message.includes('g1672-phantom.js'));
    assert.ok(hit, `G-1672 in-scope-deeper-segment finding missing, got: ${JSON.stringify(findings)}`);
    assert.equal(hit.severity, 'fail');
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

  it('G-1672 (D-02) Control H: an agent-home token whose first segment this repo does not compose produces zero findings', () => {
    const { findings } = sweep('clean');
    assert.ok(
      !findings.some((f) => f.message.includes('fixture-config')),
      `an agent-home token with an uncomposed first segment must never be reported, got: ${JSON.stringify(findings)}`
    );
  });

  it('G-1672 (D-02) Control I (anchoring): a deeper composed segment must not pull an uncomposed first segment back into scope', () => {
    const { findings } = sweep('clean');
    assert.ok(
      !findings.some((f) => f.message.includes('fixture-profiles') || f.message.includes('settings.json')),
      `the anchoring test failed -- a deeper composed segment wrongly widened scope, got: ${JSON.stringify(findings)}`
    );
  });

  it('G-1672 (D-02) Control J (CR-01 fix): a stem match must not widen scope when the anchor has a segment below it', () => {
    const { findings } = sweep('clean');
    assert.ok(
      !findings.some((f) => f.message.includes('fixture-profile.json')),
      `CR-01: a directory-shaped token sharing only a derived STEM with a composed file's name must never be reported, got: ${JSON.stringify(findings)}`
    );
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

describe('commands.js -- segmentStem (unit, WR-01)', () => {
  // WR-01 (22-REVIEW.md): direct, parameterized coverage of the pure
  // function, derived from its own grammar (dot-splitting rules), not from
  // CR-01's specific bug shape.
  const cases = [
    { input: 'audit', expected: 'audit', label: 'no dot -- unchanged' },
    { input: 'audit.jsonl', expected: 'audit', label: 'single dot -- strips the extension' },
    { input: 'a.b.c', expected: 'a.b', label: 'multi-dot -- strips only the LAST dot' },
    { input: '.credentials.json', expected: '.credentials', label: 'leading-dot dotfile WITH a further extension' },
    { input: '.hidden', expected: '.hidden', label: 'bare dotfile, no further dot -- unchanged' },
  ];

  it('non-vacuity: the case table is non-empty', () => {
    assert.ok(cases.length > 0, 'non-vacuity guard: case table must not be empty');
  });

  for (const c of cases) {
    it(`'${c.input}' (${c.label}) -> '${c.expected}'`, () => {
      assert.equal(commands.segmentStem(c.input), c.expected);
    });
  }
});

describe('commands.js -- deriveAgentHomeOwnedSegments (unit, WR-01 + CR-01)', () => {
  // CR-01: deriveAgentHomeOwnedSegments must return TWO separate sets --
  // exact composed segments and their stems -- never merge them into one
  // set, which is what let a stem accidentally satisfy an exact-match
  // check regardless of the anchor's position in the token.
  it('derives an exact set and a SEPARATE stem set from synthetic composition tuples', () => {
    const tuples = [
      ['.claude', 'audit'],
      ['.claude', 'hooks'],
      ['.claude', 'settings.json'],
    ];
    const result = commands.deriveAgentHomeOwnedSegments(tuples);
    assert.deepEqual([...result.agentHomeOwnedSegments].sort(), ['audit', 'hooks', 'settings.json']);
    assert.deepEqual([...result.agentHomeOwnedStems].sort(), ['audit', 'hooks', 'settings']);
  });

  it('a tuple without the .claude segment anywhere contributes nothing to either set', () => {
    const result = commands.deriveAgentHomeOwnedSegments([['unrelated', 'thing']]);
    assert.equal(result.agentHomeOwnedSegments.size, 0);
    assert.equal(result.agentHomeOwnedStems.size, 0);
  });

  it('.claude as the LAST element of a tuple (nothing follows it) contributes nothing', () => {
    const result = commands.deriveAgentHomeOwnedSegments([['x', '.claude']]);
    assert.equal(result.agentHomeOwnedSegments.size, 0);
    assert.equal(result.agentHomeOwnedStems.size, 0);
  });
});

describe('commands.js -- isRepoOwnedAgentHomeToken (unit, CR-01 + WR-01)', () => {
  // Synthetic evidence mirroring the real repo's own derived set (see the
  // module docstring: hooks/audit-logger.js + lib/agents/claude-code.js +
  // lib/update.js compose {audit, hooks, settings.json} under '.claude',
  // whose stems are {audit, hooks, settings}) -- called directly, not
  // through a fixture sweep, per WR-01.
  const evidence = {
    agentHomeOwnedSegments: new Set(['audit', 'hooks', 'settings.json']),
    agentHomeOwnedStems: new Set(['audit', 'hooks', 'settings']),
  };

  it('non-vacuity: both synthetic evidence sets are non-empty', () => {
    assert.ok(
      evidence.agentHomeOwnedSegments.size > 0 && evidence.agentHomeOwnedStems.size > 0,
      'non-vacuity guard: synthetic evidence sets must not be empty'
    );
  });

  // The segment-position x match-tier matrix WR-01 asks for: anchor is the
  // token's final segment vs. anchor has a segment below it, each crossed
  // with an exact match, a stem-only match, or no match at all.
  const cases = [
    {
      segments: ['audit.jsonl'],
      expected: true,
      label: 'stem match, anchor IS the final segment (DOC-03a shape -- stays in scope so grading can still fail it)',
    },
    {
      segments: ['audit', '2026-08-21.jsonl'],
      expected: true,
      label: 'exact match on the anchor, real segment below it',
    },
    {
      segments: ['hooks', 'g1672-phantom.js'],
      expected: true,
      label: 'exact match (Defect C shape) -- a genuinely-absent deeper segment is still graded, not filtered here',
    },
    {
      segments: ['settings.json'],
      expected: true,
      label: 'exact match, single segment',
    },
    {
      segments: ['settings', 'work.json'],
      expected: false,
      label: 'CR-01: stem-only match, anchor has a segment BELOW it -- must be OUT of scope',
    },
    {
      segments: ['settings'],
      expected: true,
      label: "CR-01's must-still-pass twin: same stem, but the anchor IS the token's final segment",
    },
    {
      segments: ['config.json'],
      expected: false,
      label: 'neither an exact nor a stem match',
    },
    {
      segments: ['profiles', 'work', 'settings.json'],
      expected: false,
      label: 'first segment not composed -- a deeper composed segment must not widen scope (Control I shape)',
    },
    {
      segments: ['.credentials.json'],
      expected: false,
      label: 'no exact or stem match (dotfile)',
    },
    {
      segments: ['<agent-id>', 'audit.jsonl'],
      expected: true,
      label: 'a leading placeholder segment is skipped when locating the anchor',
    },
  ];

  it('non-vacuity: the case table is non-empty', () => {
    assert.ok(cases.length > 0, 'non-vacuity guard: case table must not be empty');
  });

  for (const c of cases) {
    it(`${JSON.stringify(c.segments)} -> ${c.expected} (${c.label})`, () => {
      assert.equal(commands.isRepoOwnedAgentHomeToken(c.segments, evidence), c.expected);
    });
  }

  it('a token with no non-placeholder segment at all is vacuously in scope', () => {
    assert.equal(commands.isRepoOwnedAgentHomeToken(['<a>', '*.jsonl'], evidence), true);
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
