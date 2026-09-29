'use strict';

// bash-firewall structural hardening (quick task 260928-ojp).
//
// G-1799: a fail-closed input cap plus linear-time checks. A hook that Claude
//   Code kills at its per-hook timeout renders no decision and the tool call
//   PROCEEDS — so a slow regex is a bypass, not a performance nit. Every timing
//   generator runs through the REAL hook process (tests/helpers/hook-runner.js).
//   What makes these tests fail: MAX_COMMAND_CHARS missing or not 100000; an
//   over-cap command not blocked; any generator killed, errored, or >= 1000 ms.
//
// Attack-shaped inputs are built at runtime from fragments
// (tests/helpers/shell-case.js); assertion messages print labels only.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const fw = require('../hooks/bash-firewall.js');
const { runFirewall } = require('./helpers/hook-runner.js');

// ---------------------------------------------------------------------------
// G-1799 firewall input cap and linear time
// ---------------------------------------------------------------------------

const CAP = 100000; // literal on purpose — do not derive from the export
const BOUND_MS = 1000;

/** prefix + unit repeated as many whole times as fit + suffix, total <= target. */
function fill(prefix, unit, suffix, target) {
  const room = target - prefix.length - suffix.length;
  const n = Math.max(0, Math.floor(room / unit.length));
  return prefix + unit.repeat(n) + suffix;
}

function quotedHeredocInSubstitution(target) {
  // git commit -m "$(cat <<'EOF'\n<20,000 lines>\nEOF\n)"
  const head = 'git commit -m "$(cat <<\'EOF\'\n';
  const tail = '\nEOF\n)"';
  const lines = 20000;
  const room = target - head.length - tail.length - (lines - 1); // newlines between lines
  const per = Math.floor(room / lines);
  const body = new Array(lines).fill('x'.repeat(per)).join('\n');
  const s = head + body + tail;
  // top up the first line so the length lands in the window
  const pad = target - s.length;
  return head + 'y'.repeat(Math.max(0, pad)) + body + tail;
}

function nestedDollarParen(depth, target) {
  const nest = '$('.repeat(depth) + 'echo' + ')'.repeat(depth);
  return fill('echo ', 'x', ' ' + nest, target);
}

const T = CAP - 16;
const TIMING_GENERATORS = [
  ['word-run', () => fill('', 'a', '', T)],
  ['echo-then-greater-than-run', () => fill('echo ', '>', '', T)],
  ['base64-token-repeat', () => fill('', 'base64 ', '', T)],
  ['curl-token-repeat', () => fill('', 'curl ', '', T)],
  ['wget-token-repeat', () => fill('', 'wget ', '', T)],
  ['funcdef-repeat', () => fill('', 'f(){ ', '', T)],
  ['colon-funcdef-repeat', () => fill('', ':(){ ', '', T)],
  ['word-paren-repeat', () => fill('', 'a(', '', T)],
  ['space-dash-flag-repeat', () => fill('ls', ' -a', '', T)],
  ['whitespace-run', () => fill('echo', ' ', 'x', T)],
  ['pipe-repeat', () => fill('', 'a|', 'a', T)],
  ['empty-double-quote-repeat', () => fill('echo ', '""', '', T)],
  ['dollar-paren-nesting-5000', () => nestedDollarParen(5000, T)],
  ['backtick-pair-repeat', () => fill('echo ', '``', '', T)],
  ['single-quote-pair-repeat', () => fill('echo ', "''", '', T)],
  ['quoted-heredoc-20000-lines-in-substitution', () => quotedHeredocInSubstitution(T)],
  ['hash-repeat', () => fill('echo a ', '#', '', T)],
  ['ansi-c-hex-escape-repeat', () => fill("echo $'", '\\x41', "'", T)],
];

describe('G-1799 firewall input cap and linear time', () => {
  it('exports MAX_COMMAND_CHARS equal to 100000', () => {
    assert.equal(fw.MAX_COMMAND_CHARS, CAP);
  });

  it('blocks a benign command of CAP+1 chars (runChecks and the real hook)', () => {
    const cmd = fill('echo', ' ab', '', CAP + 8).slice(0, CAP + 1);
    assert.equal(cmd.length, CAP + 1);
    const reason = fw.runChecks(cmd);
    assert.ok(reason, 'over-cap command must be blocked by runChecks');
    assert.match(reason, /exceeds|too large/i);
    const res = runFirewall(cmd);
    assert.equal(res.decision, 'block', `over-cap hook decision was ${res.decision}`);
  });

  it('twin: allows a benign 50,000-char command (runChecks and the real hook)', () => {
    const cmd = fill('echo', ' ab', '', 50000);
    assert.ok(cmd.length > 49990 && cmd.length <= 50000);
    assert.equal(fw.runChecks(cmd), null);
    const res = runFirewall(cmd);
    assert.equal(res.decision, 'allow', `50k hook decision was ${res.decision}`);
  });

  it('timing battery is non-vacuous (>= 18 generators, each within CAP-64..CAP)', () => {
    assert.ok(TIMING_GENERATORS.length >= 18, `only ${TIMING_GENERATORS.length} generators`);
    for (const [name, gen] of TIMING_GENERATORS) {
      const len = gen().length;
      assert.ok(len >= CAP - 64 && len <= CAP, `${name}: length ${len} outside CAP-64..CAP`);
    }
  });

  for (const [name, gen] of TIMING_GENERATORS) {
    it(`timing: ${name} finishes in the real hook under ${BOUND_MS} ms`, () => {
      const res = runFirewall(gen(), { timeoutMs: 4500 });
      assert.equal(res.signal, null, `${name}: hook killed by ${res.signal} after ${Math.round(res.elapsedMs)} ms`);
      assert.notEqual(res.decision, 'error', `${name}: hook errored (status ${res.status})`);
      assert.ok(res.elapsedMs < BOUND_MS, `${name}: took ${Math.round(res.elapsedMs)} ms`);
    });
  }
});

module.exports = { TIMING_GENERATORS, CAP };
