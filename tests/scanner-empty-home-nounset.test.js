'use strict';

// Regression (G-1549 follow-up): the four bundled supply-chain scanners run
// under `set -u` (nounset). On bash < 4.4 — which is the STOCK macOS
// interpreter, /bin/bash 3.2.57 — expanding an EMPTY array as `"${arr[@]}"`
// is a fatal "unbound variable" that kills the shell mid-run. bash >= 4.4
// (Homebrew on macOS, every mainstream Linux) treats empty `"${arr[@]}"` as
// zero arguments, so a developer machine with Homebrew bash SILENTLY MASKS
// the bug — it only reproduces on the stock macOS interpreter, which is
// exactly a real user's `bash scripts/scan-...` on a fresh Mac.
//
// The concrete failure this file locks down: a machine with none of the six
// common code directories under $HOME (a container, a CI runner, a tidy Mac)
// leaves the discovery array `SEARCH_ROOTS` — and its siblings SETTINGS_FILES,
// RC_FILES, HIST_FILES, EXT_DIRS, AI_CONFIG_ROOTS — EMPTY. If any of those is
// then expanded as `"${arr[@]}"` in a for/find/grep without an empty-safe
// guard, the scanner aborts, and every section after that point is silently
// skipped. For a security scanner that is a fail-open: the SessionStart hook
// audit (and everything below it) never runs, yet the user only sees a raw
// bash error, not a "did not finish" verdict.
//
// What makes a case here FAIL: reaching an emptyable-array expansion with no
// empty-safe guard while the array is empty. What makes it PASS: the scanner
// runs to its final `== Summary ==` banner with no `set -u` abort on stderr.
//
// This test runs each scanner under the OS's OWN /bin/bash (3.2 on macOS,
// where it bites; 5.x on Linux, where the assertions still hold but cannot
// reproduce the bug — same platform-asymmetry the repo already documents for
// the RLO / lone-0x9B sanitizer cases). It does NOT use the PATH `bash`,
// precisely because a Homebrew bash 5 would mask the very regression it
// guards.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const STOCK_BASH = '/bin/bash';
const HAVE_STOCK_BASH = fs.existsSync(STOCK_BASH)
  && spawnSync(STOCK_BASH, ['-c', 'true']).status === 0;

const SCANNERS = Object.freeze([
  'scan-chaindrop-aug2026.sh',
  'scan-g747-may22.sh',
  'scan-miasma-june2026.sh',
  'scan-shai-hulud-may2026.sh',
]);

// A PATH stub whose `gh` reports "not authenticated" (exit 1 for any args),
// so the scanners' GitHub dead-drop sections skip cleanly instead of reaching
// the network (shai-hulud/g747 gate that section on `gh auth status`, not on
// LSH_NO_NETWORK — and this session's real gh IS authenticated). Keeps the
// test hermetic and fast regardless of the host's gh state.
let stubBin;

describe('scanners run to completion under stock /bin/bash with an empty $HOME (set -u empty-array, bash 3.2)', () => {
  // Non-vacuity: the scanner set is the real four, and each file exists — an
  // empty or mistyped list would make the loop below assert nothing.
  assert.equal(SCANNERS.length, 4, 'expected exactly the four bundled scanners');
  for (const s of SCANNERS) {
    assert.ok(fs.existsSync(path.join('scripts', s)), `missing scanner script: scripts/${s}`);
  }

  before(() => {
    stubBin = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-stubbin-'));
    const ghStub = path.join(stubBin, 'gh');
    // Exit 1 on everything, including `gh auth status`, => "not authenticated".
    fs.writeFileSync(ghStub, '#!/bin/sh\nexit 1\n');
    fs.chmodSync(ghStub, 0o755);
  });

  after(() => {
    if (stubBin) fs.rmSync(stubBin, { recursive: true, force: true });
    stubBin = undefined;
  });

  for (const scanner of SCANNERS) {
    it(`${scanner}: empty HOME → no set -u abort, reaches the "== Summary ==" banner`,
      { skip: HAVE_STOCK_BASH ? false : 'no working /bin/bash on this host' },
      () => {
        const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-emptyhome-'));
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-emptyhome-tmp-'));
        try {
          const res = spawnSync(STOCK_BASH, [path.join('scripts', scanner)], {
            encoding: 'utf8',
            timeout: 60_000,
            env: {
              HOME: home,
              TMPDIR: tmp,
              PATH: `${stubBin}:${process.env.PATH}`,
              LSH_NO_NETWORK: '1',
            },
          });

          // The process must not be killed by the 60s timeout.
          assert.equal(res.signal, null, `${scanner} was killed by signal ${res.signal} (timeout?)`);

          // Direct symptom: nounset fired on an empty array expansion.
          assert.ok(
            !/unbound variable/.test(res.stderr || ''),
            `${scanner} hit a set -u "unbound variable" under stock /bin/bash — an emptyable discovery array was expanded as "\${arr[@]}" without an empty-safe guard.\nstderr:\n${res.stderr}`
          );

          // Any bash runtime error prints "<script>: line N:" — there must be none.
          assert.ok(
            !new RegExp(`${scanner.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: line \\d+:`).test(res.stderr || ''),
            `${scanner} emitted a bash runtime error under stock /bin/bash.\nstderr:\n${res.stderr}`
          );

          // Ran to completion: the final section banner is present. A mid-run
          // set -u abort exits the shell before this line ever prints.
          assert.ok(
            (res.stdout || '').includes('== Summary =='),
            `${scanner} did not reach its "== Summary ==" section under stock /bin/bash — it aborted mid-run, so every later check (a fail-open for a security scanner) was skipped.\nexit=${res.status} signal=${res.signal}\nstderr:\n${res.stderr}\nstdout tail:\n${(res.stdout || '').slice(-500)}`
          );

          // Exit status honours the 0/1/2 contract, never a raw shell-abort.
          // An empty HOME may still surface a /tmp-based IOC, so 0 (clean),
          // 1 (findings) and 2 (incomplete) are all legitimate; anything else
          // (126/127/2-from-nounset-with-set-e style) is not.
          assert.ok(
            [0, 1, 2].includes(res.status),
            `${scanner} exited ${res.status} under stock /bin/bash (expected the 0/1/2 contract).\nstderr:\n${res.stderr}`
          );
        } finally {
          fs.rmSync(home, { recursive: true, force: true });
          fs.rmSync(tmp, { recursive: true, force: true });
        }
      });
  }
});
