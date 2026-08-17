'use strict';

// Shared ChainDrop (Aug 2026) scanner fixture builders (Phase 17 / TRAV-07,
// D-XX — promoted from the locally-defined `write`/`newHome`/`runScanner`
// trio in tests/chaindrop-scanner.test.js:27-54 so tests/chaindrop-parity.test.js
// and tests/traverse/*.test.js can reuse them without duplicating ~25 lines).
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// Fixtures are built at RUNTIME in an isolated HOME and never committed — a
// file literally named Math_Symbol.js or a real poisoned lockfile committed
// under tests/ is a self-scan hazard and would break the SELF_ROOT
// false-positive guard at tests/chaindrop-scanner.test.js:285-292 (the
// scanner is pointed at its own repo and must come back clean because the
// repo legitimately contains every IOC string as detection data).
//
// tests/chaindrop-scanner.test.js itself is NOT migrated to this helper in
// this plan — plan 17-14 owns that file and performs the migration.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const DEFAULT_SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'scan-chaindrop-aug2026.sh');
const hasBash = spawnSync('bash', ['-c', 'true']).status === 0;

// Write `contents` to `file`, creating parent directories as needed.
function write(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
}

// Build a throwaway HOME, hand it to `build`, return its path. `built` is an
// array the caller registers for cleanup (typically in an `after` hook):
// `built.forEach((h) => fs.rmSync(h, { recursive: true, force: true }))`.
function newHome(built, build) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-'));
  built.push(home);
  build(home, (rel) => path.join(home, rel));
  return home;
}

// Run the real bash scanner against an isolated HOME (+ clean TMPDIR),
// network disabled. extraEnv lets a test flip LSH_NO_NETWORK off or set
// LSH_ROOTS. `scriptPath` defaults to the bundled ChainDrop scanner but can
// be overridden so parity tests can name the script explicitly. `opts.tmpSeed`
// (Phase 17 / TRAV-05, plan 17-05, the bun-staging corpus case) is an
// optional `(tmpDir) => void` callback invoked AFTER the isolated TMPDIR is
// created but BEFORE the scanner runs, so a case can seed TMPDIR content
// (e.g. a bun-dl-* staging directory) that the scanner's own mkdtemp'd
// TMPDIR would otherwise make unreachable from the case's `build(home, p)`.
function runScanner(home, extraEnv = {}, scriptPath = DEFAULT_SCRIPT, opts = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-cd-tmp-'));
  if (typeof opts.tmpSeed === 'function') opts.tmpSeed(tmp);
  const res = spawnSync('bash', [scriptPath], {
    encoding: 'utf8',
    timeout: 60_000, // non-functional: a run must terminate well within this
    env: { HOME: home, TMPDIR: tmp, PATH: process.env.PATH, LSH_NO_NETWORK: '1', ...extraEnv },
  });
  fs.rmSync(tmp, { recursive: true, force: true });
  return res;
}

// ----------------------------------------------------------------------------
// Phase 19 (G-1549) additions below. These five exports are consumed by
// tests/miasma-scanner.test.js and, per 19-CONTEXT.md D-16, by the sibling
// g747/shai-hulud/chaindrop scanner test files waves 2-6 add -- do not fork
// a second fixture helper file; extend this one.
// ----------------------------------------------------------------------------

// Per-scanner hardcoded scan-root name lists. 19-CONTEXT.md's research
// correction: the three non-chaindrop scanners do NOT share one identical
// 5-name list -- scan-miasma-june2026.sh:110 additionally scans `go/src` and
// `dev`. Mirrors, verbatim, the literal root-name lists at:
//   scripts/scan-g747-may22.sh:92
//   scripts/scan-shai-hulud-may2026.sh:146
//   scripts/scan-miasma-june2026.sh:110
// None of these three scanners has an environment override for their scan
// roots (unlike chaindrop's LSH_ROOTS) -- a fixture written outside these
// names is silently invisible to the scanner, and the paired benign positive
// control every fixture below carries is what detects that failure mode.
const SEARCH_ROOT_NAMES = Object.freeze({
  g747: Object.freeze(['Projects', 'Code', 'Documents', 'src', 'Work']),
  shaiHulud: Object.freeze(['Projects', 'Code', 'Documents', 'src', 'Work']),
  miasma: Object.freeze(['Projects', 'Code', 'Documents', 'src', 'Work', 'go/src', 'dev']),
});

// Nine hostile filename fixtures, one per byte class in 19-VALIDATION.md's
// sampling matrix. Every value is a JS string literal built with \u/\\
// escapes -- NEVER a child_process/bash round-trip. A bash
// `$(printf '\x0a')` construction of the LF case silently yields an EMPTY
// string (command substitution strips trailing newlines), which would build
// a fixture that tests nothing; that construction is banned here for that
// reason.
const HOSTILE_NAMES = Object.freeze({
  ESC: '\u001b[2K', // real ESC (0x1B) followed by the 3-char erase-line CSI tail "[2K"
  CR: '\u000d', // real CR (0x0D) -- overwrites the current line
  LF: '\u000a', // real LF (0x0A) -- splits a `read -r` iteration (D-12 fail-open)
  C1: '\u009b', // real C1 CSI (encodes to the valid 2-byte UTF-8 sequence c2 9b)
  RLO: '\u202e', // U+202E RIGHT-TO-LEFT OVERRIDE -- bidi report-line spoof
  BS_C: '\\c', // literal 2 chars: backslash, c -- the ticket's %b truncation case
  BS_N: '\\n', // literal 2 chars: backslash, n -- the ticket's %b injection case
  PCT: '%s%s%s', // 3 consecutive %s directives -- format-string probe
  CJK: 'caf\u00e9-\u670d\u52a1\u5668', // café-服务器 -- the encoding control that must survive
});

// A lone 0x9B byte that is NOT part of a valid UTF-8 sequence (the valid
// 2-byte C1 sequence is c2 9b -- that is HOSTILE_NAMES.C1 above, a different
// input entirely). This is a Buffer, never a string: a JS string ''
// encodes to the VALID 2-byte sequence, so only a Buffer can carry the
// invalid lone byte. Gate: creating this filename raises EILSEQ on APFS
// (macOS cannot create the file at all) and glibc's [[:cntrl:]] cannot strip
// the byte in ANY locale, because it matches characters and a lone 0x9B is
// not one (T6, 19-CONTEXT.md) -- so every consumer must skip unless
// os.platform() === 'linux'. Do not remove the gate believing it is a
// portability wart: macOS cannot create the file; glibc cannot strip the
// byte. Its only consumer this phase is the Linux-gated pin in
// 19-07-PLAN.md; nothing in THIS plan writes it to disk.
const HOSTILE_NAME_BUFFERS = Object.freeze({
  C1_LONE_BYTE: Buffer.from([0x65, 0x76, 0x69, 0x6c, 0x9b, 0x2e, 0x74, 0x78, 0x74]), // "evil" + 0x9B + ".txt"
});

// Verified filesystem write for a hostile filename (the "fixture never
// contained the hostile byte" vacuity detector, 19-VALIDATION.md). Writes
// `contents` under `dirAbs/<name>`, reads the directory back, and THROWS
// with a diagnostic naming the hex of both sides unless the fixture actually
// landed on disk carrying the hostile bytes.
//
// `name` may be a string (the common case -- HOSTILE_NAMES) or a Buffer (the
// Linux-only lone-byte case, HOSTILE_NAME_BUFFERS.C1_LONE_BYTE; nothing in
// THIS plan writes that Buffer case to disk, but 19-07-PLAN.md's Linux-gated
// pin reuses this function for it).
//
// String names are verified two ways, NOT a strict byte comparison of the
// whole name: (a) every control code point `name` contains must appear in
// the on-disk entry, compared strictly; (b) entry.normalize('NFC') must
// equal name.normalize('NFC'). The NFC comparison is required because APFS
// normalizes 'é' to NFD -- a strict byte comparison of the WHOLE name would
// fail on macOS for a reason that has nothing to do with the property under
// test. APFS is otherwise normalization-PRESERVING -- measured directly
// across all six hostile classes (ESC, CR, LF, C1, RLO, NFD café), all six
// store byte-identically -- so this comparison is a real detector, not a
// workaround for a filesystem that mangles everything. Returns the absolute
// path of the verified on-disk entry.
function writeHostile(dirAbs, name, contents = '') {
  fs.mkdirSync(dirAbs, { recursive: true });
  const isBuffer = Buffer.isBuffer(name);
  const nameBuf = isBuffer ? name : Buffer.from(name, 'utf8');
  const filePath = Buffer.concat([Buffer.from(dirAbs + path.sep, 'utf8'), nameBuf]);
  fs.writeFileSync(filePath, contents);

  if (isBuffer) {
    const bufEntries = fs.readdirSync(dirAbs, { encoding: 'buffer' });
    const match = bufEntries.find((e) => Buffer.compare(e, nameBuf) === 0);
    if (!match) {
      throw new Error(
        'writeHostile: on-disk entry did not match the written Buffer name.\n' +
          `  wrote (hex): ${nameBuf.toString('hex')}\n` +
          `  found (hex): ${bufEntries.map((e) => e.toString('hex')).join(', ')}`
      );
    }
    return path.join(dirAbs, match.toString('binary'));
  }

  const entries = fs.readdirSync(dirAbs);
  const controlChars = [...name].filter((ch) => {
    const cp = ch.codePointAt(0);
    return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || cp === 0x202e;
  });
  const match = entries.find((entry) => {
    const hasAllControls = controlChars.every((ch) => entry.includes(ch));
    const nfcMatches = entry.normalize('NFC') === name.normalize('NFC');
    return hasAllControls && nfcMatches;
  });
  if (!match) {
    throw new Error(
      'writeHostile: on-disk entry did not preserve the hostile name.\n' +
        `  wrote (hex): ${Buffer.from(name, 'utf8').toString('hex')}\n` +
        `  found (hex): ${entries.map((e) => Buffer.from(e, 'utf8').toString('hex')).join(', ')}`
    );
  }
  return path.join(dirAbs, match);
}

// Two-level sentinel stub for `gh` (review R1-7). mkdtempSync a directory,
// write an executable `#!/bin/sh` file named `gh`, push the dir onto `built`
// for cleanup, and return { dir, sentinelLog }. Every invocation appends its
// full argument list to the sentinel log BEFORE doing anything else, so a
// test can assert which subcommands were attempted.
//
//   'unauthenticated' (default): exits 1 for every subcommand, so
//     `command -v gh` succeeds while `gh auth status` fails, driving
//     scan-shai-hulud-may2026.sh's repo-audit block down its
//     installed-but-unauthenticated branch with zero network traffic.
//   'authenticated-tripwire': succeeds for `auth status` and, if `repo
//     list` is ever reached, writes a loud marker to the sentinel log and
//     exits 1 without contacting anything -- this mode exists so
//     19-04-PLAN.md's break-proof can prove the stub is load-bearing by
//     CHANGING it rather than by REMOVING it (removing it would let a test
//     run make a real `gh repo list --limit 200` call on an authenticated
//     workstation, which the phase-wide prohibition forbids).
//
// Ticket G-1630 owns adding the LSH_NO_NETWORK guard to that block in the
// script itself; these stubs make the tests deterministic today without
// depending on G-1630 and without folding G-1630's fix into this phase.
function ghStub(built, mode = 'unauthenticated') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-gh-stub-'));
  built.push(dir);
  const sentinelLog = path.join(dir, 'gh-invocations.log');
  fs.writeFileSync(sentinelLog, '');

  const body =
    mode === 'authenticated-tripwire'
      ? `#!/bin/sh\nprintf '%s\\n' "$*" >> "${sentinelLog}"\ncase "$1 $2" in\n` +
        `  "auth status") exit 0 ;;\n` +
        `  "repo list") printf 'TRIPWIRE: gh repo list reached the stub in authenticated-tripwire mode\\n' >> "${sentinelLog}"; exit 1 ;;\n` +
        `  *) exit 1 ;;\nesac\n`
      : `#!/bin/sh\nprintf '%s\\n' "$*" >> "${sentinelLog}"\nexit 1\n`;

  fs.writeFileSync(path.join(dir, 'gh'), body);
  fs.chmodSync(path.join(dir, 'gh'), 0o755);

  return { dir, sentinelLog };
}

module.exports = {
  write,
  newHome,
  runScanner,
  hasBash,
  SEARCH_ROOT_NAMES,
  HOSTILE_NAMES,
  HOSTILE_NAME_BUFFERS,
  writeHostile,
  ghStub,
};
