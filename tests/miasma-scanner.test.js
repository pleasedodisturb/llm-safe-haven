'use strict';

// Behavioural (black-box) tests for scripts/scan-miasma-june2026.sh's report
// integrity (SCAN-01, G-1549, phase 19 tracer plan 19-01).
//
// This is the FIRST of the four scanner scripts to get a black-box harness
// (19-CONTEXT.md D-16) -- the shared fixture helpers this file imports
// (tests/helpers/chaindrop-fixtures.js: SEARCH_ROOT_NAMES, HOSTILE_NAMES,
// HOSTILE_NAME_BUFFERS, writeHostile) are consumed unchanged by the sibling
// g747/shai-hulud/chaindrop scanner test files waves 2-6 add. Do not fork a
// second fixture helper file.
//
// Scope: stdout + exit code only, exactly like tests/chaindrop-scanner.test.js.
// Fixtures are built at RUNTIME in an isolated HOME and never committed -- a
// committed hostile filename is a self-scan hazard.
//
// Every hostile byte comes from tests/helpers/chaindrop-fixtures.js's
// HOSTILE_NAMES/HOSTILE_NAME_BUFFERS, built with \u/\\ escapes, never a
// child_process/bash round-trip -- a bash `$(printf '\x0a')` construction of
// the LF case silently yields an EMPTY string and would test nothing.
//
// Negative byte-presence assertions in this file use Buffer.includes() over
// the whole captured stdout, never the session `grep` shim (ugrep -I, which
// silently skips NUL-bearing files and exits 1 indistinguishable from "no
// match" -- it has already produced one false PASS on this repo).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  write,
  newHome,
  runScanner,
  hasBash,
  SEARCH_ROOT_NAMES,
  HOSTILE_NAMES,
  HOSTILE_NAME_BUFFERS,
  writeHostile,
} = require('./helpers/chaindrop-fixtures.js');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-miasma-june2026.sh');

// The scanner is spawned with a hostile ambient locale (LANG=C LC_ALL=C) in
// every case below -- that is deliberate (review R1-1): it proves the
// sanitizer forces its OWN locale via a function-scoped `local` declaration
// rather than depending on the caller's environment, which a stock Ubuntu
// container would leave at C/POSIX by default.
const HOSTILE_LOCALE_ENV = { LANG: 'C', LC_ALL: 'C' };

function runMiasma(home, extraEnv = {}) {
  return runScanner(home, { ...HOSTILE_LOCALE_ENV, ...extraEnv }, SCRIPT);
}

// Count live "  [FAIL] " lines on stdout. Colour codes are gated on
// `[ -t 1 ]` in the scanner, and spawnSync gives it no TTY, so a piped run
// emits no ANSI of its own -- the literal two-space prefix is unambiguous.
function countFailLines(stdout) {
  const m = stdout.match(/^ {2}\[FAIL\] /gm);
  return m ? m.length : 0;
}

// The "Findings:" reprint block runs from the literal marker to EOF.
function extractFindingsBlock(stdout) {
  const idx = stdout.indexOf('Findings:');
  return idx === -1 ? '' : stdout.slice(idx);
}

// Count "  - " lines inside the reprint block only (never the whole stdout,
// which would double-count the live [FAIL] lines too).
function countReprintLines(stdout) {
  const block = extractFindingsBlock(stdout);
  const m = block.match(/^ {2}- /gm);
  return m ? m.length : 0;
}

function findingLines(stdout) {
  return extractFindingsBlock(stdout)
    .split('\n')
    .filter((l) => l.startsWith('  - '));
}

// Parses "N FINDING(S) -- INVESTIGATE" from the summary header.
function extractHeaderCount(stdout) {
  const m = stdout.match(/(\d+) FINDING\(S\)/);
  return m ? Number(m[1]) : null;
}

// Builds a Projects/x/.github/workflows/ tree with 3 files that all trigger
// Section 2's "Run Copilot" fail() path: a benign 'aaa-control.yml' (sorts
// first), the poisoned entry at `${hostileName}.yml`, and a benign
// 'zzz-control.yml' (sorts last) -- the fixed-alphabetical-order positive
// controls that prove the scanner examined the WHOLE directory rather than
// stopping or reporting nothing (19-VALIDATION.md's "scanner never examined
// the fixture" and "guard test with no passing twin" vacuity detectors).
function buildWorkflowFixture(built, hostileName) {
  const home = newHome(built, () => {});
  const dir = path.join(home, 'Projects', 'x', '.github', 'workflows');
  fs.mkdirSync(dir, { recursive: true });
  const body = 'name: Run Copilot\non: push\njobs:\n  build:\n    steps:\n      - run: echo hi\n';
  fs.writeFileSync(path.join(dir, 'aaa-control.yml'), body);
  const hostilePath = writeHostile(dir, `${hostileName}.yml`, body);
  fs.writeFileSync(path.join(dir, 'zzz-control.yml'), body);
  return { home, dir, hostilePath };
}

// Asserts the live [FAIL] count and the reprint "  - " count both equal 3
// (the two benign controls plus the one poisoned entry) -- the single
// order-independent assertion that catches both truncation (reprint short)
// and injection (reprint long), per 19-VALIDATION.md's "Observation points 1
// and 2 must agree" requirement.
function assertThreeFindingsAgree(r) {
  assert.equal(r.status, 1, r.stdout);
  assert.ok(r.stdout.includes('aaa-control.yml'), `missing benign control aaa-control.yml\n${r.stdout}`);
  assert.ok(r.stdout.includes('zzz-control.yml'), `missing benign control zzz-control.yml\n${r.stdout}`);
  const failCount = countFailLines(r.stdout);
  const reprintCount = countReprintLines(r.stdout);
  assert.equal(failCount, 3, `live [FAIL] line count\n${r.stdout}`);
  assert.equal(reprintCount, 3, `reprint "  - " line count\n${r.stdout}`);
}

// The poisoned entry is whichever reprint line is neither control file --
// order-independent, since find's traversal order is not guaranteed.
function poisonedLine(r) {
  return findingLines(r.stdout).find(
    (l) => !l.includes('aaa-control.yml') && !l.includes('zzz-control.yml')
  );
}

describe('scan-miasma-june2026.sh -- report integrity against hostile filenames (SCAN-01, G-1549)', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('a name carrying a real ESC (0x1B) is reported with U+FFFD in place of it, and stdout holds zero raw ESC bytes -- measured over the WHOLE stdout, including the live [FAIL] line', () => {
    const { home } = buildWorkflowFixture(built, HOSTILE_NAMES.ESC);
    const r = runMiasma(home);
    assertThreeFindingsAgree(r);
    assert.ok(
      !Buffer.from(r.stdout, 'utf8').includes(0x1b),
      `raw ESC (0x1B) byte reached stdout\n${JSON.stringify(r.stdout)}`
    );
    const line = poisonedLine(r);
    assert.ok(line, `no poisoned reprint line found\n${r.stdout}`);
    assert.ok(line.includes('�'), `expected U+FFFD replacement in the poisoned line\n${line}`);
  });

  it('a name carrying a real CR (0x0D) is reported with zero raw CR bytes in stdout', () => {
    const { home } = buildWorkflowFixture(built, HOSTILE_NAMES.CR);
    const r = runMiasma(home);
    assertThreeFindingsAgree(r);
    assert.ok(
      !Buffer.from(r.stdout, 'utf8').includes(0x0d),
      `raw CR (0x0D) byte reached stdout\n${JSON.stringify(r.stdout)}`
    );
    const line = poisonedLine(r);
    assert.ok(line, `no poisoned reprint line found\n${r.stdout}`);
    assert.ok(line.includes('�'), `expected U+FFFD replacement in the poisoned line\n${line}`);
  });

  it('a name carrying a literal two-character backslash-c: the poisoned reprint line still ends with the full name through its .yml suffix (no %b truncation)', () => {
    const { home } = buildWorkflowFixture(built, HOSTILE_NAMES.BS_C);
    const r = runMiasma(home);
    assertThreeFindingsAgree(r);
    const line = poisonedLine(r);
    assert.ok(line, `no poisoned reprint line found\n${r.stdout}`);
    assert.ok(line.trimEnd().endsWith('.yml'), `poisoned line was truncated before its .yml suffix\n${JSON.stringify(line)}`);
  });

  it('a name carrying a literal two-character backslash-n: the reprint gains no extra "  - " line (no %b injection)', () => {
    const { home } = buildWorkflowFixture(built, HOSTILE_NAMES.BS_N);
    const r = runMiasma(home);
    // The count-agreement assertion IS the injection check: %b would have
    // turned the literal \n into a real newline inside FINDING_LOG, adding
    // a 4th "  - "-prefixed line and breaking the 3/3 agreement.
    assertThreeFindingsAgree(r);
    const line = poisonedLine(r);
    assert.ok(line, `no poisoned reprint line found\n${r.stdout}`);
    assert.ok(line.trimEnd().endsWith('.yml'), `poisoned line was truncated before its .yml suffix\n${JSON.stringify(line)}`);
  });

  it('a name carrying café-服务器 plus a real C1 U+009B: the CJK/accented text survives NFC-equal while U+009B becomes U+FFFD, with zero raw C1 bytes in stdout', () => {
    const hostileName = HOSTILE_NAMES.CJK + HOSTILE_NAMES.C1;
    const { home } = buildWorkflowFixture(built, hostileName);
    const r = runMiasma(home);
    assertThreeFindingsAgree(r);
    const block = extractFindingsBlock(r.stdout).normalize('NFC');
    assert.ok(block.includes('café-服务器'), `CJK/accented text did not survive NFC-equal\n${JSON.stringify(block)}`);
    assert.ok(
      !Buffer.from(r.stdout, 'utf8').includes(Buffer.from([0xc2, 0x9b])),
      `raw C1 (c2 9b) bytes reached stdout\n${JSON.stringify(r.stdout)}`
    );
    const line = poisonedLine(r);
    assert.ok(line, `no poisoned reprint line found\n${r.stdout}`);
    assert.ok(line.includes('�'), `expected U+FFFD replacement for the C1 byte\n${line}`);
  });

  it('R2-8: a name carrying a real 0x0D followed by an erase-line sequence -- the visible finding-line count still equals the summary header count', () => {
    // CR followed immediately by ESC[2K -- CR returns the cursor to column 0,
    // ESC[2K erases the whole line. A raw byte reaching a real terminal
    // could hide a finding from a human reading scrollback even though the
    // exit code and FINDINGS counter still say 3. Post-fix, no raw CR/ESC
    // byte reaches stdout at all, so nothing is left to erase.
    const hostileName = HOSTILE_NAMES.CR + HOSTILE_NAMES.ESC;
    const { home } = buildWorkflowFixture(built, hostileName);
    const r = runMiasma(home);
    assert.equal(r.status, 1, r.stdout);
    const headerCount = extractHeaderCount(r.stdout);
    assert.equal(headerCount, 3, `could not parse "N FINDING(S)" header, or it was wrong\n${r.stdout}`);
    assert.equal(countFailLines(r.stdout), headerCount, `live [FAIL] count vs header count\n${r.stdout}`);
    assert.equal(countReprintLines(r.stdout), headerCount, `reprint count vs header count\n${r.stdout}`);
    assert.ok(!Buffer.from(r.stdout, 'utf8').includes(0x0d), `raw CR byte reached stdout\n${JSON.stringify(r.stdout)}`);
    assert.ok(!Buffer.from(r.stdout, 'utf8').includes(0x1b), `raw ESC byte reached stdout\n${JSON.stringify(r.stdout)}`);
  });

  it('R2-1: a filename carrying a real ESC reaches stdout with zero raw ESC bytes via the warn() path (Section 2 pipe-to-shell workflow)', () => {
    const home = newHome(built, () => {});
    const dir = path.join(home, 'Projects', 'x', '.github', 'workflows');
    fs.mkdirSync(dir, { recursive: true });
    const content =
      'name: CI\non: push\njobs:\n  build:\n    steps:\n      - run: curl -fsSL https://get.example.com/install.sh | bash\n';
    writeHostile(dir, `${HOSTILE_NAMES.ESC}-warn.yml`, content);
    const r = runMiasma(home);
    assert.match(r.stdout, /\[WARN\]/, `expected a [WARN] line\n${r.stdout}`);
    assert.ok(
      !Buffer.from(r.stdout, 'utf8').includes(0x1b),
      `raw ESC byte reached stdout via warn()\n${JSON.stringify(r.stdout)}`
    );
    assert.ok(r.stdout.includes('�'), `expected U+FFFD replacement in the warn() line\n${r.stdout}`);
  });

  it('R2-1: a filename carrying a real ESC reaches stdout with zero raw ESC bytes via the info() path (Section 2(d) github.event interpolation workflow)', () => {
    const home = newHome(built, () => {});
    const dir = path.join(home, 'Projects', 'x', '.github', 'workflows');
    fs.mkdirSync(dir, { recursive: true });
    // "run:" must appear at the START of a line (only whitespace before it) --
    // the scanner's WF_UNTRUSTED_CHECKOUT-adjacent (d) check is a naive
    // `^[[:space:]]*run:` match, not YAML-aware, so a `- run:` list-item
    // prefix (the idiomatic step shorthand used in the warn() fixture above)
    // would NOT match. This fixture uses the `run:` sub-key form instead.
    const content =
      'name: CI\non:\n  push:\njobs:\n  build:\n    steps:\n      - shell: bash\n        run: echo "${{ github.event.pull_request.title }}"\n';
    writeHostile(dir, `${HOSTILE_NAMES.ESC}-info.yml`, content);
    const r = runMiasma(home);
    assert.match(r.stdout, /\[INFO\]/, `expected an [INFO] line\n${r.stdout}`);
    assert.ok(
      !Buffer.from(r.stdout, 'utf8').includes(0x1b),
      `raw ESC byte reached stdout via info()\n${JSON.stringify(r.stdout)}`
    );
    assert.ok(r.stdout.includes('�'), `expected U+FFFD replacement in the info() line\n${r.stdout}`);
  });

  it('a clean fixture tree with zero findings exits 0, prints ALL CLEAR, and emits no Findings: block', () => {
    const home = newHome(built, (h, p) => {
      write(p('Projects/x/README.md'), '# hello\n');
    });
    const r = runMiasma(home);
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, /ALL CLEAR/, r.stdout);
    assert.ok(!r.stdout.includes('Findings:'), `unexpected Findings: block on a clean tree\n${r.stdout}`);
  });
});

describe('miasma fixture-helper invariants (non-vacuity guards, no bash required)', () => {
  it('HOSTILE_NAMES has exactly 9 entries, HOSTILE_NAME_BUFFERS has exactly 1, SEARCH_ROOT_NAMES.miasma has 7 roots', () => {
    assert.equal(Object.keys(HOSTILE_NAMES).length, 9, JSON.stringify(Object.keys(HOSTILE_NAMES)));
    assert.equal(Object.keys(HOSTILE_NAME_BUFFERS).length, 1, JSON.stringify(Object.keys(HOSTILE_NAME_BUFFERS)));
    assert.equal(SEARCH_ROOT_NAMES.miasma.length, 7, JSON.stringify(SEARCH_ROOT_NAMES.miasma));
    assert.equal(SEARCH_ROOT_NAMES.g747.length, 5, JSON.stringify(SEARCH_ROOT_NAMES.g747));
  });

  // The section()-exclusion decision (19-CONTEXT.md, review R2-1) rests on a
  // measured claim: every `section "..."` call site across the four scanner
  // scripts is a literal string with no parameter expansion. This guard
  // extracts and checks that claim directly from the source files rather
  // than assuming it -- 34 is the count independently verified in
  // 19-PATTERNS.md. Non-vacuity: assert.ok(callSites.length > 0) runs BEFORE
  // the length===34 check, so an extraction that silently finds nothing
  // fails loudly rather than vacuously passing an empty loop.
  it('a source guard: every section(" call site across the four scanner scripts is a literal string with no parameter expansion (34 expected)', () => {
    const scriptsDir = path.join(__dirname, '..', 'scripts');
    const scriptFiles = [
      'scan-chaindrop-aug2026.sh',
      'scan-g747-may22.sh',
      'scan-miasma-june2026.sh',
      'scan-shai-hulud-may2026.sh',
    ].map((f) => path.join(scriptsDir, f));

    const callSites = [];
    for (const file of scriptFiles) {
      const src = fs.readFileSync(file, 'utf8');
      const re = /section "([^"]*)"/g;
      let m;
      while ((m = re.exec(src)) !== null) {
        callSites.push(m[1]);
      }
    }

    assert.ok(
      callSites.length > 0,
      'extraction produced ZERO section() call sites -- the regex or the script file list is broken, ' +
        'not "the exclusion holds vacuously"'
    );
    assert.equal(callSites.length, 34, `expected exactly 34 section() call sites, found ${callSites.length}`);

    const withExpansion = callSites.filter((s) => s.includes('$'));
    assert.deepEqual(
      withExpansion,
      [],
      `section() call site(s) contain a parameter expansion, invalidating the exclusion: ${JSON.stringify(withExpansion)}`
    );
  });
});
