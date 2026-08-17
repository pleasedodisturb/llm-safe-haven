'use strict';

// Behavioural (black-box) tests for scripts/scan-g747-may22.sh's report
// integrity (SCAN-01, G-1549, phase 19 plan 19-03).
//
// g747 carries the phase's largest print-site count: 1 counted `printf "%b"`
// reprint (line 462) plus 16 sites where the attacker-influenced value is
// bash printf's FORMAT ARGUMENT ITSELF (`printf "$VAR"`), never a `%b`
// anywhere. Those 16 sites are pinned by ACCUMULATOR NAME, never by line
// number -- this plan's own fix inserts a sanitizer above fail(), shifting
// every pre-edit line number before the first edit lands (review R1-8).
//
// Corpus derivation: the `XOR_HITS` site (High severity, real project-tree
// paths under SEARCH_ROOTS) is the primary probe. Its trigger is CONTENT
// (the Laravel-Lang XOR key literal), not an exact filename match, so the
// hostile byte can live directly in the triggering file's own basename --
// unlike chaindrop's file-marker vehicle (19-02), which needed an ancestor
// directory because its detector requires an exact basename match.
//
// Shared fixture helpers (SEARCH_ROOT_NAMES, HOSTILE_NAMES, writeHostile,
// runScanner) come from tests/helpers/chaindrop-fixtures.js per 19-01's
// tracer precedent (19-CONTEXT.md D-16) -- reused unchanged, never forked.
//
// Negative byte-presence assertions use Buffer.includes() over the whole
// captured stdout, never the session `grep` shim (ugrep -I, which silently
// skips NUL-bearing files and exits 1 indistinguishable from "no match" --
// it has already produced one false PASS on this repo).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { newHome, runScanner, hasBash, SEARCH_ROOT_NAMES, HOSTILE_NAMES, writeHostile } = require('./helpers/chaindrop-fixtures.js');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-g747-may22.sh');

// g747 has NO environment override for its scan roots (unlike chaindrop's
// LSH_ROOTS) -- every fixture below nests under SEARCH_ROOT_NAMES.g747's
// first entry ('Projects'), matching scripts/scan-g747-may22.sh:92's
// hardcoded list.
const HOSTILE_LOCALE_ENV = { LANG: 'C', LC_ALL: 'C' };

// Every case runs under a hostile ambient locale (review R1-1's precedent,
// carried into every scanner test file this phase adds) -- proves the
// sanitizer forces its OWN locale rather than depending on the caller's
// environment.
function runG747(home, extraEnv = {}) {
  return runScanner(home, { ...HOSTILE_LOCALE_ENV, ...extraEnv }, SCRIPT);
}

// Read the Laravel-Lang XOR key literal FROM THE SCRIPT rather than
// retyping it, so this fixture cannot silently stop matching if the literal
// ever changes. Extracted from the `grep -rlF "..."` call at
// scan-g747-may22.sh's XOR_HITS build site.
function readXorKeyLiteral() {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  const m = src.match(/grep -rlF(?:\s+--null)? "([^"]+)"/);
  assert.ok(m, 'could not extract the Laravel-Lang XOR key literal from scripts/scan-g747-may22.sh (grep -rlF pattern not found)');
  return m[1];
}

const XOR_KEY = readXorKeyLiteral();

// Count live "  [FAIL] " lines. Colour codes are gated on `[ -t 1 ]` in the
// scanner and spawnSync gives it no TTY, so a piped run emits no ANSI --
// the literal two-space prefix is unambiguous.
function countFailLines(stdout) {
  const m = stdout.match(/^ {2}\[FAIL\] /gm);
  return m ? m.length : 0;
}

// g747's summary block prints "FINDINGS: N" (not "Findings:"), followed by
// the FINDING_LOG reprint -- one "  - " line per fail() call across the
// WHOLE run, regardless of how many files any one section's accumulator
// matched. (The individual XOR_HITS paths are NOT part of this block --
// see extractXorHitListBlock below.) The block must be bounded at its END
// too: the script's own "Next steps:" advice list ALSO uses "  - "-prefixed
// bullet lines ("  - Treat affected hosts...", "  - Rotate credentials...",
// "  - Review the case study..."), separated from FINDING_LOG's dump by a
// blank line (`printf "\nNext steps:\n"`) -- an unbounded slice-to-EOF
// would silently fold those 3 unrelated bullets into the count.
function extractFindingsBlock(stdout) {
  const idx = stdout.indexOf('FINDINGS:');
  if (idx === -1) return '';
  const nextBlank = stdout.indexOf('\n\n', idx);
  return nextBlank === -1 ? stdout.slice(idx) : stdout.slice(idx, nextBlank);
}

function countReprintLines(stdout) {
  const block = extractFindingsBlock(stdout);
  const m = block.match(/^ {2}- /gm);
  return m ? m.length : 0;
}

// The XOR_HITS section makes exactly ONE fail() call (a fixed header
// message, "... found in:") regardless of how many files matched; the
// individual matched paths are then dumped via a SEPARATE raw
// `printf "$XOR_HITS"` (pre-fix) / `printf '%s' "$XOR_HITS"` (post-fix) --
// never through fail(), never added to FINDING_LOG. This extracts that raw
// dump: the text between the XOR fail() message's line and the next section
// header (section() always emits a leading blank line before "==").
function extractXorHitListBlock(stdout) {
  const marker = `Laravel-Lang XOR key string '${XOR_KEY}' found in:`;
  const markerIdx = stdout.indexOf(marker);
  assert.ok(markerIdx !== -1, `XOR fail() header line not found in stdout\n${stdout}`);
  const lineEnd = stdout.indexOf('\n', markerIdx);
  assert.ok(lineEnd !== -1, `XOR fail() header line has no trailing newline\n${stdout}`);
  const dumpStart = lineEnd + 1;
  const nextBlank = stdout.indexOf('\n\n', dumpStart);
  const dumpEnd = nextBlank === -1 ? stdout.length : nextBlank;
  return stdout.slice(dumpStart, dumpEnd);
}

function xorHitListLines(stdout) {
  return extractXorHitListBlock(stdout)
    .split('\n')
    .filter((l) => l.length > 0);
}

// Builds a Projects/x/ tree with a benign 'control.js' (carries the XOR key
// marker, always reported) and one poisoned file whose NAME carries the
// hostile byte and whose CONTENT also carries the marker.
function buildXorFixture(built, hostileName) {
  const home = newHome(built, () => {});
  const dir = path.join(home, SEARCH_ROOT_NAMES.g747[0], 'x');
  fs.mkdirSync(dir, { recursive: true });
  const content = `const marker = "${XOR_KEY}";\n`;
  const controlPath = path.join(dir, 'control.js');
  fs.writeFileSync(controlPath, content);
  const hostilePath = writeHostile(dir, `${hostileName}.js`, content);
  return { home, controlPath, hostilePath };
}

// Assertion order is deliberate (19-VALIDATION.md's vacuity table): status
// first, THEN the benign positive control, THEN the count-agreement
// invariant, and only THEN the class-specific assertion. A scanner that
// reports nothing satisfies every "does not inject" claim -- checking the
// benign control appears BEFORE any negative assertion is what rules that
// out.
function assertBaseline(r, controlPath) {
  assert.equal(r.status, 1, r.stdout);
  assert.ok(r.stdout.includes(controlPath), `missing benign control ${controlPath}\n${r.stdout}`);
  const failCount = countFailLines(r.stdout);
  const reprintCount = countReprintLines(r.stdout);
  assert.equal(failCount, reprintCount, `live [FAIL] count (${failCount}) vs reprint "  - " count (${reprintCount})\n${r.stdout}`);
}

describe(
  'scan-g747-may22.sh -- report integrity, 16 variable-as-format-string sites (SCAN-01, G-1549)',
  { skip: !hasBash ? 'bash unavailable' : false },
  () => {
    const built = [];
    after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

    // Corpus-vehicle note (Rule 1 -- same category of fixture-design bug as
    // 19-02-PLAN.md's marker-string substitution): the plan's <behavior>
    // text asks for "a real 0x0A in the NAME" as this claim's vehicle.
    // Verified empirically (manual `grep -rlF` runs against a real on-disk
    // fixture, recorded in this plan's execution session) that a REAL raw
    // LF byte inside a filename is ALREADY split into two separate reads by
    // the `while IFS= read -r f; do ... done < <(grep -rlF ...)` loop that
    // BUILDS XOR_HITS -- grep's own newline-delimited output stream cannot
    // distinguish an embedded 0x0A inside a matched filename from its own
    // record separator, so `read` returns two fragments, NEITHER of which
    // contains any control byte by the time it reaches sanitize_for_terminal
    // or the print site. That split is the T-19-GREPLOOP loop-delimiter
    // fail-open this SAME plan's <objective> explicitly names OUT OF SCOPE
    // (deferred to 19-08-PLAN.md, review R2-2) -- using a real LF as this
    // claim's vehicle would make "no fabricated extra line" structurally
    // unwinnable by Task 2's print-layer fix alone, an unwinnable RED that
    // could never turn GREEN within this plan's file list.
    //
    // The literal 2-character sequence `\n` (HOSTILE_NAMES.BS_N -- backslash
    // then 'n', not a real 0x0A) is NOT read()-delimiter-sensitive (it is
    // two ordinary printable bytes, not a control byte), so it survives the
    // read loop as ONE intact fragment -- but it IS bash printf's
    // format-string escape processor's exact target (RESEARCH.md's
    // "Site-Inventory Corrections": "the literal 2-char `\n` sequence --
    // bash's format-string escape processor recognizes it too"). Pre-fix,
    // `printf "$XOR_HITS"` unconditionally escape-processes that literal
    // sequence into a real newline, splitting the entry exactly as %b would
    // -- entirely at the PRINT layer, entirely within this plan's scope.
    // Post-fix, `printf '%s' "$XOR_HITS"` never escape-processes its
    // argument, so the literal `\n` renders as two literal characters.
    it('a name carrying a literal two-character backslash-n: the XOR hit list gains no fabricated extra line -- exactly 2 lines (control + poisoned), not 3', () => {
      const { home, controlPath } = buildXorFixture(built, HOSTILE_NAMES.BS_N);
      const r = runG747(home);
      assertBaseline(r, controlPath);
      const lines = xorHitListLines(r.stdout);
      assert.equal(
        lines.length,
        2,
        `expected exactly 2 XOR hit-list lines (control + poisoned), the literal backslash-n must not be escape-processed into a fabricated extra line\nlines: ${JSON.stringify(lines)}\nstdout:\n${r.stdout}`
      );
    });

    it('a name carrying three consecutive percent-s directives: the rendered line contains those six characters literally, nothing is silently swallowed', () => {
      const { home, controlPath } = buildXorFixture(built, HOSTILE_NAMES.PCT);
      const r = runG747(home);
      assertBaseline(r, controlPath);
      const block = extractXorHitListBlock(r.stdout);
      assert.ok(
        block.includes(HOSTILE_NAMES.PCT),
        `expected the literal 6-char sequence "%s%s%s" to survive verbatim, a %-directive was silently consumed instead\n${JSON.stringify(block)}`
      );
    });

    it('a name carrying a real ESC (0x1B): zero 0x1B bytes in stdout, U+FFFD present in the poisoned line', () => {
      const { home, controlPath } = buildXorFixture(built, HOSTILE_NAMES.ESC);
      const r = runG747(home);
      assertBaseline(r, controlPath);
      assert.ok(
        !Buffer.from(r.stdout, 'utf8').includes(0x1b),
        `raw ESC (0x1B) byte reached stdout\n${JSON.stringify(r.stdout)}`
      );
      const block = extractXorHitListBlock(r.stdout);
      assert.ok(block.includes('�'), `expected U+FFFD replacement in the XOR hit list\n${JSON.stringify(block)}`);
    });

    it('must-still-pass control: a name carrying a literal backslash-c is NOT truncated -- the line is complete through its .js suffix (measured asymmetry: \\c truncates only inside %b, not a bare format string)', () => {
      const { home, controlPath, hostilePath } = buildXorFixture(built, HOSTILE_NAMES.BS_C);
      const r = runG747(home);
      assertBaseline(r, controlPath);
      const lines = xorHitListLines(r.stdout);
      const poisoned = lines.find((l) => l !== controlPath);
      assert.ok(poisoned, `no poisoned XOR hit-list line found\nlines: ${JSON.stringify(lines)}`);
      assert.ok(
        poisoned.trimEnd().endsWith('.js'),
        `poisoned line was truncated before its .js suffix (this would be the %b-only truncation bug, which must NOT apply to this bare-format-string site)\n${JSON.stringify(poisoned)}\nhostilePath: ${hostilePath}`
      );
    });

    it('a name carrying café-服务器: the CJK/accented text survives NFC-equal in the XOR hit list', () => {
      const { home, controlPath } = buildXorFixture(built, HOSTILE_NAMES.CJK);
      const r = runG747(home);
      assertBaseline(r, controlPath);
      const block = extractXorHitListBlock(r.stdout).normalize('NFC');
      assert.ok(block.includes('café-服务器'), `CJK/accented text did not survive NFC-equal\n${JSON.stringify(block)}`);
    });

    // Must-still-pass twin for the whole %s-format conversion: two ordinary
    // (non-hostile) filenames must render exactly as their two absolute
    // paths, nothing added, nothing dropped, no spacing/trailing-newline
    // drift introduced by the format change. Order across the two lines is
    // NOT asserted (grep -rlF's directory-enumeration order is not a
    // guaranteed sort), but content and line COUNT are -- a set comparison
    // still fails on a duplicated, dropped, or malformed line.
    it('benign-rendering golden case: two ordinary hit names render as exactly their two paths, one per line, no extra/missing/malformed lines', () => {
      const home = newHome(built, () => {});
      const dir = path.join(home, SEARCH_ROOT_NAMES.g747[0], 'x');
      fs.mkdirSync(dir, { recursive: true });
      const content = `const marker = "${XOR_KEY}";\n`;
      const alphaPath = path.join(dir, 'alpha-hit.js');
      const betaPath = path.join(dir, 'beta-hit.js');
      fs.writeFileSync(alphaPath, content);
      fs.writeFileSync(betaPath, content);
      const r = runG747(home);
      assert.equal(r.status, 1, r.stdout);
      const lines = xorHitListLines(r.stdout);
      assert.deepEqual(
        [...lines].sort(),
        [alphaPath, betaPath].sort(),
        `benign rendering must be exactly the two paths, one per line\nlines: ${JSON.stringify(lines)}\nstdout:\n${r.stdout}`
      );
    });

    it('a clean fixture tree with zero findings exits 0, prints ALL CLEAR, and emits no FINDINGS: block', () => {
      const home = newHome(built, () => {});
      const dir = path.join(home, SEARCH_ROOT_NAMES.g747[0], 'x');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'README.md'), '# hello\n');
      const r = runG747(home);
      assert.equal(r.status, 0, r.stdout);
      assert.match(r.stdout, /ALL CLEAR/, r.stdout);
      assert.ok(!r.stdout.includes('FINDINGS:'), `unexpected FINDINGS: block on a clean tree\n${r.stdout}`);
    });
  }
);

// ---------------------------------------------------------------------------
// Section E: TrapDoor zero-width Unicode detector (19-REVIEW.md CR-01/WR-02,
// G-1549 gap closure). Before this closure, Section E had ZERO test coverage
// of any kind (confirmed by grep: no hits for "TrapDoor"/"zero-width"/"200B"/
// "FEFF" anywhere in the test suite) -- that gap is what let CR-01 ship
// undetected. Three cases per WR-02's minimum: (1) positive path, (2)
// negative path, (3) the CR-01 hostile-ancestor regression itself.
//
// Section E's file-discovery loop, pre-fix, is a TWO-STAGE newline-delimited
// round trip through a variable (`find | while read` into $AI_FILES, then
// `while read <<< "$AI_FILES"`), unlike every sibling find-fed loop in this
// same file (already NUL-delimited by 19-08-PLAN.md). A real embedded LF in
// an ancestor directory component is split by the FIRST stage into two
// non-existent path fragments; the SECOND stage's perl reader treats
// "could not open" (both fragments) identically to "no hit" (`exit 0`), so
// the real file's actual content -- including any genuine zero-width
// payload -- is NEVER examined, and the section prints a false [PASS].
// -----------------------------------------------------------------------
// Directory-write counterpart to writeHostile() -- Section E's predicate is
// an EXACT basename match (CLAUDE.md, .cursorrules, *.mdc, AGENTS.md,
// MEMORY.md, SKILL.md, SOUL.md), so the hostile LF cannot live in the
// basename without breaking the match; it lives in an ANCESTOR directory
// component instead, exactly like 10 of the 12 loops
// tests/find-loop-nul-delimiting.test.js covers. Mirrors that file's own
// local writeHostileDir (and tests/shai-hulud-scanner.test.js's) exactly --
// verifies the hostile byte actually landed on disk before the scanner runs
// rather than trusting the write call.
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

// Writes a CLAUDE.md-named AI config file under dirAbs. `hasZeroWidth` picks
// between a genuine TrapDoor payload (a real U+200B ZERO WIDTH SPACE, past
// the perl detector's 3-byte BOM-skip offset) and ordinary clean content.
function buildTrapDoorFile(dirAbs, hasZeroWidth) {
  fs.mkdirSync(dirAbs, { recursive: true });
  const content = hasZeroWidth
    ? '# Project notes\n\nSome instructions​ hidden here.\n'
    : '# Project notes\n\nOrdinary content, nothing hidden.\n';
  const filePath = path.join(dirAbs, 'CLAUDE.md');
  fs.writeFileSync(filePath, content);
  return filePath;
}

// Section E's hit-list dump (TD_HITS), extracted the same way
// extractXorHitListBlock() extracts XOR_HITS above: the text between the
// fail() header line and the next section() header (a blank-line boundary).
function extractTrapDoorHitListBlock(stdout) {
  const marker = 'Zero-width Unicode chars in AI config files (TrapDoor pattern):';
  const markerIdx = stdout.indexOf(marker);
  assert.ok(markerIdx !== -1, `TrapDoor fail() header line not found in stdout\n${stdout}`);
  const lineEnd = stdout.indexOf('\n', markerIdx);
  assert.ok(lineEnd !== -1, `TrapDoor fail() header line has no trailing newline\n${stdout}`);
  const dumpStart = lineEnd + 1;
  const nextBlank = stdout.indexOf('\n\n', dumpStart);
  const dumpEnd = nextBlank === -1 ? stdout.length : nextBlank;
  return stdout.slice(dumpStart, dumpEnd);
}

function trapDoorHitListLines(stdout) {
  return extractTrapDoorHitListBlock(stdout)
    .split('\n')
    .filter((l) => l.length > 0);
}

// Section E's own scanned-file-count claim: `info "Scanning $N_AI AI config
// files for ..."`. Pre-fix, a hostile-ancestor-split path inflates this
// count (each non-existent fragment counted as its own "file"); post-fix it
// must equal the number of REAL files discovered, never inflated.
function extractScanCount(stdout) {
  const m = stdout.match(/Scanning (\d+) AI config files for/);
  assert.ok(m, `"Scanning N AI config files" line not found in stdout\n${stdout}`);
  return Number(m[1]);
}

describe(
  'scan-g747-may22.sh -- Section E TrapDoor zero-width Unicode detector (SCAN-02, 19-REVIEW.md CR-01/WR-02, G-1549)',
  { skip: !hasBash ? 'bash unavailable' : false },
  () => {
    const built = [];
    after(() => built.forEach((h) => fs.rmSync(h, { recursive: true, force: true })));

    it('positive path (WR-02): a benign directory containing a CLAUDE.md with an embedded U+200B is FAILed', () => {
      const home = newHome(built, () => {});
      const dir = path.join(home, SEARCH_ROOT_NAMES.g747[0], 'proj');
      const filePath = buildTrapDoorFile(dir, true);

      const r = runG747(home);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stdout, /Zero-width Unicode chars in AI config files \(TrapDoor pattern\):/, r.stdout);
      const lines = trapDoorHitListLines(r.stdout);
      assert.ok(lines.includes(filePath), `expected ${filePath} in the TrapDoor hit list\nlines: ${JSON.stringify(lines)}\n${r.stdout}`);
      assert.equal(lines.length, 1, `expected exactly 1 TrapDoor hit-list line, found ${lines.length}\nlines: ${JSON.stringify(lines)}`);
      assert.equal(extractScanCount(r.stdout), 1, `expected N_AI == 1 (one real file, not inflated)\n${r.stdout}`);
    });

    it('negative path (WR-02): the same file with no zero-width chars PASSes', () => {
      const home = newHome(built, () => {});
      const dir = path.join(home, SEARCH_ROOT_NAMES.g747[0], 'proj');
      buildTrapDoorFile(dir, false);

      const r = runG747(home);
      assert.equal(r.status, 0, r.stdout);
      assert.match(r.stdout, /No zero-width Unicode injection detected in 1 AI config files/, r.stdout);
      assert.ok(!r.stdout.includes('Zero-width Unicode chars in AI config files'), `unexpected TrapDoor FAIL on a clean file\n${r.stdout}`);
    });

    // CR-01: the hostile-ancestor regression itself. BOTH the control and
    // the poisoned CLAUDE.md carry a real U+200B (so both are independently
    // FAIL-worthy) -- this is what makes the count/discrimination assertions
    // below meaningful: pre-fix, the poisoned entry's real content is NEVER
    // examined (silently treated as "no hit"), so it is ABSENT from TD_HITS
    // entirely (a false negative, not merely a phantom-count inflation) --
    // while N_AI still reports an INFLATED count (3, not 2) because the
    // first discovery stage's own newline-delimited split already happened
    // before the perl check ever ran. Post-fix, both real files are
    // examined, both entries appear (poisoned one sanitized), and the count
    // is exact.
    it('hostile-ancestor regression (CR-01): a Projects/<LF-ancestor>/CLAUDE.md with U+200B, plus a benign-with-U+200B control sibling, both FAIL -- both paths present, exactly 2 hit-list lines (not inflated), no phantom fragment lines, and the scanned-file count is exact', () => {
      const home = newHome(built, () => {});
      const root = path.join(home, SEARCH_ROOT_NAMES.g747[0]);
      const controlPath = buildTrapDoorFile(path.join(root, 'ctrl-td'), true);
      const poisonedParent = writeHostileDir(root, `poison-td${HOSTILE_NAMES.LF}evil`);
      const poisonedPath = buildTrapDoorFile(poisonedParent, true);

      const r = runG747(home);
      assert.equal(r.status, 1, r.stdout);

      // Positive control BEFORE any negative assertion (19-VALIDATION.md's
      // vacuity table): a scanner that reports nothing satisfies every
      // "does not inject" claim below unless the control's own presence is
      // checked first.
      const lines = trapDoorHitListLines(r.stdout);
      assert.ok(lines.includes(controlPath), `missing the benign positive control\ncontrol: ${JSON.stringify(controlPath)}\nlines: ${JSON.stringify(lines)}`);

      const sanitizedPoisoned = poisonedPath.replace(HOSTILE_NAMES.LF, '�');
      assert.ok(
        lines.includes(sanitizedPoisoned),
        `missing the poisoned entry (sanitized) in full -- this is CR-01 itself: pre-fix, the real file's content is never examined and the finding is silently dropped\nexpected: ${JSON.stringify(sanitizedPoisoned)}\nlines: ${JSON.stringify(lines)}\n${r.stdout}`
      );
      assert.equal(
        lines.length,
        2,
        `expected exactly 2 TrapDoor hit-list lines (control + poisoned), found ${lines.length} -- pre-fix this is either 1 (poisoned dropped) or inflated by a phantom fragment\nlines: ${JSON.stringify(lines)}`
      );

      const [fragPrefix, fragSuffix] = poisonedPath.split(HOSTILE_NAMES.LF);
      assert.ok(!lines.includes(fragPrefix), `phantom PREFIX fragment reported as a standalone hit-list entry\nfragment: ${JSON.stringify(fragPrefix)}\nlines: ${JSON.stringify(lines)}`);
      assert.ok(!lines.includes(fragSuffix), `phantom SUFFIX fragment reported as a standalone hit-list entry\nfragment: ${JSON.stringify(fragSuffix)}\nlines: ${JSON.stringify(lines)}`);

      assert.equal(
        extractScanCount(r.stdout),
        2,
        `expected N_AI == 2 (two real files, not inflated by counting the poisoned path's split fragments as extra "files")\n${r.stdout}`
      );
    });
  }
);

describe('g747 source-level guard: 16 variable-as-format-string sites, pinned by ACCUMULATOR NAME (never by line number)', () => {
  // Pinned by name, not by line, because this plan's own fix inserts
  // sanitize_for_terminal() above fail(), shifting every pre-edit line
  // number in the file before the first edit lands (review R1-8: a prior
  // revision of this plan pinned line numbers and would have failed its own
  // guard on the first run). There are exactly 16 distinct accumulator
  // names, one per site, making the name SET a stronger pin than any line
  // list ever was: a site that is silently deleted or duplicated changes
  // the set, not merely a count.
  const EXPECTED_NAMES = [
    'GVFSD_HITS',
    'PARIKH_HITS',
    'FLIPBOX_HITS',
    'DEBUG_HITS',
    'XOR_HITS',
    'NXC_BAD',
    'NXC_INSTALLED',
    'TS_HITS',
    'ML_HITS',
    'AV_HITS',
    'PY_HITS',
    'LL_HITS',
    'PK_FAILS',
    'PK_HITS',
    'AL_HITS',
    'TD_HITS',
  ];

  // The unfixed, vulnerable form: `printf "$VAR"` -- the bare variable IS
  // the format string, unconditionally escape-processed by bash.
  function extractVulnerableSiteNames(src) {
    const re = /printf "\$([A-Za-z_][A-Za-z0-9_]*)"/g;
    const names = [];
    let m;
    while ((m = re.exec(src)) !== null) names.push(m[1]);
    return names;
  }

  // The fixed, safe form: a fixed literal '%s' format with the variable
  // passed as a separate, quoted argument.
  function extractSafeSiteNames(src) {
    const re = /printf\s+['"]%s['"]\s+"\$([A-Za-z_][A-Za-z0-9_]*)"/g;
    const names = [];
    let m;
    while ((m = re.exec(src)) !== null) names.push(m[1]);
    return names;
  }

  it('every accumulator print site is accounted for -- either all 16 are still vulnerable (pre-fix) or all 16 are now safe %s-format prints (post-fix); "zero remaining sites" cannot be satisfied by deleting the prints', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    const vulnNames = extractVulnerableSiteNames(src);

    if (vulnNames.length > 0) {
      // Pre-fix state: assert non-empty and length BEFORE comparing
      // anything (non-vacuity -- an extraction that silently finds nothing
      // must fail loudly, not vacuously agree with an empty expectation).
      assert.ok(vulnNames.length > 0, 'extraction produced ZERO printf "$VAR" sites while some vulnerable sites exist -- unreachable, guards the branch itself');
      assert.equal(
        vulnNames.length,
        16,
        `expected exactly 16 unfixed printf "$VAR" sites, found ${vulnNames.length}: ${JSON.stringify(vulnNames)}`
      );
      assert.deepEqual(
        [...vulnNames].sort(),
        [...EXPECTED_NAMES].sort(),
        `vulnerable site name SET mismatch\nfound: ${JSON.stringify([...vulnNames].sort())}\nexpected: ${JSON.stringify([...EXPECTED_NAMES].sort())}`
      );
    } else {
      // Post-fix state: zero printf "$VAR" sites remain, AND a paired
      // positive control confirms all 16 names are still printed -- via the
      // SAFE %s-format form -- so this branch cannot be satisfied by
      // silently deleting the 16 prints instead of fixing them.
      const safeNames = extractSafeSiteNames(src);
      assert.ok(
        safeNames.length > 0,
        'extraction produced ZERO %s-format print sites after the fix -- the positive-control regex or the file is broken, not "the fix removed every print"'
      );
      for (const name of EXPECTED_NAMES) {
        assert.ok(
          safeNames.includes(name),
          `accumulator ${name} is no longer printed via a safe %s-format site -- was it deleted rather than fixed?\nfound safe sites: ${JSON.stringify(safeNames)}`
        );
      }
    }
  });
});
