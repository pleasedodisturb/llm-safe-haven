'use strict';

// The permanent repo-wide NUL-byte guard (G-1573, TOOL-01, plan 18-01).
//
// Why this exists. lib/scorecard.js carried two literal 0x00 bytes as the
// delimiter of its MCP finding-grouping key. `grep -I`-class tools silently
// SKIP any file containing a NUL in its first 256 KiB and exit 1 — a result
// indistinguishable from "no match". The single file that renders hostile MCP
// config data to the operator's terminal was therefore invisible to routine
// security greps, and to the agent tooling that reviews this repo. This file
// stops the next such byte from landing.
//
// TWO COMPLEMENTARY PASSES, neither a superset of the other:
//   - git ls-files sees every TRACKED file, including files that are never
//     shipped (tests, CI workflows, local tooling).
//   - npm pack --dry-run sees the SHIPPED file set. Only this one holds for a
//     consumer, who has an installed package and no git repo at all. Gating the
//     whole property on git availability would leave it unchecked in exactly
//     the case a user sees (review A-2).

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..');
const MAX_BUFFER = 64 * 1024 * 1024;
const TIMEOUT_MS = 60000;

// The NUL byte itself, built from its char code. Writing it as a literal here
// would put the very byte this file bans into this file.
const NUL = String.fromCharCode(0);

const tmpDirs = [];
after(() => tmpDirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

// KNOWN_BINARY — exact repo-relative paths that are legitimately allowed to
// contain a 0x00 byte. Each entry needs a one-line justification beside it.
//
// IT IS EMPTY ON PURPOSE. Measured 2026-08-11: every one of the 449 tracked
// files is text once lib/scorecard.js is de-NULed by this same plan. Adding an
// entry here is a deliberate act and requires a stated reason. Adding
// `lib/scorecard.js` would defeat TOOL-01 entirely — that file is the reason
// this guard exists, and exempting it would restore the exact invisibility the
// requirement was written to remove.
const KNOWN_BINARY = [];

// Non-vacuity floors. A guard that scans an empty list passes forever: a broken
// probe, a bad cwd, or a future filter typo would make the assertions above it
// trivially true while reporting success. 449 tracked and 82 packed files were
// measured on 2026-08-11; these floors leave headroom for deletions while
// staying far above any degenerate result.
const GIT_FILE_FLOOR = 400;
const PACK_FILE_FLOOR = 50;

// ---------------------------------------------------------------------------
// The ONE byte-checking implementation. Both enumeration passes AND the
// positive fixture call this exact function, which is what makes the fixture's
// non-vacuity proof transfer to the two guards rather than proving something
// about a parallel code path.
//
// Deliberately NOT grep, rg, or any subprocess. The entire defect TOOL-01 fixes
// is that the tool doing the grepping is the one that skips the file, so a
// grep-based assertion here would be doubly vacuous. Read raw bytes.
// ---------------------------------------------------------------------------
function scanForNulBytes(absPaths) {
  let scanned = 0;
  const offenders = [];
  for (const abs of absPaths) {
    // Establish the file TYPE before opening it. readFileSync() on a FIFO
    // blocks forever waiting for a writer — measured: a 5s timeout kills it,
    // it never returns — so a single tracked FIFO would hang CI indefinitely
    // rather than fail it. lstat (not stat) because a symlink must be judged
    // as itself: following one would scan a file outside the tracked set and
    // report an offender path that is not the path git enumerated.
    //
    // This mirrors the project's own read-path discipline — the traversal
    // engine opens with O_NOFOLLOW and gates on fstat().isFile() for exactly
    // this reason (lib/traverse/read-pool.js). A guard that can hang is worse
    // than one that fails: a hang has no output to read.
    let st;
    try {
      st = fs.lstatSync(abs);
    } catch (err) {
      offenders.push({ file: abs, offset: null, error: (err && err.code) || 'UNKNOWN' });
      continue;
    }
    if (!st.isFile()) {
      // Not a pass. A non-regular tracked entry has not been shown NUL-free,
      // and silently skipping it is the vacuity this file exists to prevent.
      offenders.push({ file: abs, offset: null, error: 'NON_REGULAR_FILE' });
      continue;
    }

    let buf;
    try {
      buf = fs.readFileSync(abs);
    } catch (err) {
      // A path the enumerator reported but we could not open is NOT a pass.
      // Silently skipping it is the vacuity this file exists to prevent.
      offenders.push({ file: abs, offset: null, error: (err && err.code) || 'UNKNOWN' });
      continue;
    }
    scanned++;
    const offset = buf.indexOf(0);
    if (offset !== -1) offenders.push({ file: abs, offset });
  }
  return { scanned, offenders };
}

function describeOffenders(offenders) {
  return offenders
    .map((o) => (o.error ? `${o.file} (unreadable: ${o.error})` : `${o.file} @ byte ${o.offset}`))
    .join(', ');
}

const FIX_HINT =
  'Fix the ENCODING, never the delimiter (CONTEXT D-05): replace the literal byte with its ' +
  'six-character JS escape sequence. The two are the same string value at runtime, so behaviour ' +
  'is unchanged. Swapping in a printable delimiter would INTRODUCE a collision flaw in ' +
  'attacker-controlled data. If a file is genuinely binary, add it to KNOWN_BINARY with a reason.';

function withoutKnownBinary(offenders) {
  const allowed = new Set(KNOWN_BINARY.map((p) => path.join(REPO_ROOT, p)));
  return offenders.filter((o) => !allowed.has(o.file));
}

// ---------------------------------------------------------------------------
// Enumeration pass 1 — tracked files
// ---------------------------------------------------------------------------

// Availability probe idiom copied from tests/packaging.test.js:27-30: probe
// once at module load and degrade to a SKIP with a reason, never a failure.
function gitAvailable() {
  const r = spawnSync('git', ['--version'], { timeout: 10000 });
  return !r.error && r.status === 0;
}
const GIT_OK = gitAvailable();
const GIT_SKIP_REASON = 'git is not available on PATH';

function trackedFiles() {
  const r = spawnSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, maxBuffer: MAX_BUFFER, timeout: TIMEOUT_MS });
  assert.equal(r.status, 0, `git ls-files -z failed: ${r.stderr ? r.stderr.toString() : ''}`);
  // -z is exactly right: the output is NUL-separated, so there are no quoting
  // rules to get wrong and the separator can never occur inside a path.
  //
  // NO EXTENSION FILTER (review C-3). An earlier draft matched
  // /\.(js|cjs|mjs|sh|json|md|ya?ml)$/ while claiming "every tracked source
  // file"; measured, that missed 24 of 448 files including the extensionless
  // LICENSE, twelve .jsonc, seven .toml, and the .npmignore/.gitignore entries.
  // The check is byte-based and costs microseconds per file, so a guard whose
  // stated truth is "no tracked file" scans them all. The ONLY exclusion is the
  // explicit, named, justified KNOWN_BINARY array.
  return r.stdout
    .toString('utf8')
    .split(NUL)
    .filter(Boolean)
    .map((rel) => path.join(REPO_ROOT, rel));
}

// ---------------------------------------------------------------------------
// Enumeration pass 2 — the packaged artifact
// ---------------------------------------------------------------------------

function npmAvailable() {
  const r = spawnSync('npm', ['--version'], { timeout: 10000 });
  return !r.error && r.status === 0;
}
const NPM_OK = npmAvailable();
const NPM_SKIP_REASON = 'npm is not available on PATH';

/** Shape copied from tests/packaging.test.js:42-56 — writes no tarball. */
function packDryRunFiles() {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: REPO_ROOT,
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  assert.equal(result.status, 0, `npm pack --dry-run --json failed: ${result.stderr ? result.stderr.toString() : ''}`);
  const parsed = JSON.parse(result.stdout.toString('utf8'));
  return parsed[0].files.map((f) => path.join(REPO_ROOT, f.path));
}

// ---------------------------------------------------------------------------

describe('no literal NUL byte in any tracked or shipped file (TOOL-01 / G-1573)', () => {
  it('no TRACKED file contains a literal NUL byte', { skip: !GIT_OK && GIT_SKIP_REASON }, () => {
    const { offenders } = scanForNulBytes(trackedFiles());
    const real = withoutKnownBinary(offenders);
    assert.deepEqual(real, [], `tracked file(s) contain a literal NUL byte: ${describeOffenders(real)}. ${FIX_HINT}`);
  });

  it('no file npm would SHIP contains a literal NUL byte', { skip: !NPM_OK && NPM_SKIP_REASON }, () => {
    const { offenders } = scanForNulBytes(packDryRunFiles());
    const real = withoutKnownBinary(offenders);
    assert.deepEqual(real, [], `shipped file(s) contain a literal NUL byte: ${describeOffenders(real)}. ${FIX_HINT}`);
  });

  it('NON-VACUITY: the tracked pass actually opened files', { skip: !GIT_OK && GIT_SKIP_REASON }, (t) => {
    const { scanned } = scanForNulBytes(trackedFiles());
    t.diagnostic(`git pass scanned ${scanned} tracked file(s)`);
    assert.ok(
      scanned >= GIT_FILE_FLOOR,
      `only ${scanned} tracked file(s) were opened (floor ${GIT_FILE_FLOOR}). Without this floor a ` +
        'git ls-files that returned nothing — a broken probe, a bad cwd, a future filter typo — would ' +
        'make the guard above pass trivially while scanning zero bytes.'
    );
  });

  it('NON-VACUITY: the packaged pass actually opened files', { skip: !NPM_OK && NPM_SKIP_REASON }, (t) => {
    const { scanned } = scanForNulBytes(packDryRunFiles());
    t.diagnostic(`npm pack pass scanned ${scanned} shipped file(s)`);
    assert.ok(
      scanned >= PACK_FILE_FLOOR,
      `only ${scanned} shipped file(s) were opened (floor ${PACK_FILE_FLOOR}). Same reasoning as the ` +
        'tracked floor: an empty file set is not a clean result.'
    );
  });

  // Guarded on nothing — needs neither git nor npm, so the helper both passes
  // depend on is proven to actually detect a NUL under every environment in
  // which this suite runs.
  it('NON-VACUITY: scanForNulBytes flags a fixture that really does contain a NUL', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'no-nul-source-'));
    tmpDirs.push(dir);
    const file = path.join(dir, 'has-a-nul.txt');
    fs.writeFileSync(file, Buffer.from([0x61, 0x00, 0x62]));

    const { scanned, offenders } = scanForNulBytes([file]);

    assert.equal(scanned, 1);
    assert.equal(offenders.length, 1, 'the same helper both guards call must flag this file');
    assert.equal(offenders[0].file, file);
    assert.equal(offenders[0].offset, 1, 'the NUL sits at byte offset 1 of "a<NUL>b"');
  });
});
