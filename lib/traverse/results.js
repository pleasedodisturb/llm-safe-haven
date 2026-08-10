'use strict';

/**
 * Results-directory protocol (G-1482, TRAV-01, D-04/D-16, T-17-10/T-17-10c).
 *
 * This is the ONLY seam in this codebase where attacker-controlled bytes
 * (filenames) cross from Node into a bash consumer (plan 17-14). Every
 * FIELD of every record is NUL-delimited -- not just every record -- because
 * a POSIX filename may legally contain a TAB or a newline, and a
 * TAB-separated field layout would let a crafted filename shift `path` into
 * `detail`, corrupting the consumer's field alignment. NUL is the one byte
 * a path cannot contain, so it is the only safe delimiter anywhere this
 * module writes.
 *
 * `resultsDir` is ALWAYS supplied by the caller (bash's own `mktemp -d`) --
 * this module never creates it, never derives its path from a guessable
 * pattern, and refuses (throws) if it turns out to be a symlink or not a
 * directory, so a symlink planted at a predictable temp-file location
 * cannot be used to redirect these writes (T-17-09).
 *
 * `findings.json` is a human/debugging artifact -- the bash scanner never
 * parses it (see `scalars/` below for what bash actually reads).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const { FILE_CLASSES, SKIP_REASONS } = require('./index.js');

const RESULTS_SCHEMA_VERSION = 1;

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

const NUL_RE = /\0/;
const HYGIENE_RE = /[\n\r\0]/;

/**
 * T-17-09 -- `lstat` (never `stat`) so a symlink is detected as itself,
 * never followed to whatever it points at.
 */
function ensureResultsDirSafe(resultsDir) {
  let st;
  try {
    st = fs.lstatSync(resultsDir);
  } catch (err) {
    throw new Error(`writeResults: resultsDir does not exist or is inaccessible: ${resultsDir} (${(err && err.code) || err})`);
  }
  if (st.isSymbolicLink()) {
    throw new Error(`writeResults: resultsDir must not be a symlink: ${resultsDir}`);
  }
  if (!st.isDirectory()) {
    throw new Error(`writeResults: resultsDir is not a directory: ${resultsDir}`);
  }
}

function makeSubdir(resultsDir, name) {
  const dir = path.join(resultsDir, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.chmodSync(dir, DIR_MODE); // explicit -- mkdirSync's mode option is masked by umask
  return dir;
}

function writeProtectedFile(filePath, contents) {
  fs.writeFileSync(filePath, contents);
  fs.chmodSync(filePath, FILE_MODE); // explicit -- writeFileSync's mode option is masked by umask
}

function assertNoNul(value, label) {
  if (typeof value === 'string' && NUL_RE.test(value)) {
    throw new Error(
      `writeResults: ${label} contains a NUL byte -- a NUL cannot have come from the filesystem; refusing to ` +
        'write a record that would desynchronise the NUL-delimited reader'
    );
  }
}

function assertHygienic(value, label) {
  if (typeof value === 'string' && HYGIENE_RE.test(value)) {
    throw new Error(
      `writeResults: ${label} contains a newline, carriage return, or NUL byte -- validateWaveSpec should ` +
        'already have rejected this; refusing to write it into a newline-delimited spec list (defence in depth)'
    );
  }
}

/**
 * Validates every string this module is about to write BEFORE any
 * directory or file is created, so a violation anywhere throws with the
 * results dir left untouched -- never a partially-written protocol.
 */
function validateBeforeWriting(result, spec) {
  for (const f of result.findings) {
    assertNoNul(f.id, `finding.id (${f.absPath})`);
    assertNoNul(f.severity, `finding.severity (${f.absPath})`);
    assertNoNul(f.absPath, 'finding.path');
    assertNoNul(f.detail, `finding.detail (${f.absPath})`);
  }

  for (const name of spec.fileMarkers.fail) assertHygienic(name, 'spec.fileMarkers.fail entry');
  for (const name of spec.compromisedFamily) assertHygienic(name, 'spec.compromisedFamily entry');
  for (const s of spec.markerStrings) assertHygienic(s, 'spec.markerStrings entry');
  for (const p of spec.staticPaths) assertHygienic(p, 'spec.staticPaths entry');
  for (const entry of spec.knownBadHashes) assertHygienic(entry.sha256, 'spec.knownBadHashes[].sha256');
  for (const [pkg, versions] of Object.entries(spec.poisonedVersions)) {
    assertHygienic(pkg, 'spec.poisonedVersions key');
    for (const v of versions) assertHygienic(v, `spec.poisonedVersions.${pkg} entry`);
  }
}

/**
 * Strict integer/boolean formatter -- never string interpolation of
 * arbitrary data. A scalar file's ENTIRE content is this one line, which is
 * what makes it `$(cat)`-safe: no path data can ever land in it.
 */
function writeScalar(scalarsDir, name, value) {
  let n;
  if (typeof value === 'boolean') {
    n = value ? 1 : 0;
  } else if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
    n = value;
  } else {
    throw new TypeError(`writeResults: scalar "${name}" must be a non-negative integer or boolean, got ${JSON.stringify(value)}`);
  }
  writeProtectedFile(path.join(scalarsDir, name), `${n}\n`);
}

function writeNulList(filePath, entries) {
  let body = '';
  for (const entry of entries) body += entry + '\0';
  writeProtectedFile(filePath, body);
}

function writeNewlineList(filePath, entries) {
  writeProtectedFile(filePath, entries.length ? entries.join('\n') + '\n' : '');
}

function classListEntries(byClass, className) {
  if (!byClass) return [];
  if (byClass instanceof Map) return byClass.get(className) || [];
  return byClass[className] || [];
}

/**
 * The two shell-history file paths are NOT spec data -- they are
 * OS-standard $HOME locations, mirroring the bash scanner's own hardcoded
 * pair (scripts/scan-chaindrop-aug2026.sh:477), resolved at write time the
 * same way lib/roots.js resolves its home-relative defaults. Bash owns
 * section 6a's marker-string matching against these files
 * (DETECTOR_OWNERSHIP); this file supplies only the two paths it checks.
 */
function shellHistoryPaths(homedirFn) {
  const home = homedirFn();
  return [path.join(home, '.zsh_history'), path.join(home, '.bash_history')];
}

/**
 * Writes the full results-directory protocol into the caller-supplied,
 * already-existing `resultsDir`. See the module header for the safety and
 * NUL-delimiting rules this implements.
 *
 * `result` -- a TraverseResult from `Traversal.run()`.
 * `spec` -- the validated wave spec `result` was produced against.
 * `options` (all optional):
 *   - roots: string[] -- the resolved scan roots, echoed into findings.json
 *   - elapsedMs: number -- total wall-clock ms for the run() call
 *   - candidatesRead: number -- reserved for a future engine revision that
 *     exposes a read-pool submission count; `Traversal.run()` does not
 *     currently surface one, so this defaults to 0. `findings.json` is a
 *     human/debug artifact only (the bash scanner never parses it -- see
 *     `scalars/` above), so an honest placeholder is preferable to a
 *     fabricated estimate.
 *   - byClass: Map<string,string[]> | object -- per-FILE_CLASSES absolute
 *     path lists (typically from a second, read-free
 *     `Traversal.enumerateSync()` pass with `classes: FILE_CLASSES`), used
 *     to populate `lists/<class>.z`. Defaults to an empty list per class.
 *   - homedir: () => string, defaults to `os.homedir` -- injectable for tests.
 */
function writeResults(resultsDir, result, spec, options = {}) {
  ensureResultsDirSafe(resultsDir);
  validateBeforeWriting(result, spec);

  const roots = Array.isArray(options.roots) ? options.roots : [];
  const elapsedMs = typeof options.elapsedMs === 'number' ? options.elapsedMs : 0;
  const candidatesRead = typeof options.candidatesRead === 'number' ? options.candidatesRead : 0;
  const homedirFn = typeof options.homedir === 'function' ? options.homedir : os.homedir;

  const severityCounts = { fail: 0, warn: 0, info: 0 };
  for (const f of result.findings) {
    if (Object.prototype.hasOwnProperty.call(severityCounts, f.severity)) severityCounts[f.severity] += 1;
  }

  const degradations = (result.degradations || []).map((d) =>
    typeof d === 'string' ? { repoRoot: null, reason: d } : { repoRoot: d.repoRoot || null, reason: d.reason }
  );

  const skipCounts = result.skips.counts();

  // --- findings.json -------------------------------------------------------
  const envelope = {
    resultsSchemaVersion: RESULTS_SCHEMA_VERSION,
    wave: spec.wave,
    specVersion: spec.specVersion,
    exitCode: result.exitCode,
    incomplete: result.incomplete,
    tiers: result.tiers,
    counts: {
      filesWalked: result.counts.filesWalked,
      dirsWalked: result.counts.dirsWalked,
      rootsWalked: result.counts.rootsWalked,
      candidatesRead,
      elapsedMs,
    },
    severityCounts,
    skips: skipCounts,
    degradations,
    findings: result.findings.map((f) => ({ id: f.id, class: f.class, path: f.absPath, detail: f.detail, severity: f.severity })),
    roots,
  };
  writeProtectedFile(path.join(resultsDir, 'findings.json'), JSON.stringify(envelope, null, 2) + '\n');

  // --- scalars/ --------------------------------------------------------------
  // Bash needs about a dozen integers and Node is already running here --
  // line-oriented grep/sed extraction from pretty-printed JSON is brittle
  // against a schema that is explicitly allowed to grow additively
  // (RESULTS_SCHEMA_VERSION), so each scalar gets its own single-integer file.
  const scalarsDir = makeSubdir(resultsDir, 'scalars');
  writeScalar(scalarsDir, 'exit-code', result.exitCode);
  writeScalar(scalarsDir, 'incomplete', result.incomplete);
  writeScalar(scalarsDir, 'finding-count', result.findings.length);
  writeScalar(scalarsDir, 'fail-count', severityCounts.fail);
  writeScalar(scalarsDir, 'warn-count', severityCounts.warn);
  writeScalar(scalarsDir, 'info-count', severityCounts.info);
  writeScalar(scalarsDir, 'targeted-complete', result.tiers.targeted.complete);
  writeScalar(scalarsDir, 'bulk-complete', result.tiers.bulk.complete);
  writeScalar(scalarsDir, 'elapsed-ms', elapsedMs);
  writeScalar(scalarsDir, 'files-walked', result.counts.filesWalked);
  writeScalar(scalarsDir, 'dirs-walked', result.counts.dirsWalked);
  writeScalar(scalarsDir, 'degradation-count', degradations.length);
  for (const reason of SKIP_REASONS) {
    writeScalar(scalarsDir, `skip-${reason}`, skipCounts[reason] || 0);
  }

  // --- lists/ ------------------------------------------------------------
  const listsDir = makeSubdir(resultsDir, 'lists');
  for (const cls of FILE_CLASSES) {
    writeNulList(path.join(listsDir, `${cls}.z`), classListEntries(options.byClass, cls));
  }
  // NUL-delimited FIELDS as well as NUL-terminated records (T-17-10/B5): a
  // POSIX filename may contain any byte except NUL and `/`, so TAB is a
  // legal filename character and a TAB-separated field layout would let a
  // crafted filename shift `path` into `detail`. NUL is the only byte a
  // path cannot contain, so it is the only safe field separator. Bash reads
  // a record with four chained `IFS= read -r -d ''` calls.
  let findingsBody = '';
  for (const f of result.findings) {
    findingsBody += f.id + '\0' + f.severity + '\0' + f.absPath + '\0' + f.detail + '\0';
  }
  writeProtectedFile(path.join(listsDir, 'findings.z'), findingsBody);

  // --- skips/ --------------------------------------------------------------
  // D-16: the human report shows aggregate counts (findings.json.skips /
  // scalars/skip-<reason>); the full path list per reason lives here.
  const skipsDir = makeSubdir(resultsDir, 'skips');
  for (const reason of SKIP_REASONS) {
    writeNulList(path.join(skipsDir, `${reason}.z`), result.skips.paths(reason));
  }

  // --- spec/ ---------------------------------------------------------------
  // Newline-delimited: safe because validateWaveSpec already rejects any
  // spec string containing a newline, carriage return or NUL --
  // `validateBeforeWriting` above re-asserts that invariant (defence in depth).
  const specDir = makeSubdir(resultsDir, 'spec');
  const poisonedLines = [];
  for (const [pkg, versions] of Object.entries(spec.poisonedVersions)) {
    for (const v of versions) poisonedLines.push(`${pkg}@${v}`);
  }
  writeNewlineList(path.join(specDir, 'poisoned-versions.txt'), poisonedLines);
  writeNewlineList(path.join(specDir, 'compromised-family.txt'), spec.compromisedFamily);
  writeNewlineList(path.join(specDir, 'fail-filenames.txt'), spec.fileMarkers.fail);
  writeNewlineList(path.join(specDir, 'known-bad-hashes.txt'), spec.knownBadHashes.map((e) => e.sha256));
  writeNewlineList(path.join(specDir, 'marker-strings.txt'), spec.markerStrings);
  writeNewlineList(path.join(specDir, 'watcher-paths.txt'), spec.staticPaths);
  writeNewlineList(path.join(specDir, 'shell-history-paths.txt'), shellHistoryPaths(homedirFn));
}

module.exports = { RESULTS_SCHEMA_VERSION, writeResults };
