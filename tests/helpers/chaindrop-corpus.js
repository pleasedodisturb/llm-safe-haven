'use strict';

// Detection-parity corpus (Phase 17 / TRAV-05, plan 17-05, Q-01). This is the
// load-bearing no-regression oracle for the whole phase: plan 17-14 replaces
// scripts/scan-chaindrop-aug2026.sh's eight `find` passes with one traversal
// engine invocation, and tests/chaindrop-parity.test.js (which consumes this
// file) is the ONLY thing proving that retrofit does not silently lose or
// duplicate a detection.
//
// FIXTURE-TENSION RESOLUTION (recorded here per 17-05-PLAN.md Task 1, and
// per the "IMPORTANT — self-scan-hazard precedent" note in 17-PATTERNS.md):
// every case below is built at RUNTIME into a throwaway HOME via `buildCase`
// (which delegates to tests/helpers/chaindrop-fixtures.js's `write`), NOT
// committed under tests/fixtures/. tests/chaindrop-scanner.test.js:12-14
// already establishes that a committed file literally named Math_Symbol.js,
// or a real poisoned lockfile, is a self-scan hazard — committing it would
// break the Q-03 self-root-exclusion false-positive guard
// (tests/chaindrop-scanner.test.js:285-292 / this file's own parity
// self-root case), which points the scanner at this repo and requires
// ALL CLEAR. A deterministic runtime builder + a frozen expectation table
// gives the same "golden corpus" oracle property without that hazard.
//
// IOC literals (marker strings, poisoned versions, filenames) are pulled
// from manifests/waves/chaindrop-aug2026.json (D-25's wave spec) so a spec
// edit cannot silently orphan this corpus — see SPEC below. The one literal
// NOT in that spec is the "safe" (non-poisoned) twin version used to prove
// no false positive; that comes from the sibling
// manifests/chaindrop-poisoned-versions.json `lastKnownGood` map, which is
// the existing, already-parity-tested source of vendor-confirmed safe
// versions (tests/chaindrop-scanner.test.js:343-354).
//
// MULTIPLICITY: every `expect` carries an exact `findingCount` (the integer
// parsed from the scanner's own "%d FINDING(S)" summary line), and FAIL
// cases additionally carry `matchCounts` — an exact count of matching
// stdout LINES per named pattern. This corpus discovered (2026-08-07, by
// running the real scanner against every planned fixture before writing any
// expectation down) that scan-chaindrop-aug2026.sh's own report format
// prints every fail() message TWICE: once live under `[FAIL]`, and again,
// undecorated, in the final "Findings:" summary reprint (script:547-548).
// A presence-only or unanchored substring count would therefore see "2" for
// every single real finding, which would mask rather than reveal a genuine
// duplicated detection. Every matchCounts pattern below is anchored to the
// literal `[FAIL]` prefix (present only on the live line, never the summary
// reprint) so the count reflects the true number of DISTINCT findings, and
// a split engine/bash detector that fires twice on the same input produces
// a second live `[FAIL]` line — which this oracle can see and fail on.
//
// specVersion 1 is asserted below (not just read) so a future wave-spec
// migration cannot silently change field shapes out from under this corpus.

const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { write } = require('./chaindrop-fixtures.js');
const { initRepo } = require('./git-fixture.js');

const SPEC_PATH = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const SPEC = JSON.parse(fs.readFileSync(SPEC_PATH, 'utf8'));
if (SPEC.specVersion !== 1) {
  throw new Error(`tests/helpers/chaindrop-corpus.js: manifests/waves/chaindrop-aug2026.json specVersion changed (expected 1, got ${SPEC.specVersion}) — review this corpus's literals before bumping`);
}

const LEGACY_MANIFEST = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'manifests', 'chaindrop-poisoned-versions.json'), 'utf8')
);

// ---- IOC literals, sourced from the spec (never retyped) -------------------
const FN_MATH_SYMBOL = SPEC.fileMarkers.fail.find((n) => n === 'Math_Symbol.js');
const POISONED_KEYV = SPEC.poisonedVersions.keyv[0]; // '6.0.0'
const SAFE_KEYV = LEGACY_MANIFEST.lastKnownGood.keyv; // '5.6.0' — vendor-confirmed downgrade target
const SAFE_FLAT_CACHE = LEGACY_MANIFEST.lastKnownGood['flat-cache']; // '6.1.23'
const MARKER = SPEC.markerStrings.find((s) => s === 'npm-cache.com');
const VARIANT_THRESHOLD = SPEC.fileMarkers.variantPattern.sizeThresholdBytes; // 204800
const BULK_CAP = SPEC.bounds.bulkReadCapBytes; // 262144
if (!FN_MATH_SYMBOL || !POISONED_KEYV || !SAFE_KEYV || !SAFE_FLAT_CACHE || !MARKER || !VARIANT_THRESHOLD || !BULK_CAP) {
  throw new Error('tests/helpers/chaindrop-corpus.js: an expected literal is missing from manifests/waves/chaindrop-aug2026.json — corpus and spec have drifted');
}

// ---- REVIEWED_FILE_MARKER_NAMES (TRAV-13 / G-1505 / D-07) -----------------
// A DELIBERATELY hand-maintained literal, reviewed by a human. It must NEVER
// be derived from manifests/waves/chaindrop-aug2026.json's fileMarkers.fail
// (do not "fix" this by re-deriving it from the spec, even though every
// other IOC literal in this file IS spec-sourced — see the comment above).
// It is the independent second source that tests/chaindrop-spec-parity.test.js
// compares the wave spec against.
//
// This REVERSES an earlier version of this plan, which required the
// per-marker corpus cases below to be generated FROM spec.fileMarkers.fail
// "not from a re-hardcoded literal array". That instruction is exactly what
// made the spec-parity drift guard tautological (defect B2): with one
// source feeding both sides of the comparison, deleting a name (e.g.
// router_runtime.js) from the spec removed it from BOTH sides and the guard
// passed. Adding a marker to the spec without adding it here — or here
// without the spec — is a TEST FAILURE BY DESIGN, not a bug.
const REVIEWED_FILE_MARKER_NAMES = [
  'Math_Symbol.js',
  'math_init.js',
  'router_runtime.js',
  'gh-token-monitor.sh',
  'gh-token-monitor.service',
  'com.user.gh-token-monitor.plist',
];

// buildCase(home, caseDef) — writes caseDef's fixture into `home`, exposing
// the same `p(rel) => path.join(home, rel)` convenience join every other
// fixture builder in this repo uses (tests/helpers/chaindrop-fixtures.js
// `newHome`, tests/chaindrop-scanner.test.js's local `write`/`newHome`).
function buildCase(home, caseDef) {
  const p = (rel) => path.join(home, rel);
  caseDef.build(home, p);
}

// preinstall marker content, matching the exact shape
// scan-chaindrop-aug2026.sh's grep pattern requires:
//   "preinstall"[[:space:]]*:[[:space:]]*"node[[:space:]]+setup\.mjs"
function preinstallPackageJson(name) {
  return JSON.stringify({ name, scripts: { preinstall: 'node setup.mjs' } });
}

function claudeHookSettings() {
  return JSON.stringify(
    { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'node setup.mjs' }] }] } },
    null,
    2
  );
}

// -----------------------------------------------------------------------
// CASES — one per A1 taxonomy row (plus a benign/FP twin where the row has
// one). Every finding-count / matchCounts value below was captured by
// actually running scripts/scan-chaindrop-aug2026.sh against the built
// fixture BEFORE being written down — this is the oracle's premise: the
// frozen verdict is what the CURRENT scanner really does, not a guess.
// -----------------------------------------------------------------------
const CASES = [
  {
    id: 'fn-exact',
    ioc: 'fileMarkers.fail:Math_Symbol.js',
    build: (h, p) => write(p(`Projects/x/node_modules/keyv/${FN_MATH_SYMBOL}`), '/* stub */\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/file marker 'Math_Symbol\.js'/],
      matchCounts: { [/\[FAIL\].*file marker 'Math_Symbol\.js'/.source]: 1 },
    },
    note: 'Strong filename marker, section 1(a) — has no legitimate use, FAILs on presence alone.',
  },
  {
    id: 'fn-watcher-local',
    ioc: 'staticPaths:$HOME/.local/bin/gh-token-monitor.sh',
    build: (h, p) => write(p('.local/bin/gh-token-monitor.sh'), '#!/bin/sh\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/token-revocation watcher installed/, /REMOVE THIS BEFORE ROTATING/],
      matchCounts: {
        [/\[FAIL\].*token-revocation watcher installed/.source]: 1,
        [/\[FAIL\].*REMOVE THIS BEFORE ROTATING/.source]: 1,
      },
    },
    note: 'Section 1b, static $HOME path #1. Both patterns match the SAME live [FAIL] line — one finding, two pinned substrings.',
  },
  {
    id: 'fn-watcher-plist',
    ioc: 'staticPaths:$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist',
    build: (h, p) => write(p('Library/LaunchAgents/com.user.gh-token-monitor.plist'), '<?xml version="1.0"?>\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/token-revocation watcher installed/],
      matchCounts: { [/\[FAIL\].*token-revocation watcher installed/.source]: 1 },
    },
    note: 'Section 1b, static $HOME path #2.',
  },
  {
    id: 'fn-watcher-systemd',
    ioc: 'staticPaths:$HOME/.config/systemd/user/gh-token-monitor.service',
    build: (h, p) => write(p('.config/systemd/user/gh-token-monitor.service'), '[Unit]\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/token-revocation watcher installed/],
      matchCounts: { [/\[FAIL\].*token-revocation watcher installed/.source]: 1 },
    },
    note: 'Section 1b, static $HOME path #3 (the 4th static path, /etc/systemd/system/..., is root-owned and out of scope for a HOME-scoped corpus).',
  },
  {
    id: 'variant-large',
    ioc: 'fileMarkers.variantPattern (>= sizeThresholdBytes)',
    build: (h, p) => write(p('Projects/a/node_modules/keyv/math_9f2c.js'), '/*' + 'x'.repeat(VARIANT_THRESHOLD + 5 * 1024) + '*/\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/Stage-2 payload variant/],
      matchCounts: { [/\[FAIL\].*Stage-2 payload variant/.source]: 1 },
    },
    note: 'Section 1(a2): a Math_*/math_* variant name at/above the 204800-byte threshold FAILs even without a hash match (real stage-2 is ~727KB).',
  },
  {
    id: 'variant-small',
    ioc: 'fileMarkers.variantPattern (< sizeThresholdBytes, no hash match)',
    build: (h, p) => write(p('Projects/a/Math_Helper.js'), 'export const add = (a,b) => a+b;\n'),
    expect: {
      status: 0,
      findingCount: 0,
      mustMatch: [/stage-2 naming pattern/],
      mustNotMatch: [/\[FAIL\]/],
    },
    note: 'This is the reason the engine\'s exit computation must be severity-aware: it produces stdout output (a WARN) but is NOT a finding — status 0, findingCount 0.',
  },
  {
    id: 'setup-bare',
    ioc: 'fileMarkers.warnOnly:setup.mjs (no worm markers)',
    build: (h, p) => {
      write(p('Projects/g/node_modules/motion-dom/setup.mjs'), 'export const setup = () => {};\n');
      write(p('Projects/g/node_modules/motion-dom/package.json'), JSON.stringify({ name: 'motion-dom', version: '11.0.0' }));
    },
    expect: {
      status: 0,
      findingCount: 0,
      mustMatch: [/setup\.mjs present with no worm markers/],
      mustNotMatch: [/\[FAIL\]/],
    },
    note: 'The motion-dom false-positive class: a bare setup.mjs with no preinstall pairing and no bad hash is WARN, never FAIL.',
  },
  {
    id: 'setup-paired',
    ioc: 'fileMarkers.warnOnly:setup.mjs (paired with installMarker)',
    build: (h, p) => {
      write(p('Projects/x/package.json'), preinstallPackageJson('x'));
      write(p('Projects/x/setup.mjs'), 'process.exit(0)\n');
    },
    expect: {
      status: 1,
      findingCount: 2,
      mustMatch: [/setup\.mjs paired with a 'preinstall: node setup\.mjs'/, /package\.json has 'preinstall: node setup\.mjs'/],
      matchCounts: {
        [/\[FAIL\].*setup\.mjs paired with a 'preinstall: node setup\.mjs'/.source]: 1,
        [/\[FAIL\].*package\.json has 'preinstall: node setup\.mjs'/.source]: 1,
      },
    },
    note: 'TWO independent detectors legitimately fire on the same fixture today: section 1(b) (setup.mjs+package.json pairing) AND section 2 (the standalone preinstall grep). findingCount is 2, not 1 — verified by actually running the current scanner, not assumed. A retrofit that merges these into one engine detector must still emit two findings or this case fails.',
  },
  {
    id: 'preinstall-plain',
    ioc: 'installMarker (bare, no setup.mjs)',
    build: (h, p) => write(p('Projects/y/package.json'), preinstallPackageJson('y')),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/preinstall: node setup\.mjs/],
      matchCounts: { [/\[FAIL\].*package\.json has 'preinstall: node setup\.mjs'/.source]: 1 },
    },
    note: 'Section 2 alone (no setup.mjs sibling triggers section 1b, so only the standalone preinstall grep fires).',
  },
  {
    id: 'preinstall-node-modules',
    ioc: 'installMarker (inside node_modules)',
    build: (h, p) => write(p('Projects/y/node_modules/keyv/package.json'), preinstallPackageJson('keyv')),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/preinstall: node setup\.mjs/],
      matchCounts: { [/\[FAIL\].*package\.json has 'preinstall: node setup\.mjs'/.source]: 1 },
    },
    coverageAddition: 'D-25',
    note: 'D-25: bash section 2 (script:277-289) scans package.json via `grep -rlE` with NO directory prune at all — not even PRUNE_COMMON, and node_modules is not excluded. This already FAILs on the CURRENT scanner; this case pins that scope so the engine\'s class taxonomy (the "no-prune" class in manifests/waves/chaindrop-aug2026.json) cannot quietly narrow it (RESEARCH Risk 3).',
  },
  {
    id: 'preinstall-pruned-dirs',
    ioc: 'installMarker x4 (dist/build/.next/target)',
    build: (h, p) => {
      for (const dir of ['dist', 'build', '.next', 'target']) {
        write(p(`Projects/y/${dir}/package.json`), preinstallPackageJson(dir));
      }
    },
    expect: {
      status: 1,
      findingCount: 4,
      mustMatch: [/preinstall: node setup\.mjs/],
      matchCounts: { [/\[FAIL\].*package\.json has 'preinstall: node setup\.mjs'/.source]: 4 },
    },
    note: 'dist/, build/, .next/ and target/ ARE in PRUNE_COMMON (script:180) and so are pruned by sections 1, 3a, 4 and 5 — but section 2 applies NO prune at all and reaches all four today. This is the corpus-level counterpart of the B1 defect the cross-AI review found: a physical prune added to the engine\'s walk would silently narrow this exact scope from 4 findings to 0.',
  },
];

// Lockfile-format matrix — a poisoned keyv@6.0.0 in EVERY common lockfile
// shape must FAIL exactly once; the safe twin (keyv@5.6.0, the vendor
// lastKnownGood pin) must be CLEAN. Content shapes mirror
// tests/chaindrop-scanner.test.js's existing LOCKFILES matrix (this corpus
// is a strict superset, not a duplicate — it adds npm-shrinkwrap.json and
// bun.lock as separate ids, and freezes exact findingCount/matchCounts on
// every entry, which the existing suite does not).
const LOCKFILE_FORMATS = [
  {
    idBase: 'lock-npm-v3',
    file: 'package-lock.json',
    poisoned: (v) => JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: v } } }, null, 2),
  },
  {
    idBase: 'lock-npm-v1',
    file: 'package-lock.json',
    poisoned: (v) => JSON.stringify({ lockfileVersion: 1, dependencies: { keyv: { version: v } } }, null, 2),
  },
  {
    idBase: 'lock-yarn-classic',
    file: 'yarn.lock',
    poisoned: (v) => `"keyv@^${v}":\n  version "${v}"\n  resolved "https://registry.yarnpkg.com/keyv/-/keyv-${v}.tgz"\n`,
  },
  {
    idBase: 'lock-yarn-berry',
    file: 'yarn.lock',
    poisoned: (v) => `"keyv@npm:^${v}":\n  version: ${v}\n  resolution: "keyv@npm:${v}"\n  languageName: node\n`,
  },
  {
    idBase: 'lock-pnpm',
    file: 'pnpm-lock.yaml',
    poisoned: (v) => `packages:\n  'keyv@${v}':\n    resolution: {integrity: sha512-x}\n`,
  },
  {
    idBase: 'lock-shrinkwrap',
    file: 'npm-shrinkwrap.json',
    poisoned: (v) => JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/keyv': { version: v } } }, null, 2),
  },
  {
    idBase: 'lock-bun',
    file: 'bun.lock',
    poisoned: (v) => `{\n  "lockfileVersion": 1,\n  "packages": {\n    "keyv": ["keyv@${v}", "", {}, "sha512-x"]\n  }\n}\n`,
  },
];

for (const fmt of LOCKFILE_FORMATS) {
  CASES.push({
    id: fmt.idBase,
    ioc: `lockfiles:${fmt.file} + poisonedVersions.keyv`,
    build: (h, p) => write(p(`Projects/a/${fmt.file}`), fmt.poisoned(POISONED_KEYV)),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [new RegExp(`Poisoned ChainDrop version keyv@${POISONED_KEYV.replace(/\./g, '\\.')}`)],
      matchCounts: {
        [new RegExp(`\\[FAIL\\].*Poisoned ChainDrop version keyv@${POISONED_KEYV.replace(/\./g, '\\.')}`).source]: 1,
      },
    },
    note: `Section 3a, lockfile format: ${fmt.file}.`,
  });
  CASES.push({
    id: `${fmt.idBase}-safe`,
    ioc: `lockfiles:${fmt.file} + lastKnownGood.keyv (no false positive)`,
    build: (h, p) => write(p(`Projects/a/${fmt.file}`), fmt.poisoned(SAFE_KEYV)),
    expect: {
      status: 0,
      findingCount: 0,
      mustNotMatch: [/\[FAIL\]/],
    },
    note: `Twin of ${fmt.idBase} at the vendor lastKnownGood version (${SAFE_KEYV}) — must stay clean.`,
  });
}

CASES.push(
  {
    id: 'installed-poisoned',
    ioc: 'compromisedFamily + poisonedVersions (installed on disk)',
    build: (h, p) => write(p('Projects/app/node_modules/@keyv/redis/package.json'), JSON.stringify({ name: '@keyv/redis', version: POISONED_KEYV }, null, 2)),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/Installed poisoned version on disk/],
      matchCounts: { [/\[FAIL\].*Installed poisoned version on disk/.source]: 1 },
    },
    note: 'Section 3b: reads the exact on-disk package.json version and compares against the poisoned map.',
  },
  {
    id: 'installed-safe',
    ioc: 'compromisedFamily at lastKnownGood (no false positive)',
    build: (h, p) => {
      write(p('Projects/g/node_modules/keyv/package.json'), JSON.stringify({ name: 'keyv', version: SAFE_KEYV }));
      write(p('Projects/g/node_modules/flat-cache/package.json'), JSON.stringify({ name: 'flat-cache', version: SAFE_FLAT_CACHE }));
    },
    expect: {
      status: 0,
      findingCount: 0,
      mustMatch: [/non-poisoned versions/],
      mustNotMatch: [/\[FAIL\]/],
    },
    note: 'Family presence at a non-poisoned version is NOT an IOC — these are ubiquitous eslint transitive deps (manifest rationale).',
  },
  {
    id: 'claude-hook',
    ioc: 'persistence.claudeSettings (static $HOME path)',
    build: (h, p) => write(p('.claude/settings.json'), claudeHookSettings()),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/Suspicious hook command/],
      matchCounts: { [/\[FAIL\].*Suspicious hook command/.source]: 1 },
    },
    note: 'Section 4a, $HOME/.claude/settings.json (static path).',
  },
  {
    id: 'claude-hook-project',
    ioc: 'persistence.claudeSettings (per-root glob discovery)',
    build: (h, p) => write(p('Projects/x/.claude/settings.json'), claudeHookSettings()),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/Suspicious hook command/],
      matchCounts: { [/\[FAIL\].*Suspicious hook command/.source]: 1 },
    },
    note: 'Proves the per-root glob discovery path (script:402-407), not just the two static $HOME paths.',
  },
  {
    id: 'claude-hook-both',
    ioc: 'persistence.claudeSettings (static + per-root, multiplicity pin)',
    build: (h, p) => {
      write(p('.claude/settings.json'), claudeHookSettings());
      write(p('Projects/x/.claude/settings.json'), claudeHookSettings());
    },
    expect: {
      status: 1,
      findingCount: 2,
      mustMatch: [/Suspicious hook command/],
      matchCounts: { [/\[FAIL\].*Suspicious hook command/.source]: 2 },
    },
    note: 'Multiplicity pin for section 4a: BOTH files planted together must yield exactly 2 findings and exactly 2 matching [FAIL] lines. A retrofit that consolidates static-path + glob-discovery ownership into the engine and double-reports one of them would show up here and nowhere else.',
  },
  {
    id: 'vscode-task-fail',
    ioc: 'persistence.vscodeTasks (ChainDrop pattern)',
    build: (h, p) => write(p('Projects/x/.vscode/tasks.json'), JSON.stringify({ version: '2.0.0', tasks: [{ label: 'Environment Setup', type: 'shell', command: 'node setup.mjs', runOptions: { runOn: 'folderOpen' } }] }, null, 2)),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/folderOpen task matches ChainDrop persistence/],
      matchCounts: { [/\[FAIL\].*folderOpen task matches ChainDrop persistence/.source]: 1 },
    },
    note: 'Section 4b: a folderOpen task whose label/command matches the ChainDrop-specific pattern.',
  },
  {
    id: 'vscode-task-info',
    ioc: 'persistence.vscodeTasks (legitimate folderOpen dev task)',
    build: (h, p) => write(p('Projects/g/.vscode/tasks.json'), JSON.stringify({ version: '2.0.0', tasks: [{ label: 'dev', type: 'shell', command: 'npm run dev', runOptions: { runOn: 'folderOpen' } }] })),
    expect: {
      status: 0,
      findingCount: 0,
      mustNotMatch: [/\[FAIL\]/],
      mustMatch: [/\[INFO\] tasks\.json has a folderOpen auto-run task \(review if unexpected\)/],
      matchCounts: { [/\[INFO\] tasks\.json has a folderOpen auto-run task \(review if unexpected\)/.source]: 1 },
    },
    note: 'TRAV-13/G-1505: A legitimate dev-server folderOpen task is INFO ("review if unexpected"), never FAIL — the ChainDrop-specific pattern is the FAIL gate, not folderOpen itself. This case previously asserted ONLY the absence of [FAIL], which would pass identically if the scanner emitted nothing at all for this fixture (vacuous — proven by break-proof 1 in 17.1-02-SUMMARY.md). It now also pins the literal INFO line the scanner actually emits, captured by running the real scanner against this exact fixture (2026-08-10).',
  },
  {
    id: 'marker-source',
    ioc: 'markerStrings (bulk-content class, .js)',
    build: (h, p) => write(p('Projects/x/loader.js'), `const c2 = "${MARKER}";\n`),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/marker string/i],
      matchCounts: { [/\[FAIL\].*marker string/i.source]: 1 },
    },
    note: 'Section 6b, bulk-content marker scan on an ordinary source file.',
  },
  {
    id: 'marker-npmrc',
    ioc: 'markerStrings (targeted-tier: .npmrc credential file)',
    build: (h, p) => write(p('Projects/x/.npmrc'), `; ioc: ${MARKER}\nregistry=https://registry.npmjs.org/\n`),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/marker string/i],
      matchCounts: { [/\[FAIL\].*marker string/i.source]: 1 },
    },
    note: '.npmrc is in section 6b\'s name allowlist (script:493). The engine keeps .npmrc/.env in the TARGETED `marker-config` class precisely so this case cannot be lost to gitignore pruning — see KNOWN_TIERING_TRADEOFFS below for the contrast.',
  },
  {
    id: 'marker-env',
    ioc: 'markerStrings (targeted-tier: .env credential file)',
    build: (h, p) => write(p('Projects/x/.env'), `SECRET=1\n# ${MARKER}\n`),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/marker string/i],
      matchCounts: { [/\[FAIL\].*marker string/i.source]: 1 },
    },
    note: 'Same rationale as marker-npmrc: .env is in the section 6b allowlist and stays in the engine\'s targeted `marker-config` class.',
  },
  {
    id: 'marker-history',
    ioc: 'markerStrings (shell history)',
    build: (h, p) => write(p('.zsh_history'), `: 1699999999:0;curl ${MARKER}\n`),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [/in shell history/],
      matchCounts: { [/\[FAIL\].*in shell history/.source]: 1 },
    },
    note: 'Section 6, shell history scan ($HOME/.zsh_history or .bash_history) — independent of the SEARCH_ROOTS bulk-content scan.',
  },
  {
    id: 'marker-oversized',
    ioc: 'markerStrings (bulk-content size cap, no false positive)',
    build: (h, p) => write(p('Projects/x/huge.js'), 'x'.repeat(BULK_CAP + 40 * 1024) + `\n${MARKER}\n`),
    expect: {
      // 17.1-01 (G-1512, TRAV-15, decision D-02): a marker string past the
      // bulk-content cap is still never READ (no false positive -- pinned
      // by findingCount: 0 and the mustNotMatch FAIL guard below,
      // unchanged), but the scan can no longer claim ALL CLEAR about a file
      // it never examined. `skips.counts().oversized > 0` now folds into
      // `incomplete`, so this exits 2 (INCOMPLETE), not 0. This is a
      // deliberate, operator-approved widening of the exit contract
      // (17.1-CONTEXT.md decisions D-01/D-02), not a detection-parity
      // regression -- the evidence found (zero) is identical; only the
      // scan's own honesty about what it could not examine changed.
      status: 2,
      findingCount: 0,
      mustNotMatch: [/\[FAIL\]/],
      mustMatch: [/INCOMPLETE/],
    },
    note: `Pins the bulk-content size bound (${BULK_CAP} bytes, script's \`-size -256k\`): a marker string past the cap is never read, so it does not FAIL. This is the bound D-24's hash-candidate tier is deliberately EXEMPT from (see manifests/waves/chaindrop-aug2026.json knownBadHashes[0].description) — the marker-string bulk scan and the hash-candidate scan use different caps on purpose. As of 17.1-01 (G-1512/D-02), the skipped-oversized file also makes the scan report INCOMPLETE (exit 2) rather than falsely claiming ALL CLEAR.`,
  },
  {
    id: 'bun-staging',
    ioc: 'persistence-adjacent: Bun staging directory (TMPDIR)',
    build: () => {},
    tmpSeed: (tmp) => fs.mkdirSync(path.join(tmp, 'bun-dl-abc123')),
    expect: {
      status: 0,
      findingCount: 0,
      mustMatch: [/Bun staging dir/],
      mustNotMatch: [/\[FAIL\]/],
    },
    note: 'Section 6 tail: a bun-dl-* directory under TMPDIR is WARN (a live/recent detonation signal), never FAIL by itself. Needs tests/helpers/chaindrop-fixtures.js\'s tmpSeed extension since runScanner mkdtemps its own TMPDIR per run.',
  },
  {
    id: 'clean',
    ioc: 'none (empty HOME, no code roots)',
    build: () => {},
    expect: {
      status: 0,
      findingCount: 0,
      mustMatch: [/ALL CLEAR/],
    },
    note: 'The negative control: no code roots at all, every section short-circuits to INFO/skip, and the summary reports ALL CLEAR.',
  }
);

// -----------------------------------------------------------------------
// This corpus case used to live in a separate KNOWN_TIERING_TRADEOFFS table
// (kept out of CASES, asserting a DECLARED coverage trade-off: oldExpect
// FAIL, newExpect CLEAN) pending human sign-off on plan 17-14's tiering
// design. 2026-08-07 Vitalik review REJECTED that trade-off as a real
// regression, not an acceptable one -- the OLD bash scanner's section 6b
// never consulted gitignore for ANY of its marker-string allowlist, not
// just credential files, so losing this FAIL was a genuine detection loss.
// The fix (lib/traverse/classify.js's `isMarkerConfigMember`, widened to
// cover every `spec.classes['bulk-content'].fileGlobs` name/extension, not
// just `.env`/`.env.*`/`.npmrc`) restores the old FAIL verdict exactly, so
// this is now an ORDINARY frozen CASE like every other -- the corpus is
// made STRICTER by this change (an exemption removed), never weaker; every
// other frozen expectation in this file is untouched.
CASES.push({
  id: 'marker-gitignored-source',
  ioc: 'markerStrings (ordinary source file) inside a git-repo-gitignored path, outside PRUNE_COMMON',
  build: (h, p) => {
    initRepo(p('Projects/repo'), {
      gitignore: 'notes/\n',
      untracked: { 'notes/loader.js': `const c2 = "${MARKER}";\n` },
    });
  },
  expect: {
    status: 1,
    findingCount: 1,
    mustMatch: [/marker string/i],
    matchCounts: { [/\[FAIL\].*marker string/i.source]: 1 },
  },
  note:
    'Section 6b parity: the old bash scanner never consulted gitignore for its marker-string scan at all, so a marker string in a git-ignored, non-PRUNE_COMMON path FAILs both before AND after the plan 17-14 retrofit -- this is no longer a declared trade-off, it is ordinary parity. The credential-bearing members of section 6b\'s allowlist (.env, .npmrc) were ALREADY exempt from any gitignore consultation via the targeted `marker-config` class before this widening (see the marker-npmrc / marker-env cases above); the widening extends that same targeted-tier treatment to every other allow-listed extension too.',
});

// -----------------------------------------------------------------------
// Per-reviewed-marker cases (TRAV-13 / G-1505 / D-07), modelled exactly on
// the LOCKFILE_FORMATS loop above. Every `spec.fileMarkers.fail` entry gets
// its OWN independent corpus case, sourced from REVIEWED_FILE_MARKER_NAMES
// (never from the spec itself — see that const's comment). Each is planted
// under its own `Projects/marker-<index>/` subdirectory so no two cases
// collide, and under a plain `Projects/...` path (not inside node_modules)
// so the basename-only `isAllFilesMember`/file-marker detector fires rather
// than the staticPaths detector (fn-watcher-local above already covers
// `.local/bin/gh-token-monitor.sh`'s STATIC path specifically — this loop's
// gh-token-monitor.* cases are deliberately a DIFFERENT location, proving
// the basename marker fires anywhere, not just at the known static paths;
// they are not duplicates of fn-watcher-local/-plist/-systemd).
//
// findingCount/mustMatch below were captured by actually running the real
// scanner against each built fixture (2026-08-10), per the corpus's own
// premise — not estimated. All six produced exactly one finding (the
// basename file-marker verdict); none additionally triggered the
// staticPaths watcher-removal guidance, because none of these six fixtures
// are planted at a recognised static watcher path.
//
// This loop exists so that deleting an entry from
// manifests/waves/chaindrop-aug2026.json's fileMarkers.fail breaks a
// corpus-level parity test here, independent of Task 3's spec-parity drift
// guard — two independent guards, not one.
//
// The pre-existing hard-coded `fn-exact` case (Math_Symbol.js inside
// node_modules/keyv, defined at the top of CASES) is intentionally NOT a
// duplicate of this loop's `fn-marker-Math_Symbol.js` entry: fn-exact
// covers the D-25 no-prune-inside-node_modules scope specifically, while
// this loop covers the generic "any of the six reviewed names, anywhere
// under a scan root" scope. Do not delete either as redundant.
for (const [index, name] of REVIEWED_FILE_MARKER_NAMES.entries()) {
  CASES.push({
    id: `fn-marker-${name}`,
    ioc: `fileMarkers.fail:${name}`,
    build: (h, p) => write(p(`Projects/marker-${index}/${name}`), '/* stub */\n'),
    expect: {
      status: 1,
      findingCount: 1,
      mustMatch: [new RegExp(`ChainDrop file marker '${name.replace(/\./g, '\\.')}' present`)],
      matchCounts: {
        [new RegExp(`\\[FAIL\\].*ChainDrop file marker '${name.replace(/\./g, '\\.')}' present`).source]: 1,
      },
    },
    note: `TRAV-13/G-1505/D-07: independent per-marker case for REVIEWED_FILE_MARKER_NAMES[${index}] ('${name}'). Observed (2026-08-10, real scanner run): status 1, findingCount 1, exactly one [FAIL] line — no additional staticPaths watcher-removal guidance fired for this name at this location. This loop exists so deleting this name from the wave spec breaks a test here, independent of Task 3's bidirectional spec-parity drift guard.`,
  });
}

// -----------------------------------------------------------------------
// computeExpectationFingerprint() — sha256 over a canonical serialisation of
// every CASES entry's id, expect.status, expect.findingCount,
// expect.matchCounts, the .source of every mustMatch/mustNotMatch regex, AND
// (TRAV-13/G-1505/D-04) a digest of the FIXTURE TREE that entry's `build`
// (and, where present, `tmpSeed`) actually WRITES TO DISK. tests/chaindrop-
// parity.test.js asserts this against a hard-coded constant; editing any
// expected verdict, OR any fixture that a case writes, without updating that
// constant in the SAME commit makes the tampering conspicuous in review.
// This is a review aid, not a security control — a determined executor can
// update both — its purpose is to guarantee an expectation OR fixture change
// is never invisible in a diff.
//
// WHY THE FIXTURE IS HASHED, NOT THE BUILDER'S SOURCE TEXT (D-04 / B8): a
// rejected earlier design stringified each case's `build` function directly
// (i.e. called Function.prototype.toString() on it), which captures SOURCE
// TEXT, not the closure's captured values. 27 of 40 corpus cases close over
// ALL_CAPS module constants (e.g. `fn-exact`'s build is
// `(h, p) => write(p(\`...${FN_MATH_SYMBOL}\`), ...)`) — editing
// `const FN_MATH_SYMBOL = ...` changes what lands on disk while that
// stringified source text stays byte-identical. That is the exact
// reproduction ROADMAP criterion 6 exists to kill, and it survived the
// source-text-stringification fix. Hashing the BUILT tree instead closes
// it: a constant edit, a helper edit,
// a `tmpSeed` edit, and a `build` body edit are all visible, because all of
// them change what actually lands on disk. This also removes the
// whitespace-sensitivity caveat source-text hashing would have introduced
// (reformatting a `build` with the same bytes written no longer moves the
// fingerprint).
//
// `.git` is excluded at any depth, and no file metadata (mtime, mode, size,
// inode) is hashed. Rationale: git's object store embeds commit hashes and
// timestamps, so it is not byte-reproducible across runs; the corpus's only
// git-dependent property is which files are tracked versus ignored, and
// that is fully captured by the `.gitignore` contents and the file set,
// both of which ARE hashed. An mtime would make the digest nondeterministic
// on its own and would train reviewers to expect (and therefore ignore)
// spurious mismatches — so no metadata beyond entry TYPE is ever hashed.
//
// A future agent must NOT resolve a FROZEN_FINGERPRINT mismatch by
// reflexively regenerating the constant without reading the diff that moved
// it — the whole point of this fingerprint is to make such a change
// conspicuous, not to be a rubber stamp.
// -----------------------------------------------------------------------
function canonicalCase(c) {
  return {
    id: c.id,
    status: c.expect.status,
    findingCount: c.expect.findingCount,
    matchCounts: c.expect.matchCounts || {},
    mustMatch: (c.expect.mustMatch || []).map((r) => r.source).sort(),
    mustNotMatch: (c.expect.mustNotMatch || []).map((r) => r.source).sort(),
  };
}

// hashTree(dir) — a deterministic sha256 digest of a directory tree's SHAPE
// and CONTENT: path names, entry types, file bytes, and symlink targets.
// Never follows symlinks. Skips any entry named `.git` at any depth (see the
// rationale above). Hashes no mtime/mode/size/inode — type only.
function hashTree(dir) {
  const hash = crypto.createHash('sha256');

  function walk(current) {
    const entries = fs
      .readdirSync(current, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (entry.name === '.git') continue;
      const abs = path.join(current, entry.name);
      const rel = path.relative(dir, abs).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        const target = fs.readlinkSync(abs);
        hash.update(`l\0${rel}\0${target}\0`);
      } else if (entry.isDirectory()) {
        // Emit the directory's own record BEFORE recursing, so an EMPTY
        // directory (e.g. the `bun-staging` case's tmpSeed-created
        // `bun-dl-abc123`) is visible in the digest even though it has no
        // file entries of its own.
        hash.update(`d\0${rel}\0`);
        walk(abs);
      } else {
        const contents = fs.readFileSync(abs);
        const fileHash = crypto.createHash('sha256').update(contents).digest('hex');
        hash.update(`f\0${rel}\0${fileHash}\0`);
      }
    }
  }

  walk(dir);
  return hash.digest('hex');
}

// fixtureDigest(c) — builds case `c`'s fixture into a throwaway temp HOME
// (and, if present, a second throwaway temp dir for `tmpSeed`, mirroring the
// real fixture protocol where tmpSeed seeds the scanner's own TMPDIR rather
// than HOME), hashes each with hashTree, and always cleans up — even if the
// builder throws — so a broken case cannot leak fixtures into os.tmpdir().
function fixtureDigest(c) {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-fp-'));
  let tmpDir;
  try {
    buildCase(homeDir, c);
    const homeDigest = hashTree(homeDir);
    if (c.tmpSeed) {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-fp-'));
      c.tmpSeed(tmpDir);
      const tmpDigest = hashTree(tmpDir);
      return `${homeDigest}:${tmpDigest}`;
    }
    return homeDigest;
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// computeExpectationFingerprint() is memoised: building 40 fixtures (one of
// which shells out to real `git init`/`git commit` via initRepo) is too
// expensive to pay at module load, and this file is required by several
// test files that never touch the fingerprint at all. Lazy + memoised
// computation does not weaken the guard (decision D-04 leaves this timing
// choice to the executor's discretion, provided the guard is not weakened)
// because the parity suite calls it unconditionally, exactly once per
// process, in its tamper-evidence check.
let _fingerprintCache = null;
function computeExpectationFingerprint() {
  if (_fingerprintCache === null) {
    _fingerprintCache = crypto
      .createHash('sha256')
      .update(JSON.stringify(CASES.map((c) => ({ ...canonicalCase(c), fixture: fixtureDigest(c) }))))
      .digest('hex');
  }
  return _fingerprintCache;
}

module.exports = { CASES, buildCase, computeExpectationFingerprint, canonicalCase, SPEC_PATH };
