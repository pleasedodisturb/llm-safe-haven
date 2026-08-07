'use strict';

// Tests for scripts/validate-wave-spec.js (TRAV-08) AND the doc-drift guards
// that pin docs/wave-spec.md + docs/supply-chain-defense.md to reality
// (T-17-01, T-17-01-01). Three concerns in one file because they share the
// same "the doc must never silently fall behind the code" purpose:
//
//   1. The validation script itself (exit codes, OK/FAIL line shapes).
//   2. Set-equality doc-coverage: docs/wave-spec.md's field table must name
//      EXACTLY the validator's REQUIRED_SECTIONS plus the optional metadata
//      keys present in the bundled spec -- no more, no less. A one-directional
//      (containment) check only catches a new undocumented field; the reverse
//      direction catches a documented field that no longer exists, which
//      sends a time-pressured wave author down a dead end.
//   3. Defaults cross-check: the numeric bound/budget values written into
//      both docs equal lib/traverse/index.js DEFAULTS, so a bench-driven
//      change to those numbers (plan 17-02) cannot leave a stale doc behind.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'validate-wave-spec.js');
const BUNDLED_SPEC = path.join(__dirname, '..', '..', 'manifests', 'waves', 'chaindrop-aug2026.json');
const WAVE_SPEC_DOC = path.join(__dirname, '..', '..', 'docs', 'wave-spec.md');
const SUPPLY_CHAIN_DOC = path.join(__dirname, '..', '..', 'docs', 'supply-chain-defense.md');

const { DEFAULTS } = require('../../lib/traverse/index.js');

// Mirrors REQUIRED_SECTIONS in lib/traverse/wave-spec.js (not exported from
// that module -- same local-copy convention tests/traverse/wave-spec.test.js
// already uses) and the acceptance criteria key list for
// manifests/waves/chaindrop-aug2026.json (17-04 Task 1).
const REQUIRED_SECTIONS = [
  'fileMarkers', 'knownBadHashes', 'poisonedVersions', 'compromisedFamily',
  'markerStrings', 'installMarker', 'persistence', 'lockfiles', 'staticPaths',
  'classes', 'bounds',
];

function run(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 30_000 });
}

describe('scripts/validate-wave-spec.js -- process-boundary behaviour', () => {
  it('validates the bundled spec: exit 0, stdout starts with OK', () => {
    const res = run([BUNDLED_SPEC]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /^OK\b/);
    assert.match(res.stdout, new RegExp(`specVersion 1`));
  });

  it('with no argument, validates every manifests/waves/*.json and exits 0', () => {
    const res = run([]);
    assert.equal(res.status, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /^OK\b/m);
    assert.match(res.stdout, /chaindrop-aug2026\.json/);
  });

  it('a nonexistent path exits 2 and prints a line starting with FAIL', () => {
    const res = run(['/nonexistent/does-not-exist.json']);
    assert.equal(res.status, 2);
    assert.match(res.stdout, /^FAIL\b/);
  });

  it('a spec copy with specVersion mutated to 2 exits 2 and names specVersion in the reason', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-validate-wave-spec-'));
    const mutated = path.join(tmp, 'mutated.json');
    try {
      const spec = JSON.parse(fs.readFileSync(BUNDLED_SPEC, 'utf8'));
      spec.specVersion = 2;
      fs.writeFileSync(mutated, JSON.stringify(spec));

      const res = run([mutated]);
      assert.equal(res.status, 2, res.stdout + res.stderr);
      assert.match(res.stdout, /^FAIL\b/);
      assert.match(res.stdout, /specVersion/);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('node -c passes on the script (syntax-clean, no runtime deps)', () => {
    const res = spawnSync(process.execPath, ['-c', SCRIPT], { encoding: 'utf8' });
    assert.equal(res.status, 0, res.stdout + res.stderr);
  });
});

// ---------------------------------------------------------------------
// Doc-coverage set equality (both directions).
// ---------------------------------------------------------------------

// Extracts the "## Field reference" section's markdown table field-name
// column from docs/wave-spec.md. Field names appear in the first pipe-cell
// of each data row, wrapped in backticks, e.g. "| `specVersion` | ... |".
function parseDocumentedFields(markdown) {
  const sectionMatch = markdown.match(/## Field reference\n([\s\S]*?)\n## /);
  assert.ok(sectionMatch, 'expected a "## Field reference" section in docs/wave-spec.md');
  const section = sectionMatch[1];

  const fields = new Set();
  for (const line of section.split('\n')) {
    if (!line.trim().startsWith('|')) continue;
    // Skip the header row and the "|---|---|" separator row.
    if (/^\s*\|\s*-+\s*\|/.test(line)) continue;
    const firstCell = line.split('|')[1];
    if (!firstCell) continue;
    const backticked = firstCell.match(/`([a-zA-Z0-9_]+)`/);
    if (!backticked) continue; // header row ("Field") has no backticks
    fields.add(backticked[1]);
  }
  return fields;
}

describe('docs/wave-spec.md -- field-table set equality against the real spec surface', () => {
  const markdown = fs.readFileSync(WAVE_SPEC_DOC, 'utf8');
  const documentedFields = parseDocumentedFields(markdown);

  const bundledSpec = JSON.parse(fs.readFileSync(BUNDLED_SPEC, 'utf8'));
  const optionalMetadataKeys = Object.keys(bundledSpec).filter((k) => !REQUIRED_SECTIONS.includes(k));
  const expectedFields = new Set([...REQUIRED_SECTIONS, ...optionalMetadataKeys]);

  it('documents every required section (REQUIRED_SECTIONS subset check)', () => {
    for (const section of REQUIRED_SECTIONS) {
      assert.ok(documentedFields.has(section), `docs/wave-spec.md is missing a field-table row for required section "${section}"`);
    }
  });

  it('documents every optional metadata key present in the bundled spec', () => {
    for (const key of optionalMetadataKeys) {
      assert.ok(documentedFields.has(key), `docs/wave-spec.md is missing a field-table row for bundled-spec key "${key}"`);
    }
  });

  it('documents NO field beyond REQUIRED_SECTIONS + the bundled spec\'s optional keys (reverse direction)', () => {
    const extra = [...documentedFields].filter((f) => !expectedFields.has(f));
    assert.deepEqual(extra, [], `docs/wave-spec.md documents field(s) that do not exist in the validator or bundled spec: ${extra.join(', ')} -- this sends a wave author down a dead end`);
  });

  it('full set equality: documented fields === REQUIRED_SECTIONS union bundled-spec optional keys', () => {
    assert.deepEqual([...documentedFields].sort(), [...expectedFields].sort());
  });
});

describe('docs/wave-spec.md -- required prose anchors', () => {
  const markdown = fs.readFileSync(WAVE_SPEC_DOC, 'utf8');

  for (const heading of [
    '## What a wave spec is',
    '## Field reference',
    '## specVersion policy',
    '## Tiering rules',
    '## Bounds',
    '## Authoring checklist',
    '## Worked example',
  ]) {
    it(`contains the "${heading}" section heading`, () => {
      assert.ok(markdown.includes(heading), `missing heading: ${heading}`);
    });
  }

  it('cites the concrete 727,680-byte ChainDrop payload as the hashCandidateMaxBytes rationale', () => {
    assert.ok(/727,680|727680/.test(markdown));
  });

  it('names the marker-config class', () => {
    assert.ok(markdown.includes('marker-config'));
  });

  it('names the G-1490 legacy-migration ticket', () => {
    assert.ok(markdown.includes('G-1490'));
  });

  it('the authoring checklist contains a copy-pasteable validate-wave-spec.js command', () => {
    assert.match(markdown, /node scripts\/validate-wave-spec\.js/);
  });
});

// ---------------------------------------------------------------------
// Defaults cross-check: docs must equal lib/traverse/index.js DEFAULTS.
// ---------------------------------------------------------------------

describe('docs/wave-spec.md -- Bounds section values equal DEFAULTS', () => {
  const markdown = fs.readFileSync(WAVE_SPEC_DOC, 'utf8');

  it('documented bulkReadCapBytes equals DEFAULTS.bulkReadCapBytes', () => {
    const match = markdown.match(/`bulkReadCapBytes`\s*\|\s*`(\d+)`/);
    assert.ok(match, 'could not find a documented bulkReadCapBytes value');
    assert.equal(Number(match[1]), DEFAULTS.bulkReadCapBytes);
  });

  it('documented hashCandidateMaxBytes equals DEFAULTS.hashCandidateMaxBytes', () => {
    const match = markdown.match(/`hashCandidateMaxBytes`\s*\|\s*`(\d+)`/);
    assert.ok(match, 'could not find a documented hashCandidateMaxBytes value');
    assert.equal(Number(match[1]), DEFAULTS.hashCandidateMaxBytes);
  });
});

describe('docs/supply-chain-defense.md -- env-var defaults equal DEFAULTS', () => {
  const markdown = fs.readFileSync(SUPPLY_CHAIN_DOC, 'utf8');

  function defaultAfter(envVarName) {
    const idx = markdown.indexOf(`\`${envVarName}\``);
    assert.ok(idx >= 0, `docs/supply-chain-defense.md does not mention ${envVarName}`);
    const window = markdown.slice(idx, idx + 600);
    const match = window.match(/Default:\s*`(\d+)`/);
    assert.ok(match, `could not find a "Default: \`N\`" token near ${envVarName}`);
    return Number(match[1]);
  }

  it('documented LSH_BUDGET_SECONDS default equals DEFAULTS.budgetSeconds', () => {
    assert.equal(defaultAfter('LSH_BUDGET_SECONDS'), DEFAULTS.budgetSeconds);
  });

  it('documented LSH_MAX_FILES default equals DEFAULTS.maxFiles', () => {
    assert.equal(defaultAfter('LSH_MAX_FILES'), DEFAULTS.maxFiles);
  });

  it('mentions LSH_ROOTS, LSH_BUDGET_SECONDS, LSH_MAX_FILES, and LSH_WAVE_SPEC', () => {
    for (const name of ['LSH_ROOTS', 'LSH_BUDGET_SECONDS', 'LSH_MAX_FILES', 'LSH_WAVE_SPEC']) {
      assert.ok(markdown.includes(name), `missing mention of ${name}`);
    }
  });

  it('states exit 2 means the scan did not finish and found nothing', () => {
    assert.match(markdown, /did not finish/);
  });

  it('states WARN/INFO lines do not change the exit code', () => {
    assert.match(markdown, /never change the exit code|do not change the exit code/);
  });

  it('states the LSH_ROOTS separator is Unix-only (mentions Windows)', () => {
    assert.match(markdown, /Windows/i);
  });

  it('contains the coverage-change note naming .gitignore, .env, and .npmrc', () => {
    assert.match(markdown, /\.gitignore/);
    assert.match(markdown, /\.env/);
    assert.match(markdown, /\.npmrc/);
    assert.match(markdown, /coverage/i);
  });
});
