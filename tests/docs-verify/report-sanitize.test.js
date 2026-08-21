'use strict';

// Tests for terminal sanitization in lib/docs-verify/index.js's
// formatReport() (G-1570 Codex review F1, PR #105).
//
// THREAT: f.severity, f.check, f.file, f.message, inc.check, and
// inc.reason all originate from check-module output, and a check's
// `file` field is ultimately derived from an on-disk filename (or a
// doc-authored link target/message) -- attacker-controlled input by this
// project's own threat model. Before this fix, formatReport() interpolated
// those fields into stdout unsanitized: a filename or message carrying
// `\x1b[...` (CSI), `\x1b]...\x07` (OSC), or a lone `\r` could forge or
// hide a report line -- the exact Phase-19 defect class already fixed in
// lib/scorecard.js's sanitizeForTerminal and scripts/scan-*.sh.
//
// What would make this test fail: formatReport() interpolating a
// finding/incomplete field into its output without passing it through a
// sanitizer first. The assertion is a regex over the RENDERED STRING for
// raw ESC (\x1b) / CR (\r) bytes -- not a mock of the sanitizer -- so a
// wrong-but-present sanitizer (e.g. one that forgets the `message` field)
// still fails this test.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { formatReport } = require('../../lib/docs-verify/index.js');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'docs-verify.js');

describe('formatReport -- terminal sanitization (F1)', () => {
  it('a finding whose file/message carry CSI + OSC + lone-CR control bytes renders with no raw ESC/CR bytes', () => {
    const findings = [
      {
        check: 'identifiers',
        file: 'docs/x\x1b[2K\rfail  identifiers  README.md:1  forged',
        line: 1,
        severity: 'fail',
        message: 'evil link \x1b]8;;http://evil\x07click here\x1b\\',
      },
    ];
    const out = formatReport({ findings, incomplete: [] });

    assert.ok(!/\x1b/.test(out), `raw ESC byte survived sanitization: ${JSON.stringify(out)}`);
    assert.ok(!/\r/.test(out), `raw CR byte survived sanitization: ${JSON.stringify(out)}`);

    // The forged payload attempted to inject a standalone fake report
    // line ("fail  identifiers  README.md:1  forged") preceded by a CSI
    // erase-line + CR (which, on a real terminal, would erase and
    // overwrite the genuine line). Assert that exact forged text never
    // appears as its own line in the rendered output.
    const lines = out.split('\n');
    assert.ok(
      !lines.includes('fail  identifiers  README.md:1  forged'),
      `forged report line was rendered verbatim: ${JSON.stringify(out)}`
    );
  });

  it('control: an ordinary finding with no control characters renders unchanged', () => {
    const findings = [
      { check: 'version', file: 'docs/install.md', line: 12, severity: 'fail', message: "version '2.0.0' does not match '1.0.0'" },
    ];
    const out = formatReport({ findings, incomplete: [] });
    const expected =
      "fail  version  docs/install.md:12  version '2.0.0' does not match '1.0.0'\n" +
      'Summary: 1 findings, 1 files, 1 checks with findings, 0 incomplete';
    assert.equal(out, expected, 'an ordinary finding must render byte-identically to the pre-sanitization report');
  });

  it('incomplete entries (inc.check, inc.reason) are sanitized too', () => {
    const incomplete = [{ check: 'ev\x1bil-check', reason: 'boom\rforged incomplete line' }];
    const out = formatReport({ findings: [], incomplete });
    assert.ok(!/\x1b/.test(out), `raw ESC byte survived sanitization in incomplete entry: ${JSON.stringify(out)}`);
    assert.ok(!/\r/.test(out), `raw CR byte survived sanitization in incomplete entry: ${JSON.stringify(out)}`);
  });

  it('control: an ordinary incomplete entry renders unchanged', () => {
    const incomplete = [{ check: 'version', reason: 'context-error: missing' }];
    const out = formatReport({ findings: [], incomplete });
    assert.equal(out, 'Incomplete:\nincomplete  version  context-error: missing\nSummary: 0 findings, 0 files, 0 checks with findings, 1 incomplete');
  });
});

describe('scripts/docs-verify.js CLI -- forged escape sequence in a discovered filename never reaches stdout raw (F1)', () => {
  it('a markdown filename containing a literal ESC byte produces stdout with zero raw ESC bytes', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-docs-verify-sanitize-cli-'));
    try {
      fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'fixture-pkg', version: '1.0.0' }));
      fs.mkdirSync(path.join(tmp, 'docs'));
      const evilName = 'docs/evil\x1bfile.md';
      fs.writeFileSync(path.join(tmp, evilName), 'npx fixture-pkg@2.0.0 today\n');

      const res = spawnSync(process.execPath, [SCRIPT, '--root', tmp], { encoding: 'utf8', timeout: 30_000 });
      assert.ok(res.stdout.length > 0, 'non-vacuity: CLI produced no stdout at all');
      assert.ok(!/\x1b/.test(res.stdout), `raw ESC byte from the filename reached stdout: ${JSON.stringify(res.stdout)}`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
