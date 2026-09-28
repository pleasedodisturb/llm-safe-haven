'use strict';

// scripts/scan-shai-hulud-may2026.sh Section 7 (lockfiles): the four packages
// republished on 2026-09-07 with the byte-identical May 19 Wave C payload must
// be reported, and near-miss names must not be.
//
// What makes this fail: removing any of the four names from COMPROMISED_PKGS
// (the named package is then missing from the lockfile hit list), or loosening
// the quoted-name match so a longer name containing one of them is flagged
// (the must-still-pass twin then sees a hit).
//
// The expected names are hand-written literals, never read back out of the
// script: a list extracted from the script would agree with whatever ships.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { write, newHome, runScanner, hasBash, SEARCH_ROOT_NAMES, ghStub } = require('./helpers/chaindrop-fixtures.js');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'scan-shai-hulud-may2026.sh');
const ROOT = SEARCH_ROOT_NAMES.shaiHulud[0];

const REUSED_PAYLOAD_PKGS = [
  ['feishu-docx-mcp', '0.3.2'],
  ['bmc-i18n-extract-cli', '1.1.1'],
  ['blueai-cli', '0.7.0'],
  ['bmc-translate-utils', '1.1.1'],
];

function packageLock(name, version) {
  return JSON.stringify({
    name: 'fixture-app',
    lockfileVersion: 3,
    packages: {
      '': { name: 'fixture-app', dependencies: { [name]: `^${version}` } },
      [`node_modules/${name}`]: { version },
    },
  }, null, 2) + '\n';
}

function run(built, home) {
  const { dir } = ghStub(built, 'unauthenticated');
  return runScanner(home, { LANG: 'C', LC_ALL: 'C', PATH: `${dir}:${process.env.PATH}` }, SCRIPT);
}

describe('scan-shai-hulud-may2026.sh -- Sept 7 2026 Wave C payload reuse IOCs (lockfile section)', { skip: !hasBash ? 'bash unavailable' : false }, () => {
  const built = [];
  after(() => built.forEach((h) => require('fs').rmSync(h, { recursive: true, force: true })));

  it('flags each of the four republished packages in its own package-lock.json and exits 1', () => {
    assert.ok(REUSED_PAYLOAD_PKGS.length === 4, 'non-vacuity: expected four IOC packages');
    const home = newHome(built, (h, p) => {
      for (const [name, version] of REUSED_PAYLOAD_PKGS) {
        write(p(`${ROOT}/app-${name}/package-lock.json`), packageLock(name, version));
      }
    });
    const res = run(built, home);
    assert.equal(res.status, 1, res.stdout);
    assert.match(res.stdout, /4 lockfile\/package combination\(s\) reference compromised packages/, res.stdout);
    for (const [name] of REUSED_PAYLOAD_PKGS) {
      assert.match(res.stdout, new RegExp(`^  PKG: ${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'), `${name} not reported\n${res.stdout}`);
    }
  });

  it('must-still-pass twin: longer names that contain an IOC name are not flagged', () => {
    const home = newHome(built, (h, p) => {
      write(p(`${ROOT}/near-a/package-lock.json`), packageLock('feishu-docx-mcp-server', '1.0.0'));
      write(p(`${ROOT}/near-b/package-lock.json`), packageLock('blueai-cli-tools', '2.0.0'));
      write(p(`${ROOT}/near-c/package-lock.json`), packageLock('@scope/bmc-translate-utils-lite', '1.1.1'));
    });
    const res = run(built, home);
    assert.match(res.stdout, /No lockfiles reference compromised packages/, res.stdout);
    assert.ok(!/^  FILE: /m.test(res.stdout), `unexpected lockfile hit\n${res.stdout}`);
    assert.equal(res.status, 0, res.stdout);
  });
});
