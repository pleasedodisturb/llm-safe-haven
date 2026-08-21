'use strict';

// Tests for lib/docs-verify/helpers/context.js's listFiles() -- symlink
// containment (F5, Codex review PR #105).
//
// THREAT: listFiles({ext}) lists every dirent whose NAME matches `ext`,
// without ever checking entry.isFile(). A symlink dirent's isDirectory()
// is false (its dirent type is SYMLINK, not DIR, since Node's Dirent
// reflects the readdir entry's OWN type, never the link target's type),
// so it falls straight into the "not a directory -> maybe list it" branch
// exactly like a regular file. readText(relPath) then opens the listed
// path with fs.readFileSync, which DOES follow the symlink -- so a
// symlink planted inside the scanned tree can make a check read (and
// potentially satisfy an identifier/command-evidence match against)
// content OUTSIDE root, defeating resolveInRoot()'s root-bounded-read
// contract at its only real enforcement point: resolveInRoot() only ever
// sees the lexical relPath listFiles() handed it, never the symlink's
// resolved target.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { buildContext } = require('../../lib/docs-verify/helpers/context.js');

/**
 * Attempts fs.symlinkSync and returns true/false rather than throwing --
 * symlink creation can be denied by policy (notably Windows without
 * Developer Mode / elevated privileges). A denied attempt must SKIP with
 * a stated reason, never silently pass as if the assertion below it were
 * exercised.
 */
function trySymlink(target, linkPath) {
  try {
    fs.symlinkSync(target, linkPath);
    return true;
  } catch {
    return false;
  }
}

describe('context.js listFiles() -- symlinked entries are excluded, never followed (F5)', () => {
  it('a .js symlink pointing OUTSIDE root is excluded from listFiles(...) results; a regular file is still listed', (t) => {
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-context-outside-'));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-context-root-'));
    try {
      const outsideFile = path.join(outsideDir, 'secret.js');
      fs.writeFileSync(outsideFile, 'const SECRET_IDENT = 1;\n');
      fs.mkdirSync(path.join(root, 'lib'));
      fs.writeFileSync(path.join(root, 'lib', 'real.js'), 'const x = 1;\n');

      if (!trySymlink(outsideFile, path.join(root, 'lib', 'outside-link.js'))) {
        t.skip('symlink creation not permitted on this filesystem/platform');
        return;
      }

      const context = buildContext(root);
      const res = context.listFiles('lib', { ext: '.js' });
      assert.ok(Array.isArray(res.files), `listFiles() returned an error instead of a file list: ${JSON.stringify(res)}`);
      assert.ok(
        !res.files.includes('lib/outside-link.js'),
        `symlinked .js file was listed despite pointing outside root: ${JSON.stringify(res.files)}`
      );
      assert.ok(res.files.includes('lib/real.js'), 'control: an ordinary regular file must still be listed');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it('control: a symlinked DIRECTORY is not descended into by a recursive listFiles() walk', (t) => {
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-context-outside-dir-'));
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lsh-context-root-dir-'));
    try {
      fs.writeFileSync(path.join(outsideDir, 'leaked.js'), 'const LEAKED = 1;\n');
      fs.mkdirSync(path.join(root, 'lib'));
      fs.writeFileSync(path.join(root, 'lib', 'real.js'), 'const x = 1;\n');

      if (!trySymlink(outsideDir, path.join(root, 'lib', 'outside-dir-link'))) {
        t.skip('symlink creation not permitted on this filesystem/platform');
        return;
      }

      const context = buildContext(root);
      const res = context.listFiles('lib', { ext: '.js', recursive: true });
      assert.ok(Array.isArray(res.files), `listFiles() errored: ${JSON.stringify(res)}`);
      assert.ok(
        !res.files.some((f) => f.includes('outside-dir-link')),
        `symlinked directory was descended into: ${JSON.stringify(res.files)}`
      );
      assert.ok(res.files.includes('lib/real.js'));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });
});
