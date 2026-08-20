'use strict';

/**
 * Markdown discovery for docs:verify (G-1570).
 *
 * PRODUCTION CONTRACT, stated honestly: this returns every on-disk `*.md`
 * file under `root`, MINUS the root `.gitignore`'s directory entries,
 * MINUS `STATIC_SKIP_DIRS`. It is NOT "every tracked markdown file" -- it
 * consults no VCS index, and a nested `.gitignore` deeper in the tree is
 * NOT read (today the only one, `.serena/.gitignore`, covers no markdown).
 * The two definitions coincide on this checkout; tests/docs-verify/
 * discover-md.test.js's parity test is the tripwire that fires the moment
 * they stop coinciding -- either an untracked `*.md` appears outside an
 * ignored directory, or a nested `.gitignore` starts covering markdown.
 *
 * No VCS or text-search subprocess runs here or anywhere else in this
 * subsystem (T-21-01-03): the session shell's text-search tool silently
 * skips files containing NUL bytes and exits 1 identically to "no match",
 * which is exactly how a tracked file could vanish from the sweep and
 * produce a false clean.
 */

const fs = require('fs');
const path = require('path');

// tests/fixtures is load-bearing and MUST stay here: the planted-defect
// corpus this guard's own test suite commits lives there, and without
// this exclusion a real-repo sweep would report the guard's own test
// fixtures as documentation drift.
const STATIC_SKIP_DIRS = Object.freeze(new Set(['.git', 'node_modules', 'tests/fixtures', 'test/fixtures']));

function gitignoreDirEntries(root) {
  const gitignorePath = path.join(root, '.gitignore');
  let text;
  try {
    text = fs.readFileSync(gitignorePath, 'utf8');
  } catch {
    return new Set();
  }
  const entries = new Set();
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#') || line.startsWith('!')) continue;
    if (line.endsWith('/')) {
      entries.add(line.slice(0, -1));
    }
  }
  return entries;
}

// Matching rule, stated because two of STATIC_SKIP_DIRS's entries are
// multi-segment (`tests/fixtures`, `test/fixtures`): compare against the
// candidate's normalized repo-relative POSIX path, never against a bare
// basename. A basename match would exclude any directory anywhere in the
// tree merely named "fixtures", and would simultaneously FAIL to exclude
// "tests/fixtures" itself, because no single basename ever equals
// "tests/fixtures". Single-segment entries (".git") still match at any
// depth; multi-segment entries match the path prefix only.
function isExcluded(relPath, skipDirs) {
  for (const skip of skipDirs) {
    if (relPath === skip || relPath.startsWith(`${skip}/`)) return true;
  }
  return false;
}

function byteCompare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function discoverMarkdown(root) {
  const errors = [];
  const files = [];
  const gitignoreDirs = gitignoreDirEntries(root);
  const skipDirs = new Set([...STATIC_SKIP_DIRS, ...gitignoreDirs]);

  function walk(absDir, relDir) {
    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch (err) {
      errors.push({ path: relDir || '.', reason: (err && err.code) || 'read-error' });
      return;
    }
    for (const entry of entries) {
      const childRel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (isExcluded(childRel, skipDirs)) continue;
        walk(path.join(absDir, entry.name), childRel);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith('.md')) {
        files.push(childRel);
      }
    }
  }

  walk(root, '');
  // Byte-wise sort, never localeCompare: collation is locale- and
  // ICU-build-dependent, which contradicts the byte-identical-report
  // promise the moment a non-ASCII id or filename appears.
  files.sort(byteCompare);
  return { files, errors };
}

module.exports = { discoverMarkdown, gitignoreDirEntries, STATIC_SKIP_DIRS };
