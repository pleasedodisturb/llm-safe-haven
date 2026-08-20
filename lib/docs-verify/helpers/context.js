'use strict';

/**
 * Root-bounded read context for docs:verify (G-1570).
 *
 * `resolveInRoot` is the single choke point that stops a documented link
 * target (or any other root-relative path a check module computes) from
 * escaping `root` -- three parent-directory hops followed by `etc/passwd`
 * is REPORTED as out-of-tree and is never opened (T-21-01-02).
 */

const fs = require('fs');
const path = require('path');

const { discoverMarkdown } = require('./discover-md.js');

function resolveInRoot(root, relPath) {
  const absRoot = path.resolve(root);
  const candidate = path.resolve(absRoot, relPath);
  if (candidate !== absRoot && !candidate.startsWith(absRoot + path.sep)) {
    return { ok: false, reason: 'out-of-tree' };
  }
  return { ok: true, abs: candidate };
}

function buildContext(root) {
  const errors = [];
  const disc = discoverMarkdown(root);
  errors.push(...disc.errors);

  const mdFiles = [];
  for (const relPath of disc.files) {
    const resolved = resolveInRoot(root, relPath);
    if (!resolved.ok) {
      errors.push({ file: relPath, reason: resolved.reason });
      continue;
    }
    try {
      const text = fs.readFileSync(resolved.abs, 'utf8');
      mdFiles.push({ path: relPath, abs: resolved.abs, text });
    } catch (err) {
      errors.push({ file: relPath, reason: (err && err.code) || 'read-error' });
    }
  }

  function readText(relPath) {
    const resolved = resolveInRoot(root, relPath);
    if (!resolved.ok) {
      return { error: resolved.reason };
    }
    try {
      return { text: fs.readFileSync(resolved.abs, 'utf8') };
    } catch (err) {
      return { error: (err && err.code) || 'read-error' };
    }
  }

  function listFiles(relDir, options = {}) {
    const { ext, recursive = false } = options;
    const resolved = resolveInRoot(root, relDir);
    if (!resolved.ok) {
      return { error: resolved.reason };
    }
    const results = [];
    function walk(absDir, relPathPrefix) {
      const entries = fs.readdirSync(absDir, { withFileTypes: true });
      for (const entry of entries) {
        const childRel = relPathPrefix ? `${relPathPrefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          if (recursive) walk(path.join(absDir, entry.name), childRel);
          continue;
        }
        if (!ext || entry.name.endsWith(ext)) {
          results.push(`${relDir}/${childRel}`);
        }
      }
    }
    try {
      walk(resolved.abs, '');
    } catch (err) {
      return { error: (err && err.code) || 'read-error' };
    }
    results.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return { files: results };
  }

  let pkg = null;
  const pkgResult = readText('package.json');
  if (pkgResult.text !== undefined) {
    try {
      pkg = JSON.parse(pkgResult.text);
    } catch {
      errors.push({ file: 'package.json', reason: 'parse-error' });
    }
  } else {
    errors.push({ file: 'package.json', reason: pkgResult.error || 'missing' });
  }

  return { root, mdFiles, readText, listFiles, pkg, errors };
}

module.exports = { buildContext, resolveInRoot };
