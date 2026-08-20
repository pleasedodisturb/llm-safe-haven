'use strict';

// STUB (RED phase, G-1570) -- see discover-md.js stub header.

function resolveInRoot() {
  return { ok: false, reason: 'out-of-tree' };
}

function buildContext(root) {
  return { root, mdFiles: [], readText: () => ({ error: 'stub' }), listFiles: () => ({ error: 'stub' }), pkg: null, errors: [] };
}

module.exports = { buildContext, resolveInRoot };
