'use strict';

// Shared require-cache stubbing helper (Phase 8 review F10 — previously
// byte-identical copies lived in tests/audit.test.js and tests/cli.test.js).
//
// Lives under tests/helpers/ (NOT matching the package.json test glob
// `tests/*.test.js`), so the test runner never picks it up as a test file.
//
// WR-01 ordering (the stale-binding trap): modules like lib/audit.js
// capture collaborators (buildEnvelope/detectAll/scanForEnvFiles) in
// top-level destructured requires, so a stub installed here MUST be in
// require.cache BEFORE the module under test is first required in the
// process — replacing a cache entry AFTER the module under test has
// loaded never reaches its already-bound references. If the module under
// test is already cached, evict it (delete require.cache[path]) before
// installing the stubs so its next require rebinds against them.

const Module = require('module');
const os = require('os');
const osPath = require.resolve('os');

function installStub(resolvedPath, exports) {
  const stub = new Module(resolvedPath);
  stub.filename = resolvedPath;
  stub.loaded = true;
  stub.exports = exports;
  require.cache[resolvedPath] = stub;
}

// stubHomedir (Phase 11 / TESTQ-02, D-04 — generalizes the 5+ near-identical
// loadXAgainstHome-style loaders duplicated across scan.test.js,
// update.test.js, and agents/claude-code.test.js). Locked signature:
// stubHomedir(dir, modulePath). Spreads the real os module first so
// unrelated os.* calls (os.tmpdir(), etc.) keep working — only homedir()
// is redirected — then evicts and re-requires modulePath so its top-level
// bindings rebind against the stub (WR-01 ordering).
function stubHomedir(dir, modulePath) {
  installStub(osPath, { ...os, homedir: () => dir });
  delete require.cache[modulePath];
  return require(modulePath);
}

module.exports = { installStub, stubHomedir };
