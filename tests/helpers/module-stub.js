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
//
// RESTORE CONTRACT: this mutates process-global require.cache state and does
// NOT restore it. Callers MUST undo the stub when done — either hand-roll the
// snapshot-before/restore-after dance (snapshot require.cache[osPath] BEFORE
// the first stubHomedir call, restore it in afterEach), or call
// restoreHomedir(modulePath) below, which restores the os cache entry that
// was live before the FIRST stubHomedir call in this process. Snapshotting
// AFTER calling stubHomedir "restores" the stub itself — that leaks a
// redirected homedir() to every module loaded later in this file's process.
let preStubOsEntry;
let preStubOsEntryCaptured = false;

function stubHomedir(dir, modulePath) {
  if (!preStubOsEntryCaptured) {
    preStubOsEntry = Object.prototype.hasOwnProperty.call(require.cache, osPath)
      ? require.cache[osPath] : undefined;
    preStubOsEntryCaptured = true;
  }
  installStub(osPath, { ...os, homedir: () => dir });
  delete require.cache[modulePath];
  return require(modulePath);
}

// Companion restorer for stubHomedir. Restores the os require.cache entry
// captured before the first stubHomedir call; optionally evicts modulePath
// so the next require rebinds against the real os module.
function restoreHomedir(modulePath) {
  if (preStubOsEntry === undefined) delete require.cache[osPath];
  else require.cache[osPath] = preStubOsEntry;
  if (modulePath) delete require.cache[modulePath];
}

module.exports = { installStub, stubHomedir, restoreHomedir };
