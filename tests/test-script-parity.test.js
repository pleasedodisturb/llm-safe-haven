'use strict';

// WR-02 (Phase 9 review fix): the positional test-file globs in
// package.json's `test` and `test:coverage` scripts are hand-duplicated
// (sh has no globstar, so the per-directory enumeration is deliberate).
// CI's coverage job runs ONLY `test:coverage` (the Node 18 floor leg runs
// only `test`), so if the two lists ever drift — e.g. a new test
// directory added to one script but not the other — a subset of tests
// silently stops running in one CI leg with zero errors. This suite pins
// the parity so drift fails loudly instead.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const pkg = require('../package.json');

// Extract the positional glob tail: every whitespace-separated token that
// names a test-file glob (ends in .test.js). Flags/quoting differences
// between the two scripts are intentionally ignored — only the executed
// file set must match.
function globsOf(script) {
  return script.split(/\s+/).filter((token) => token.endsWith('.test.js'));
}

describe('package.json test-script glob parity (WR-02)', () => {
  it('`test` and `test:coverage` enumerate the identical test-file glob set', () => {
    const testGlobs = globsOf(pkg.scripts.test);
    const coverageGlobs = globsOf(pkg.scripts['test:coverage']);

    assert.ok(testGlobs.length > 0, 'the `test` script must enumerate at least one *.test.js glob');
    assert.deepEqual(
      coverageGlobs,
      testGlobs,
      'test and test:coverage must run the identical file set — CI\'s coverage job only executes test:coverage, so a glob present in one list but not the other silently drops tests from CI'
    );
  });

  it('this very file is matched by the enumerated globs (self-check that the parity guard itself runs)', () => {
    // If someone restructures the glob lists so tests/*.test.js no longer
    // matches, this guard would vanish from the suite without failing.
    // Pin its own inclusion: at least one glob must match tests/<name>.test.js.
    const testGlobs = globsOf(pkg.scripts.test);
    assert.ok(
      testGlobs.includes('tests/*.test.js'),
      `expected the tests/*.test.js glob (which picks up this parity guard) in the test script, got: ${testGlobs.join(', ')}`
    );
  });
});
