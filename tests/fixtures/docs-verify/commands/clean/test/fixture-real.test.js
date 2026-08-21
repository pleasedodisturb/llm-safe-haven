'use strict';

// Fixture stub proving Check 6 existence-checks a real file under the
// repo's own `test/` directory once WR-03 (21-REVIEW.md) is fixed --
// mirrors the real repo's `test/backup-file.test.js`, which exists
// alongside `tests/` (both top-level directories are real; `package.json`'s
// own `test` script runs `test/*.test.js` and `tests/*.test.js`).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

describe('fixture-real.test.js (docs-verify commands fixture, not run by npm test)', () => {
  it('is a stub -- its only purpose is to exist on disk', () => {
    assert.ok(true);
  });
});
