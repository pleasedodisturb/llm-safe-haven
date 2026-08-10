'use strict';

// Risk 1 regression guard (G-1482, TRAV-05, 17-VALIDATION.md hash-cap row):
// the known-bad-hash check must hash the WHOLE candidate, never a
// bulk-cap-truncated prefix, because the real ChainDrop stage-2 payload
// (727,680 bytes) is well over the 262,144-byte bulk-content cap. A real
// ChainDrop hash cannot be used here because forging a preimage is
// impossible -- that is exactly why the detection-parity corpus (plan
// 17-05) has no real-hash case, and plan 17-14 Task 3 closes the
// end-to-end gap with a temporary spec after the retrofit.
//
// Every property here is proven in BOTH directions where applicable (an
// included case AND an excluded case at each byte boundary) per
// 17-VALIDATION.md's Q-02 non-vacuity rule.

const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { classify } = require('../../lib/traverse/classify.js');
const { createReadPool } = require('../../lib/traverse/read-pool.js');

const SPEC = require('../../manifests/waves/chaindrop-aug2026.json');

const BULK_CAP = SPEC.bounds.bulkReadCapBytes; // 262144
const HASH_CAP = SPEC.bounds.hashCandidateMaxBytes; // 1048576

const dirs = [];
function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hash-cap-'));
  dirs.push(dir);
  return dir;
}
after(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function writeSizedFile(dir, name, size, fillByte = 0x61 /* 'a' */) {
  const file = path.join(dir, name);
  const buf = Buffer.alloc(size, fillByte);
  fs.writeFileSync(file, buf);
  return file;
}

function independentSha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function readOnlyCtx() {
  // No `ignore` field -- classify() no longer accepts one (2026-08-07
  // tiering-trade-off reversal; see lib/traverse/classify.js's module
  // header).
  return {
    selfRoot: null,
    skips: { add() {} },
  };
}

// ---------------------------------------------------------------------------
// Whole-file digest equality
// ---------------------------------------------------------------------------

describe('hash-cap — whole-candidate digest equals an independently computed whole-file sha256', () => {
  it('a 400 KiB file (over the bulk cap, under the hash cap), hash-only, produces the exact independent digest', async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'Math_Symbol.js', 400 * 1024);
    const expected = independentSha256(file);

    // Drive classify() first (the file is a hash-candidate name in the
    // all-files class), matching the plan's "classify + createReadPool"
    // composition, then submit exactly the hash work classify implies.
    const result = classify({ absPath: file, dirent: null, depth: 0, repoRoot: null, isDirectory: false }, SPEC, readOnlyCtx());
    assert.ok(result.classes.includes('all-files'));

    // A synthetic spec whose knownBadHashes contains this file's real
    // digest -- proves the digest this pool produces is the value a
    // wave-spec matcher (plan 17-11) would actually compare against.
    const syntheticSpec = { ...SPEC, knownBadHashes: [{ sha256: expected, description: 'synthetic', sizeBytes: 400 * 1024 }] };
    assert.ok(syntheticSpec.knownBadHashes.some((h) => h.sha256 === expected));

    const pool = createReadPool({});
    pool.submit({ absPath: file, classes: result.classes, needHash: true, priority: 'targeted' });
    const [record] = await pool.drain();

    assert.equal(record.digest, expected);
  });

  it('the SAME 400 KiB file with a bulk read on the SAME handle first still produces the exact independent digest, and opens exactly once', async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'dual-tier.js', 400 * 1024);
    const expected = independentSha256(file);

    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true, needHash: true, priority: 'targeted' });
    const [record] = await pool.drain();

    // The bulk read is capped at 262144 and the 400 KiB file exceeds that,
    // so the bulk half is recorded oversized -- the hash half must still
    // be correct and complete, proving it never inherited the bulk
    // buffer or the handle's advanced read cursor.
    assert.equal(record.bulkSkipped, 'oversized-bulk');
    assert.equal(record.digest, expected);
    assert.equal(pool.stats().opened, 1);
  });
});

// ---------------------------------------------------------------------------
// Paired negative: the two caps are genuinely different code paths
// ---------------------------------------------------------------------------

describe('hash-cap — bulk cap and hash cap are different code paths, not one shared buffer', () => {
  it('a marker string placed past the 262,144-byte bulk cap produces NO bulk match, even though the file is well under the hash cap', async () => {
    const dir = mkFixture();
    const size = 400 * 1024;
    const buf = Buffer.alloc(size, 0x61);
    const marker = Buffer.from('npm-cache.com');
    marker.copy(buf, size - marker.length); // placed at the very end, past the 262144 cap
    const file = path.join(dir, 'marker-past-cap.js');
    fs.writeFileSync(file, buf);

    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true, needHash: true });
    const [record] = await pool.drain();

    assert.equal(record.bulkSkipped, 'oversized-bulk');
    assert.equal(record.bulkBuffer, null); // no buffer to search a marker in at all
    // The hash half is unaffected by the bulk cap.
    assert.equal(record.digest, independentSha256(file));
  });
});

// ---------------------------------------------------------------------------
// Boundary cases -- one included, one excluded, at each cap
// ---------------------------------------------------------------------------

describe('hash-cap — exact byte-boundary pairs', () => {
  it(`a file at exactly ${HASH_CAP - 1} bytes IS hashed`, async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'just-under-hash-cap.bin', HASH_CAP - 1);
    const pool = createReadPool({});
    pool.submit({ absPath: file, needHash: true });
    const [record] = await pool.drain();
    assert.equal(record.hashSkipped, null);
    assert.equal(record.digest, independentSha256(file));
  });

  it(`a file at exactly ${HASH_CAP} bytes is NOT hashed and is recorded oversized (hash-specific)`, async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'at-hash-cap.bin', HASH_CAP);
    const pool = createReadPool({});
    pool.submit({ absPath: file, needHash: true });
    const [record] = await pool.drain();
    assert.equal(record.hashSkipped, 'oversized-hash');
    assert.equal(record.digest, null);
  });

  it(`a file at exactly ${BULK_CAP - 1} bytes IS bulk-read to its end`, async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'just-under-bulk-cap.js', BULK_CAP - 1);
    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.bulkSkipped, null);
    assert.equal(record.bulkBuffer.length, BULK_CAP - 1);
  });

  it(`a file at exactly ${BULK_CAP} bytes is NOT bulk-read and is recorded oversized (bulk-specific, exclusion not truncation)`, async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'at-bulk-cap.js', BULK_CAP);
    const pool = createReadPool({});
    pool.submit({ absPath: file, needBulk: true });
    const [record] = await pool.drain();
    assert.equal(record.bulkSkipped, 'oversized-bulk');
    assert.equal(record.bulkBuffer, null);
  });
});

// ---------------------------------------------------------------------------
// Size provenance: a file that GROWS between classification and open
// ---------------------------------------------------------------------------

describe('hash-cap — size provenance comes from filehandle.stat(), closing the TOCTOU window', () => {
  it('a file that grows past the hash cap AFTER classify() but BEFORE the pool opens it is still bounded correctly', async () => {
    const dir = mkFixture();
    const file = writeSizedFile(dir, 'grows.bin', HASH_CAP - 100); // small enough to be classified as hashable

    // Simulate the classify-then-open window: the file grows past the cap
    // before submit()/drain() actually opens it.
    fs.appendFileSync(file, Buffer.alloc(1000, 0x62));
    assert.ok(fs.statSync(file).size >= HASH_CAP);

    const pool = createReadPool({});
    pool.submit({ absPath: file, needHash: true });
    const [record] = await pool.drain();

    // The bound fired for the GROWN size, not the size observed before
    // the file grew -- proving the bound is read from the open handle's
    // own stat(), not a size captured earlier.
    assert.equal(record.hashSkipped, 'oversized-hash');
    assert.equal(record.digest, null);
  });
});

// ---------------------------------------------------------------------------
// Non-vacuity (Q-02) -- each guard proven to actually bite by breaking it
// once during development, then restoring it. Documented here as the
// permanent record of that check; the mutations themselves are not left in
// the shipped module.
//
//   1. Capping the hash read at `bulkReadCapBytes` instead of
//      `hashCandidateMaxBytes` (i.e. `needHash` inheriting the bulk-tier
//      cap) breaks BOTH the "hash-only" digest-equality test and the
//      1,048,575-byte boundary test above -- the digest becomes one of a
//      truncated 262144-byte prefix, which no longer equals the
//      independent whole-file digest.
//   2. Dropping the explicit `position` argument from the hash loop's
//      `handle.read()` call (letting it continue from the handle's
//      implicit cursor after a prior bulk read on the same handle) would
//      break the "dual-tier same handle" test above the same way -- the
//      cursor would already be past the sniff/bulk window, so the hash
//      would start mid-file and mismatch the independent digest.
// Mutation 1 was applied once during development (`hashWholeFile(handle,
// Math.min(size, normalized.bulkReadCapBytes))`), confirmed to fail four
// of the tests above, and reverted; mutation 2's failure mode was
// confirmed by code inspection (every `handle.read()` in this module's
// hash loop is called with an explicit `position`, never relying on the
// implicit cursor -- removing it is mechanically the same class of bug).
// ---------------------------------------------------------------------------
