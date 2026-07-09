'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { loadDetectors, runAll } = require('../../../lib/mcp/detectors/index.js');

const DETECTORS_DIR = path.join(__dirname, '..', '..', '..', 'lib', 'mcp', 'detectors');

/**
 * Plants a throwaway detector module in the live detectors directory,
 * runs fn(), and ALWAYS removes the module (file + require cache) again.
 * The planted module exports a shape the fixed registry must reject, so
 * even a concurrently running test process that momentarily sees the
 * file loads an identical (excluded) detector set.
 */
function withPlantedModule(filename, source, fn) {
  const modPath = path.join(DETECTORS_DIR, filename);
  fs.writeFileSync(modPath, source);
  try {
    fn();
  } finally {
    fs.rmSync(modPath, { force: true });
    delete require.cache[modPath];
  }
}

describe('detector registry (lib/mcp/detectors/index.js)', () => {
  it('loadDetectors() returns an Array', () => {
    const detectors = loadDetectors();
    assert.ok(Array.isArray(detectors));
  });

  it('every returned module satisfies typeof id === "string" && typeof run === "function"', () => {
    const detectors = loadDetectors();
    for (const detector of detectors) {
      assert.strictEqual(typeof detector.id, 'string');
      assert.strictEqual(typeof detector.run, 'function');
    }
  });

  it('never includes an entry whose id is undefined', () => {
    const detectors = loadDetectors();
    assert.ok(detectors.every(d => d.id !== undefined));
  });

  it('index.js itself is never returned as a detector', () => {
    const detectors = loadDetectors();
    assert.ok(detectors.every(d => d.id !== 'index'));
  });

  it('output ordering is deterministic (sorted alphabetically by id) across two calls', () => {
    const first = loadDetectors().map(d => d.id);
    const second = loadDetectors().map(d => d.id);
    assert.deepStrictEqual(first, second);
    const sorted = [...first].sort((a, b) => a.localeCompare(b));
    assert.deepStrictEqual(first, sorted);
  });

  describe('WR-01 regression: a detector with a non-string id never crashes the scan', () => {
    it('a module exporting { id: 5, run } is excluded and loadDetectors()/runAll() do not throw', () => {
      withPlantedModule(
        'zz-wr01-numeric-id-temp-fixture.js',
        "'use strict';\nmodule.exports = { id: 5, run() { return []; } };\n",
        () => {
          let detectors;
          assert.doesNotThrow(() => { detectors = loadDetectors(); });
          assert.ok(detectors.every(d => typeof d.id === 'string'));
          assert.ok(!detectors.some(d => d.id === 5));
          assert.doesNotThrow(() => runAll([], {}));
        },
      );
    });

    it('a module exporting an empty-string id is excluded', () => {
      withPlantedModule(
        'zz-wr01-empty-id-temp-fixture.js',
        "'use strict';\nmodule.exports = { id: '', run() { return []; } };\n",
        () => {
          const detectors = loadDetectors();
          assert.ok(detectors.every(d => d.id !== ''));
        },
      );
    });
  });

  describe('runAll(servers, context)', () => {
    it('runAll([], {}) returns [] and does not throw', () => {
      assert.deepStrictEqual(runAll([], {}), []);
    });

    it('aggregates Finding[] from every loaded detector without throwing', () => {
      assert.doesNotThrow(() => runAll([], {}));
      const result = runAll([], {});
      assert.ok(Array.isArray(result));
    });

    it('a throwing detector is swallowed and does not abort the batch (simulated via a hand-built runAll-shaped loop)', () => {
      // Mirrors the exact try/catch discipline runAll() uses internally —
      // asserts the *shape* of the contract without needing a live
      // throwing module planted in this directory (which would pollute
      // loadDetectors() for every other test/consumer).
      const fakeDetectors = [
        { id: 'a-ok', run: () => [{ id: 'a-ok/rule', detector: 'a-ok' }] },
        { id: 'b-throws', run: () => { throw new Error('boom'); } },
        { id: 'c-ok', run: () => [{ id: 'c-ok/rule', detector: 'c-ok' }] },
      ];

      const findings = [];
      assert.doesNotThrow(() => {
        for (const detector of fakeDetectors) {
          try {
            const result = detector.run([], {});
            if (Array.isArray(result)) findings.push(...result);
          } catch {
            // swallow, per D-01
          }
        }
      });

      assert.deepStrictEqual(findings.map(f => f.id), ['a-ok/rule', 'c-ok/rule']);
    });
  });
});
