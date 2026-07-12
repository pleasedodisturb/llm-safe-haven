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
async function withPlantedModule(filename, source, fn) {
  const modPath = path.join(DETECTORS_DIR, filename);
  fs.writeFileSync(modPath, source);
  try {
    await fn();
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
    it('a module exporting { id: 5, run } is excluded and loadDetectors()/runAll() do not throw', async () => {
      await withPlantedModule(
        'zz-wr01-numeric-id-temp-fixture.js',
        "'use strict';\nmodule.exports = { id: 5, run() { return []; } };\n",
        async () => {
          let detectors;
          assert.doesNotThrow(() => { detectors = loadDetectors(); });
          assert.ok(detectors.every(d => typeof d.id === 'string'));
          assert.ok(!detectors.some(d => d.id === 5));
          await assert.doesNotReject(() => runAll([], {}));
        },
      );
    });

    it('a module exporting an empty-string id is excluded', async () => {
      await withPlantedModule(
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
    it('runAll([], {}) resolves to [] and does not reject', async () => {
      assert.deepStrictEqual(await runAll([], {}), []);
    });

    it('aggregates Finding[] from every loaded detector without rejecting', async () => {
      let result;
      await assert.doesNotReject(async () => { result = await runAll([], {}); });
      assert.ok(Array.isArray(result));
    });

    it('CR-01 regression: runAll([null], {}) never rejects and never crashes the process, even with the async provenance detector loaded', async () => {
      // Before the CR-01 fix, every SYNC detector's TypeError on
      // server.command was contained, but provenance's async rejection
      // escaped runAll()'s try/catch as an unhandled rejection and
      // terminated the Node process AFTER runAll() had returned.
      let result;
      await assert.doesNotReject(async () => { result = await runAll([null], {}); });
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

  describe('CR-01 regression: async detectors are awaited, contained, and collected', () => {
    it("an async detector's findings are collected, not silently dropped as an un-awaited Promise", async () => {
      await withPlantedModule(
        'zz-cr01-async-findings-temp-fixture.js',
        "'use strict';\nmodule.exports = { id: 'zz-cr01-async', run: async () => [{ id: 'zz-cr01-async/rule', detector: 'zz-cr01-async' }] };\n",
        async () => {
          const findings = await runAll([], {});
          assert.ok(
            findings.some(f => f.id === 'zz-cr01-async/rule'),
            'async detector findings must appear in the aggregated result'
          );
        },
      );
    });

    it('a rejecting async detector never crashes the scan and every other detector still runs', async () => {
      // Plant a rejecting async detector that sorts FIRST (id 'aa-...')
      // and a sync marker detector that sorts LAST (id 'zz-...') — the
      // marker's finding proves the batch continued past the rejection.
      await withPlantedModule(
        'aa-cr01-async-rejects-temp-fixture.js',
        "'use strict';\nmodule.exports = { id: 'aa-cr01-rejects', run: async () => { throw new Error('boom'); } };\n",
        async () => {
          await withPlantedModule(
            'zz-cr01-sync-marker-temp-fixture.js',
            "'use strict';\nmodule.exports = { id: 'zz-cr01-marker', run: () => [{ id: 'zz-cr01-marker/rule', detector: 'zz-cr01-marker' }] };\n",
            async () => {
              let findings;
              await assert.doesNotReject(async () => { findings = await runAll([], {}); });
              assert.ok(
                findings.some(f => f.id === 'zz-cr01-marker/rule'),
                'detectors after the rejecting one must still run'
              );
              assert.ok(!findings.some(f => String(f.id).startsWith('aa-cr01-rejects')));
            },
          );
        },
      );
    });
  });
});
