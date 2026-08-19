'use strict';

// G-1658 — deprecation notice for EOS / unmaintained agent modules.
//
// What would make these fail: if a targeted module (amazon-q, aider) carries no
// `deprecated` note, or if the scorecard renderer does not surface that note to a
// human for a DETECTED agent. The paired controls (cursor has no note; a
// not-found deprecated agent prints nothing) fail if the feature is implemented
// as a blanket "mark/print everything", so the guard can't be satisfied by
// deleting the distinction.
//
// Behaviour under test — asserted against the module's own `deprecated` string
// (canonical source), never a re-statement of it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { captureLog } = require('./helpers/capture-log.js');

// Deterministic, ANSI-free render for substring matching.
process.env.NO_COLOR = '1';

const amazonQ = require('../lib/agents/amazon-q.js');
const aider = require('../lib/agents/aider.js');
const cursor = require('../lib/agents/cursor.js'); // maintained control
const { loadAgents } = require('../lib/agents/index.js');

function freshScorecard() {
  const p = require.resolve('../lib/scorecard.js');
  delete require.cache[p];
  return require('../lib/scorecard.js');
}

describe('agent deprecation notices (G-1658)', () => {
  it('the EOS/unmaintained modules carry a non-empty deprecated note', () => {
    assert.equal(typeof amazonQ.deprecated, 'string', 'amazon-q must export a deprecated string');
    assert.ok(amazonQ.deprecated.trim().length > 0, 'amazon-q deprecated note must be non-empty');
    assert.equal(typeof aider.deprecated, 'string', 'aider must export a deprecated string');
    assert.ok(aider.deprecated.trim().length > 0, 'aider deprecated note must be non-empty');
  });

  it('a maintained agent has NO deprecated note (control — guard is not vacuous)', () => {
    assert.equal(cursor.deprecated, undefined, 'cursor must not be flagged deprecated');
  });

  it('the deprecated set derived from the registry is exactly the EOS/unmaintained agents', () => {
    const ids = loadAgents()
      .filter((a) => typeof a.deprecated === 'string' && a.deprecated.trim().length > 0)
      .map((a) => a.id);
    // Exact-set equality (not just includes/excludes) so the "exactly" contract
    // in the test name actually holds — a THIRD agent gaining `deprecated`, or
    // either of these two losing it, fails this. deepEqual on a non-empty string
    // literal is itself the non-vacuity guard (an empty registry set != this).
    assert.deepEqual([...ids].sort(), ['aider', 'amazon-q']);
  });

  it('printAgentSection surfaces the note for a DETECTED deprecated agent', async () => {
    const sc = freshScorecard();
    const { logs } = await captureLog(() =>
      sc.printAgentSection(amazonQ, { found: true }, { actions: [], warnings: [] }, { checks: [] })
    );
    const out = logs.join('\n');
    assert.match(out, /Deprecated/i, 'a Deprecated line must be printed for a detected deprecated agent');
    assert.ok(
      out.includes(amazonQ.deprecated),
      'the printed note must be the module\'s own deprecated text (canonical source)'
    );
  });

  it('printAgentSection prints NO deprecated line for a maintained agent (twin)', async () => {
    const sc = freshScorecard();
    const { logs } = await captureLog(() =>
      sc.printAgentSection(cursor, { found: true }, { actions: [], warnings: [] }, { checks: [] })
    );
    assert.doesNotMatch(logs.join('\n'), /Deprecated/i, 'no Deprecated line for a non-deprecated agent');
  });

  it('printAgentSection does NOT nag about an UNINSTALLED deprecated agent', async () => {
    const sc = freshScorecard();
    const { logs } = await captureLog(() =>
      sc.printAgentSection(amazonQ, { found: false }, { actions: [], warnings: [] }, { checks: [] })
    );
    assert.doesNotMatch(logs.join('\n'), /Deprecated/i, 'not-found agents print nothing (early return preserved)');
  });
});
