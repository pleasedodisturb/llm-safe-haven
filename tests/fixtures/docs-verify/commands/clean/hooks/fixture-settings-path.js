'use strict';

// G-1672 (D-02) fixture: composes 'settings.json' under '.claude', mirroring
// lib/agents/claude-code.js:10's real
// `path.join(os.homedir(), '.claude', 'settings.json')`. Exists solely so
// the fixture-profiles/work/settings.json anchoring control (Control I in
// docs/commands-doc.md) is a meaningful test: 'settings.json' genuinely IS
// composed elsewhere in this fixture tree, so a buggy in-scope predicate
// that checked ANY segment (not just the first) would wrongly classify that
// token as in-scope. The correct predicate checks only the first segment
// after the agent-home marker ('fixture-profiles'), which is not composed
// anywhere.

const os = require('os');
const path = require('path');

const FIXTURE_SETTINGS_PATH = path.join(os.homedir(), '.claude', 'settings.json');

module.exports = { FIXTURE_SETTINGS_PATH };
