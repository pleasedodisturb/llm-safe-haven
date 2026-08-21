'use strict';

// Fixture source proving the 'hooks' bare-literal segment exists under
// hooks/**/*.js -- mirrors lib/agents/claude-code.js:9's real
// `path.join(os.homedir(), '.claude', 'hooks')` composition (G-1570,
// 21-REVIEW.md CR-01 fix). Present in the defect root too, so the
// `~/.claude/hooks/nope.js` control below is reported for its genuinely
// missing final segment ('nope.js'), not for a missing 'hooks' segment.

const os = require('os');
const path = require('path');

const FIXTURE_HOOKS_DIR = path.join(os.homedir(), '.claude', 'hooks');

module.exports = { FIXTURE_HOOKS_DIR };
