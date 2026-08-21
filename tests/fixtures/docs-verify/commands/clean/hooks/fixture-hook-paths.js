'use strict';

// Fixture source proving the 'hooks' bare-literal segment exists under
// hooks/**/*.js -- mirrors lib/agents/claude-code.js:9's real
// `path.join(os.homedir(), '.claude', 'hooks')` composition (G-1570,
// 21-REVIEW.md CR-01 fix). Exists solely so Check 6's agent-home evidence
// set contains the 'hooks' segment for the shell-variable-interpolation
// fixture pair (docs/commands-doc.md's `~/.claude/hooks/$hook` line,
// pinning docs/guides/quick-start.md:659's real shape).

const os = require('os');
const path = require('path');

const FIXTURE_HOOKS_DIR = path.join(os.homedir(), '.claude', 'hooks');

module.exports = { FIXTURE_HOOKS_DIR };
