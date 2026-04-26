'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

function detect() {
  const home = os.homedir();
  const platform = process.platform;

  // Check plugin directories for JetBrains AI Assistant
  const baseDirs = platform === 'darwin'
    ? [path.join(home, 'Library', 'Application Support', 'JetBrains')]
    : [path.join(home, '.local', 'share', 'JetBrains')];

  let found = false;
  let pluginPath = null;

  for (const baseDir of baseDirs) {
    try {
      const ideDirs = fs.readdirSync(baseDir);
      for (const ide of ideDirs) {
        const pluginsDir = path.join(baseDir, ide, 'plugins');
        try {
          const plugins = fs.readdirSync(pluginsDir);
          const aiPlugin = plugins.find(p => p.startsWith('ai-'));
          if (aiPlugin) {
            found = true;
            pluginPath = path.join(pluginsDir, aiPlugin);
            break;
          }
        } catch { /* plugins dir may not exist */ }
      }
      if (found) break;
    } catch { /* base dir may not exist */ }
  }

  return { found, version: null, path: pluginPath };
}

function harden(_projectDir, _flags) {
  const actions = [];
  const warnings = [];

  warnings.push('Review AI Assistant settings: Settings → Tools → AI Assistant');
  warnings.push('Disable "Send code snippets" if working on sensitive projects');
  warnings.push('Audit which JetBrains AI models have access to your codebase');
  warnings.push('JetBrains AI has no ignore-file mechanism — sensitive files are sent as context');

  return { actions, warnings };
}

function audit() {
  return { checks: [], level: 0 };
}

module.exports = {
  name: 'JetBrains AI',
  id: 'jetbrains-ai',
  tier: 3,
  detect,
  harden,
  audit,
};
