'use strict';

const fs = require('fs');
const path = require('path');

// Auto-discover agent modules in this directory
const SKIP = new Set(['index.js', 'base.js']);

function loadAgents() {
  const agents = [];
  const dir = __dirname;

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js') && !SKIP.has(f));

  for (const file of files) {
    try {
      const mod = require(path.join(dir, file));
      if (mod.id && mod.name && typeof mod.detect === 'function') {
        agents.push(mod);
      }
    } catch {
      // Broken module — skip silently, never crash the CLI
    }
  }

  // Sort: tier 1 first, then tier 2, then tier 3. Within tier, alphabetical.
  agents.sort((a, b) => (a.tier - b.tier) || a.name.localeCompare(b.name));
  return agents;
}

function detectAll() {
  const agents = loadAgents();
  return agents.map(agent => {
    try {
      const result = agent.detect();
      return { ...agent, detected: result };
    } catch {
      return { ...agent, detected: { found: false } };
    }
  });
}

function getById(id) {
  const agents = loadAgents();
  return agents.find(a => a.id === id) || null;
}

function getByIds(ids) {
  const agents = loadAgents();
  return ids.map(id => agents.find(a => a.id === id)).filter(Boolean);
}

module.exports = { loadAgents, detectAll, getById, getByIds };
