'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { parseArgs } = require('../lib/cli.js');

describe('parseArgs', () => {
  it('parses --help flag', () => {
    const result = parseArgs(['--help']);
    assert.strictEqual(result.flags.help, true);
  });

  it('parses -h shorthand for help', () => {
    const result = parseArgs(['-h']);
    assert.strictEqual(result.flags.help, true);
  });

  it('parses --version flag', () => {
    const result = parseArgs(['--version']);
    assert.strictEqual(result.flags.version, true);
  });

  it('parses -v shorthand for version', () => {
    const result = parseArgs(['-v']);
    assert.strictEqual(result.flags.version, true);
  });

  it('parses --dry-run flag', () => {
    const result = parseArgs(['--dry-run']);
    assert.strictEqual(result.flags.dryRun, true);
  });

  it('parses --agent with value', () => {
    const result = parseArgs(['--agent', 'claude-code']);
    assert.strictEqual(result.flags.agent, 'claude-code');
  });

  it('parses --json flag', () => {
    const result = parseArgs(['--json']);
    assert.strictEqual(result.flags.json, true);
  });

  it('defaults command to install', () => {
    const result = parseArgs([]);
    assert.strictEqual(result.command, 'install');
  });

  it('parses subcommand: audit', () => {
    const result = parseArgs(['audit']);
    assert.strictEqual(result.command, 'audit');
  });

  it('parses subcommand: scan', () => {
    const result = parseArgs(['scan']);
    assert.strictEqual(result.command, 'scan');
  });

  it('parses subcommand: update', () => {
    const result = parseArgs(['update']);
    assert.strictEqual(result.command, 'update');
  });

  it('combines subcommand with flags', () => {
    const result = parseArgs(['audit', '--json', '--agent', 'cursor']);
    assert.strictEqual(result.command, 'audit');
    assert.strictEqual(result.flags.json, true);
    assert.strictEqual(result.flags.agent, 'cursor');
  });
});
