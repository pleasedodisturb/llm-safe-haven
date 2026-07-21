'use strict';

/**
 * Unit tests for lib/mcp/restricted-yaml.js (D-03, Phase 12) — the
 * shared restricted-YAML primitives extracted verbatim out of
 * lib/mcp/parsers/continue-dev.js. Byte-identical behavior for
 * continue-dev.js itself is proven by tests/mcp/parsers/continue-dev.test.js
 * (unchanged fixtures/assertions) and goose.js's own object-keyed-mapping
 * usage is proven by tests/mcp/parsers/goose.test.js. This file exists to
 * satisfy the test-contract meta-test (tests/mcp/test-contract.test.js,
 * MCPO-06) — every lib/mcp module needs a matching test file — and to
 * unit-test the one behavior that is genuinely NEW here: the
 * checkUnsupportedShape(text, topLevelKey) parameterization.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  indentOf,
  isBlankOrComment,
  stripQuotes,
  parseInlineList,
  checkUnsupportedShape,
  parseListBlock,
  parseMappingBlock,
} = require('../../lib/mcp/restricted-yaml.js');

describe('mcp/restricted-yaml', () => {
  it('exports all seven primitives as functions', () => {
    for (const fn of [indentOf, isBlankOrComment, stripQuotes, parseInlineList, checkUnsupportedShape, parseListBlock, parseMappingBlock]) {
      assert.strictEqual(typeof fn, 'function');
    }
  });

  it('indentOf counts leading spaces', () => {
    assert.strictEqual(indentOf('  foo'), 2);
    assert.strictEqual(indentOf('foo'), 0);
    assert.strictEqual(indentOf('    - bar'), 4);
  });

  it('isBlankOrComment recognizes blank lines and comment lines', () => {
    assert.strictEqual(isBlankOrComment(''), true);
    assert.strictEqual(isBlankOrComment('   '), true);
    assert.strictEqual(isBlankOrComment('# a comment'), true);
    assert.strictEqual(isBlankOrComment('  # indented comment'), true);
    assert.strictEqual(isBlankOrComment('key: value'), false);
  });

  it('stripQuotes removes matching single or double quotes only', () => {
    assert.strictEqual(stripQuotes('"quoted"'), 'quoted');
    assert.strictEqual(stripQuotes("'quoted'"), 'quoted');
    assert.strictEqual(stripQuotes('unquoted'), 'unquoted');
    assert.strictEqual(stripQuotes('"mismatched\''), '"mismatched\'');
  });

  it('parseInlineList parses a bracketed comma list, stripping quotes and empties', () => {
    assert.deepStrictEqual(parseInlineList('[a, "b", \'c\']'), ['a', 'b', 'c']);
    assert.deepStrictEqual(parseInlineList('[]'), []);
  });

  it('checkUnsupportedShape defaults topLevelKey to "mcpServers"', () => {
    const withMcpServersFlow = 'mcpServers: {foo: bar}';
    const rejected = checkUnsupportedShape(withMcpServersFlow);
    assert.ok(rejected);
    assert.strictEqual(rejected.reason, 'unparseable');
    assert.match(rejected.detail, /mcpServers/);
  });

  it('checkUnsupportedShape(text, topLevelKey) targets the caller-supplied key for the flow-style check', () => {
    const withExtensionsFlow = 'extensions: {foo: bar}';
    // Default key (mcpServers) does NOT reject an extensions: flow-style line.
    assert.strictEqual(checkUnsupportedShape(withExtensionsFlow), null);
    // Explicit 'extensions' key DOES reject it.
    const rejected = checkUnsupportedShape(withExtensionsFlow, 'extensions');
    assert.ok(rejected);
    assert.strictEqual(rejected.reason, 'unparseable');
    assert.match(rejected.detail, /extensions/);
  });

  it('checkUnsupportedShape rejects tabs, anchors/aliases, and pollution keys regardless of topLevelKey', () => {
    assert.strictEqual(checkUnsupportedShape('key:\tvalue', 'extensions').reason, 'unparseable');
    assert.strictEqual(checkUnsupportedShape('foo: &anchor bar', 'extensions').reason, 'unparseable');
    assert.strictEqual(checkUnsupportedShape('__proto__: value', 'extensions').reason, 'polluted');
  });

  it('checkUnsupportedShape returns null for a clean, documented-shape input', () => {
    assert.strictEqual(checkUnsupportedShape('extensions:\n  foo:\n    type: stdio\n', 'extensions'), null);
  });

  it('parseMappingBlock parses flat key/value pairs at a fixed indent', () => {
    const lines = ['foo: bar', 'baz: qux'];
    const { obj, nextIndex } = parseMappingBlock(lines, 0, 0);
    assert.deepStrictEqual(obj, { foo: 'bar', baz: 'qux' });
    assert.strictEqual(nextIndex, 2);
  });

  it('parseMappingBlock recurses into a nested block mapping (object-keyed, Goose extensions shape)', () => {
    const lines = ['extensions:', '  filesystem:', '    type: stdio', '    cmd: npx'];
    const { obj } = parseMappingBlock(lines, 1, 2);
    assert.deepStrictEqual(obj, { filesystem: { type: 'stdio', cmd: 'npx' } });
  });

  it('parseListBlock parses a block sequence of mappings (continue-dev mcpServers shape)', () => {
    const lines = ['- name: srv', '  command: node'];
    const { items } = parseListBlock(lines, 0, 0);
    assert.deepStrictEqual(items, [{ name: 'srv', command: 'node' }]);
  });
});
