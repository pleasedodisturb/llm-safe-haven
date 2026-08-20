'use strict';

// Tests for lib/docs-verify/helpers/slug.js (G-1570, 21-03 Task 1).
//
// GitHub has never published an official anchor-slug specification. This
// suite pins the reverse-engineered behavior recorded in
// .planning/phases/21-doc-drift-guard/21-03-PLAN.md: repeated hyphens are
// NOT collapsed, leading/trailing hyphens are NOT trimmed (a cross-AI
// reviewer's trim claim was checked against github-slugger's source and
// REFUTED), NFC normalization runs before lowercasing, duplicate slugs get
// numeric suffixes assigned in document order, and ATX-only heading
// recognition (Setext headings are explicitly out of grammar).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { slugify, headingSlugs } = require('../../lib/docs-verify/helpers/slug.js');

describe('slug.js -- module contract', () => {
  it('exports slugify and headingSlugs', () => {
    assert.equal(typeof slugify, 'function');
    assert.equal(typeof headingSlugs, 'function');
  });

  it('is not registered as a docs:verify check', () => {
    assert.equal(
      fs.existsSync(path.join(__dirname, '..', '..', 'lib', 'docs-verify', 'slug.js')),
      false,
      'slug helper must not sit at the top level where loadChecks() would require it'
    );
    const { loadChecks } = require('../../lib/docs-verify/index.js');
    const { checks, errors } = loadChecks();
    assert.deepEqual(errors, []);
    assert.ok(checks.length > 0, 'non-vacuity: registry must not be empty');
    assert.ok(!checks.map((c) => c.id).includes('slug'), 'slug helper must not be registered as a check');
  });
});

describe('slugify -- ASCII normalization', () => {
  it('lowercases and joins words with single hyphens', () => {
    assert.equal(slugify('## Case Study: Something Happened'), 'case-study-something-happened');
  });

  it('strips punctuation rather than converting it to a hyphen', () => {
    assert.equal(slugify("What's New?"), 'whats-new');
  });

  it('strips leading/trailing whitespace (leading hash marks pinned separately below)', () => {
    assert.equal(slugify('  Trailing   '), 'trailing');
  });
});

describe('slugify -- non-collapsing / non-trimming hyphens (pinned, reverse-engineered)', () => {
  it('does NOT collapse two consecutive hyphens produced by a stripped em-dash', () => {
    assert.equal(slugify('Foo — Bar'), 'foo--bar');
  });

  it('does NOT trim a leading hyphen produced by a stripped leading character (refutes the trim claim)', () => {
    const got = slugify('## — Leading dash');
    assert.equal(
      got.charAt(0),
      '-',
      `leading hyphen must NOT be trimmed (github-slugger has no trim step) — got: ${JSON.stringify(got)}`
    );
  });

  it('does NOT trim a trailing hyphen produced by a stripped trailing character', () => {
    const got = slugify('Trailing dash —');
    assert.equal(
      got.charAt(got.length - 1),
      '-',
      `trailing hyphen must NOT be trimmed — got: ${JSON.stringify(got)}`
    );
  });
});

describe('slugify -- leading hash marks', () => {
  it('strips a leading run of hash marks and the whitespace following it', () => {
    assert.equal(slugify('### Three Hashes'), 'three-hashes');
  });
});

describe('slugify -- Unicode', () => {
  it('NFC-normalizes so a decomposed and precomposed spelling produce the same slug', () => {
    const decomposed = 'Café Notes'; // e + combining acute accent (NFD)
    const precomposed = 'Café Notes'; // precomposed é (NFC)
    assert.notEqual(decomposed, precomposed, 'sanity: inputs must actually differ byte-wise');
    assert.equal(
      slugify(decomposed),
      slugify(precomposed),
      `NFC normalization missing: ${slugify(decomposed)} vs ${slugify(precomposed)}`
    );
  });

  it('preserves non-ASCII letters via Unicode-aware character classes', () => {
    assert.equal(slugify('Café Notes'), 'café-notes');
  });
});

describe('slugify -- inline code inside a heading', () => {
  it('contributes the backticked text with the backticks (and enclosed punctuation) stripped', () => {
    assert.equal(slugify('## The `computeExit()` contract'), 'the-computeexit-contract');
  });
});

describe('headingSlugs -- duplicate suffixing in document order', () => {
  it('assigns bare, -1, -2 to three identically-slugging headings (three, not two)', () => {
    const md = '# Dup\n\n# Dup\n\n# Dup\n';
    const s = headingSlugs(md);
    assert.equal(s.length, 3, `expected 3 headings, got ${s.length}`);
    assert.equal(s.map((h) => h.slug).join(','), 'dup,dup-1,dup-2');
  });
});

describe('headingSlugs -- fence tracking', () => {
  it('does not slug a hash line inside a backtick fence carrying an info string, or inside a tilde fence', () => {
    const fence = '```';
    const md = `# Real\n\n${fence}bash\n# NotAHeading\n${fence}\n\n~~~\n# AlsoNot\n~~~\n`;
    const s = headingSlugs(md);
    assert.equal(
      s.length,
      1,
      `fenced hash line counted as a heading, got ${s.length}: ${s.map((h) => h.slug).join(',')}`
    );
    assert.equal(s[0].slug, 'real');
  });

  it('is non-vacuous and excludes ~30 fenced shell-comment hash lines against the real corpus', () => {
    const text = fs.readFileSync(path.join(__dirname, '..', '..', 'docs', 'supply-chain-defense.md'), 'utf8');
    const s = headingSlugs(text);
    assert.ok(s.length > 0, 'non-vacuity: no headings found in the real file');
    const bogus = s.filter((h) =>
      /^(quick-check|record-baseline|reconstructed-postinstall-hook-signature|find-sha-for-any-action|npmrc)/.test(
        h.slug
      )
    );
    assert.equal(
      bogus.length,
      0,
      `fenced shell comments were slugged as headings: ${bogus.map((h) => `${h.line}:${h.slug}`).join(', ')}`
    );
  });
});

describe('headingSlugs -- Setext headings are out of grammar', () => {
  it('produces no slug for a Setext-underlined heading (only the real ATX heading counts)', () => {
    const s = headingSlugs('Setext Title\n============\n\n# Real\n');
    assert.equal(s.length, 1, `Setext headings are out of grammar and must produce no slug, got: ${JSON.stringify(s.map((h) => h.slug))}`);
    assert.equal(s[0].slug, 'real');
  });
});
