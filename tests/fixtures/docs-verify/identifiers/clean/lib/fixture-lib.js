'use strict';

// Control C: UNEXPORTED_CONST is a real declared const, present in this
// module's raw source text, but deliberately NOT exported below -- mirrors
// lib/traverse/wave-spec.js's REQUIRED_SECTIONS (21-RESEARCH.md Pitfall 2).
// The clean root's scoped doc claims this identifier and must NOT be
// reported, because "exists" means raw source-text presence, never
// require()-and-inspect-exports.

const UNEXPORTED_CONST = 'declared but not exported';

function helperFn() {
  return UNEXPORTED_CONST;
}

module.exports = { helperFn };
