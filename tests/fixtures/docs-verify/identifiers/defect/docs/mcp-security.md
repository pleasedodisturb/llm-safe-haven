# Fixture MCP Security Doc (cross-check satisfier)

Documents every rule ID `fixture-detector` emits, so Check 2 (mcp-rule-ids) reports zero
findings against this root -- see the header comment in the sibling `fixture-detector.js`
for why this file exists. None of the backticked tokens below are UPPER_SNAKE_CASE or a
`functionName()`-shaped call, so Check 1 (identifiers) does not extract any claim from this
file either.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `fixture-detector` | `inlined-secret`, `broad-inheritance`, `{npx\|uvx}-no-version` | medium |
