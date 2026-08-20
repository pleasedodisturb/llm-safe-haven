# Fixture MCP Security Doc (cross-check satisfier)

Documents every rule ID the fixture-detector module emits, so Check 2 (mcp-rule-ids) reports
zero findings against this root -- see the header comment in the sibling fixture-detector.js
for why this file exists. This table's cells are all lowercase-hyphen detector/rule tokens,
never UPPER_SNAKE_CASE and never a parenthesised call, so Check 1 (identifiers) never
extracts a claim from this file either.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `fixture-detector` | `inlined-secret`, `broad-inheritance`, `{npx\|uvx}-no-version` | medium |
