# Fixture MCP Security Doc (clean)

Documents every rule ID the fixture-detector module emits, so Check 2 (mcp-rule-ids) reports
zero findings against this root. This table's cells are all lowercase-hyphen detector/rule
tokens, never UPPER_SNAKE_CASE and never a parenthesised call, so Check 1 (identifiers) never
extracts a claim from this file either.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `fixture-detector` | `inlined-secret`, `{npx\|uvx}-no-version` | medium |

`scan --mcp` discovers and parses MCP server configs across **2 agents**.

One detector runs on every scan.

Two agents were evaluated and later dropped (an unbindable claim -- no registry entry names
this exact phrasing, so this is graded as a warn, not a fail).
