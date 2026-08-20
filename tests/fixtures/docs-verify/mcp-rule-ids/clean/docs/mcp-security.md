# Fixture MCP Security Doc (clean)

Every rule ID `fixture-detector` emits is documented below, including the
dynamic `${bin}-no-version` site expanded as a brace-alternation token with
a backslash-escaped pipe — the same shape `docs/mcp-security.md` itself uses
for `unpinned-execution`. This proves `splitTableRow` does not mis-split on
`\|`.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `fixture-detector` | `inlined-secret`, `broad-inheritance`, `{npx\|uvx}-no-version` | medium |
