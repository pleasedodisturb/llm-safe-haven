# Fixture MCP Security Doc (null-detector-id)

The `some-suffix` rule IS documented here, correctly. This fixture proves
that a detector module whose id constant is declared with double quotes
(unparseable by the checker's single-quote-only grammar) forces an
incomplete sweep rather than a fabricated undocumented-rule finding.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `double-quoted-detector` | `some-suffix` | medium |
