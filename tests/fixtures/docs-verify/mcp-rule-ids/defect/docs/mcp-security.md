# Fixture MCP Security Doc (defect)

This row deliberately OMITS `broad-inheritance` and documents only the
`npx-no-version` half of the dynamic `{npx|uvx}-no-version` expansion — the
planted defect this fixture exists to prove. Two findings are expected:
`fixture-detector/broad-inheritance` and `fixture-detector/uvx-no-version`.

| Detector | Rule IDs | Severity |
|----------|----------|----------|
| `fixture-detector` | `inlined-secret`, `npx-no-version` | medium |
