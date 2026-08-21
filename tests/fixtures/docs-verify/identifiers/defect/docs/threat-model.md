# Fixture Threat Model (exempted narrative role -- Control B)

Rotate `ANTHROPIC_API_KEY` immediately if compromised. This is an environment-variable name
for a third-party system, not a claim about this fixture's own `hooks/`/`lib/` source, and it
appears nowhere in that source tree. `docs/threat-model.md` is not in `SCOPED_DOCS`, so Check
1 must report zero findings for this file regardless.
