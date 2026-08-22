# Fixture Commands Doc (clean)

Control A -- a fenced block referencing a path that exists:

```bash
cat docs/commands-doc.md
```

Control D -- an absolute system path outside the internal prefix list, zero findings:

```bash
cat /etc/passwd
```

Control B -- an inline agent-home path whose directory segment is a real source literal
(`fixture-audit`, composed in hooks/fixture-audit-logger.js) and whose file segment is a real
digit date, both graded with composition-level evidence: `~/.claude/fixture-audit/2026-08-20.jsonl`.

Control C -- all four placeholder shapes, each exempt from the segment rule: an angle-bracketed
name `~/.claude/fixture-audit/<session-id>`, a wildcard `~/.claude/fixture-audit/*.jsonl`,
the literal placeholder spelling `~/.claude/fixture-audit/YYYY-MM-DD.jsonl`, and a real digit
date already covered by Control B above.

Control E -- CR-01 (21-REVIEW.md): a shell-variable-interpolation segment, pinning
docs/guides/quick-start.md:659's exact shape:

```bash
for hook in bash-firewall.js secret-guard.js audit-logger.js; do
  if node --check ~/.claude/hooks/$hook 2>/dev/null; then
    echo "OK: $hook"
  else
    echo "BROKEN: $hook"
  fi
done
```

Control G -- WR-03 (21-REVIEW.md): a documented path under the repo's own `test/` directory
(asymmetric with `tests/`, both real top-level directories) that DOES exist:
`test/fixture-real.test.js`.

Control H -- G-1672 (D-02): an inline agent-home path whose first segment (`fixture-config`) is
not composed anywhere under `hooks/` or `lib/` -- the whole token is out of scope and produces
zero findings regardless of tier: `~/.claude/fixture-config.json`.

Control I -- G-1672 (D-02, the anchoring test): the first segment (`fixture-profiles`) is not
composed, but a DEEPER segment (`settings.json`) genuinely IS composed elsewhere in this fixture
tree (see `hooks/fixture-settings-path.js`) -- a rule that scanned all segments instead of only
the first would wrongly pull this token back into scope. It must still produce zero findings:
`~/.claude/fixture-profiles/work/settings.json`.

Control J -- G-1672 (D-02, CR-01 fix): the first segment (`settings`) IS the derived STEM of a
composed file (`settings.json`, see `hooks/fixture-settings-path.js`), but this token names a
DEEPER, unrelated file beneath a `settings/` directory this repository never composes -- a stem
match is only a legitimate stand-in for the composed file when the token names that file directly
(the anchor is the token's OWN final segment), never when the anchor is merely the first component
of a longer, unrelated path. It must still produce zero findings:
`~/.claude/settings/fixture-profile.json`.
