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
