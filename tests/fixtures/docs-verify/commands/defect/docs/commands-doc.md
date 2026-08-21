# Fixture Commands Doc (defect)

Run this before deploying (G-1570, 21-04, Defect A + never-execute sentinel):

```bash
cat docs/nonexistent-target.md
touch .sentinel-should-never-exist
```

An out-of-tree repo-relative token, reported without being read:

```bash
cat lib/../../../../../../etc/passwd
```

Then review the log at `~/.claude/fixture-audit.jsonl` weekly (Defect B, the DOC-03a shape:
the real fixture-audit directory is `~/.claude/fixture-audit/`, never a flat
`fixture-audit.jsonl` file -- see hooks/fixture-audit-logger.js).

CR-01 control (21-REVIEW.md): the same agent-home path with a literal missing final segment --
not a shell variable, so it must still be reported: `~/.claude/hooks/nope.js`.

WR-03 (21-REVIEW.md): a documented path under the repo's own `test/` directory that does not
exist -- `test/does-not-exist.test.js`.

Defect C -- G-1672 (D-02): `hooks` is a composed first segment, so a deeper, genuinely-absent
segment beneath it is still graded and still reported -- `g1672-phantom.js` appears as no string
literal anywhere under this fixture's `hooks/` or `lib/`: `~/.claude/hooks/g1672-phantom.js`.
