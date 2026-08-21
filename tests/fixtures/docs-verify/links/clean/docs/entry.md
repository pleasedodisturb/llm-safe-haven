# Links Fixture — Clean Root

Every link below must produce zero findings from Check 3 -- the full control battery for the
pinned link grammar (see 21-03-PLAN.md "Pinned link grammar").

- Existing sibling: [ok](friend.md)
- External (never fetched): [ext](https://example.com)
- Anchor-only (belongs to Check 4, not this check): [anchor](#somewhere)
- Existing directory (GitHub renders this as a tree view -- a working link): [dir](sub)
- Titled link (the title is stripped before resolution): [titled](friend.md "My Friend")
- Angle-bracketed target containing a space: [spaced](<friend with space.md>)
- Image link (an image is a link for existence purposes): ![img](pic.png)
- Autolink form (bare angle brackets, no square-bracket text) to a real file: <./friend.md>
- Reference-style link (out of grammar -- must produce zero claims): [refstyle][ref]
- Nested-parenthesis target (out of grammar -- must produce zero claims, never a corrupt one): [nested](friend(2).md)

[ref]: friend.md

Fenced example link (out of grammar -- a documented example is not a live link):

```
[fenced](gone-in-a-fence.md)
```

## Somewhere

The heading the anchor-only link above resolves against, once Check 4 (anchors, added in Task 3)
also sweeps this fixture root via the shared CLI registry.
