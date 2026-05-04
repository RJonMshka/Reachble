---
name: Wrong verdict (false SAFE or false CRITICAL/HIGH)
about: Reachble said SAFE but the CVE is reachable, or said CRITICAL/HIGH but it isn't
labels: verdict
---

**CVE ID**

**Package + version**

**Verdict Reachble gave**
- [ ] False SAFE (reachble said not reachable, but it is)
- [ ] False CRITICAL/HIGH (reachble said reachable, but it isn't)

**Why it's wrong**

<!-- Which file imports the symbol, or which file doesn't? -->

**Scan output (table format)**

```
paste reachble scan --format table output here
```

**Relevant source file snippet**

```ts
// the import or call that Reachble got wrong
```
