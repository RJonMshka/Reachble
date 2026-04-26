# Reachble

**Auto-generated VEX for npm projects, backed by reachability analysis.**

Most CVEs flagged in your `package-lock.json` are not actually exploitable in
your code. Research shows 60–80% sit in dependency code paths that are never
called. SBOM mandates (US EO 14028, EU CRA) increasingly require a **VEX**
statement explaining why each unaffected CVE is unaffected. Today that's a
spreadsheet. Reachble produces it from your code.

```bash
npx reachble scan
```

Outputs **CycloneDX VEX + OpenVEX** with machine-checkable evidence:
*"vulnerable function never imported"*, *"reachable but no path from any
HTTP entry point"*, *"reachable from unauthenticated `POST /api/upload`"*.

### What's different

| | Traditional SCA | OSV-Scanner | Endor Labs | **Reachble** |
|---|---|---|---|---|
| CVE in lockfile detection | ✓ | ✓ | ✓ | ✓ |
| Function-level reachability | | | ✓ | ✓ |
| Attack-surface scoring (entry points) | | | ✓ | ✓ |
| **Auto-generates VEX** | | | partial | **✓** |
| **Open source** | varies | ✓ | | **✓** |
| JS/TS specialization | | partial | partial | **✓** |

### Verdict tiers

```
CRITICAL — reachable from unauthenticated external input
HIGH     — reachable from authenticated route or internal service
LOW      — reachable in code, no external input path found
SAFE     — vulnerable symbol never reached  → VEX `not_affected`
```

### Demo (planned, milestone M10)

A small Express app with two known lodash CVEs side-by-side: one reachable
(verdict `CRITICAL`), one unreachable (verdict `SAFE` → VEX `not_affected`
with justification `vulnerable_code_not_in_execute_path`). Output committed
to `docs/demo-output.md` so you can see exactly what Reachble emits.

### Status

Pre-MVP. Building. See [`docs/PLAN.md`](docs/PLAN.md) for milestones,
[`docs/GUIDE.md`](docs/GUIDE.md) for the research notes and ADRs, and
[`CLAUDE.md`](CLAUDE.md) for the project's hard rules.

MIT.
