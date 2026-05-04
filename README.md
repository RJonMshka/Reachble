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

### Demo

A minimal Express app with two lodash CVEs side-by-side: one reachable
(`template` is imported → verdict `LOW`), one not (`trim` never imported →
verdict `SAFE` → VEX `not_affected`). See [`docs/demo-output.md`](docs/demo-output.md)
for the full scan output.

### Status

MVP — lockfile parsing, import-graph reachability, OSV/NVD/EPSS CVE resolution,
and CycloneDX VEX + OpenVEX output are all working. 357 tests, lint clean.

See [`docs/GUIDE.md`](docs/GUIDE.md) for research notes and ADRs, and
[`CLAUDE.md`](CLAUDE.md) for the project's hard rules.

MIT. Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security issues: see [`SECURITY.md`](SECURITY.md).
