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

## What's different

| | Traditional SCA | OSV-Scanner | Endor Labs | **Reachble** |
|---|---|---|---|---|
| CVE in lockfile detection | ✓ | ✓ | ✓ | ✓ |
| Function-level reachability | | | ✓ | ✓ |
| Attack-surface scoring (entry points) | | | ✓ | ✓ |
| **Auto-generates VEX** | | | partial | **✓** |
| **Open source** | varies | ✓ | | **✓** |
| JS/TS specialization | | partial | partial | **✓** |

## Verdict tiers

```
CRITICAL — reachable from unauthenticated external input
HIGH     — reachable from authenticated route or internal service
LOW      — reachable in code, no external input path found
SAFE     — vulnerable symbol never reached  → VEX `not_affected`
```

## Install

```bash
npm install -g reachble
# or run directly
npx reachble scan
```

## Usage

```bash
reachble scan                          # scan cwd, output table + VEX
reachble scan --path ./my-app          # specify project directory
reachble scan --format vex             # CycloneDX VEX output
reachble scan --format json            # JSON output
reachble scan --fail-on high           # exit 1 if any HIGH/CRITICAL found
```

## Demo

A minimal Express app with two lodash CVEs side-by-side:

```
Package   Version   CVE              Verdict   CVSS   Reason
──────────────────────────────────────────────────────────────────────────
lodash    4.17.18   CVE-2020-28500   SAFE      5.0    Vulnerable symbol(s) not imported
lodash    4.17.18   CVE-2021-23337   LOW       7.5    Vulnerable symbol(s) imported at src/routes/render.ts:8

2 CVEs · 0 CRITICAL · 0 HIGH · 1 LOW · 1 SAFE
VEX written to reachble-vex.cdx.json
```

## What it supports

- **Lockfiles:** npm, yarn, pnpm
- **CVE data:** OSV.dev, NVD, GHSA, EPSS scoring
- **Output formats:** CycloneDX VEX, OpenVEX, JSON, table
- **CI integration:** `--fail-on high` exits 1 when real threats are found

MIT. No telemetry. No tracking.
