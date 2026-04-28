# GUIDE.md — Reachble Knowledge Base

This document grows as we build. Every significant decision, research finding, gotcha,
or hard-won insight gets recorded here. It is the institutional memory of the project.

---

## Table of Contents

1. [Problem Space](#1-problem-space)
2. [Prior Art & Competitive Landscape](#2-prior-art--competitive-landscape)
3. [Call Graph Analysis — Research Notes](#3-call-graph-analysis--research-notes)
4. [CVE Data Sources — Field Notes](#4-cve-data-sources--field-notes)
5. [Attack Surface Detection — Patterns](#5-attack-surface-detection--patterns)
6. [Scoring Model](#6-scoring-model)
7. [Known Limitations & Edge Cases](#7-known-limitations--edge-cases)
8. [Architecture Decisions](#8-architecture-decisions)
9. [Performance Benchmarks](#9-performance-benchmarks)
10. [Changelog](#10-changelog)
11. [Symbol Extraction from Fix Commits](#11-symbol-extraction-from-fix-commits)
12. [Cross-Run Cache Invariants](#12-cross-run-cache-invariants)

---

## 1. Problem Space

**Headline framing:** Reachble auto-generates **VEX** (Vulnerability Exploitability eXchange)
for npm/JS/TS projects with machine-checkable evidence. SBOM mandates — US Executive Order
14028, the EU Cyber Resilience Act, NTIA SBOM minimum elements — increasingly require VEX
to disambiguate "CVE in SBOM" from "CVE actually exploitable here." That triage is manual
today: spreadsheets, audit calls, security tickets. We make it automatic.

**The technical core:** a CVE scorer that answers a sharper question than traditional SCA.
Research (Endor Labs, 2024) shows 60–80% of flagged CVEs exist in code paths that are never
executed. We add two filters:

1. **Reachability** — is the vulnerable function actually called by the application?
2. **Attack surface** — is it reachable from attacker-controlled input (HTTP, CLI, env)?

**The scoring gap we fill:**

```
Traditional SCA:   CVE in tree → flag it
Reachability SCA:  CVE in tree + function called → flag it
This tool:         CVE in tree + function called + reachable from user input → flag CRITICAL
                   CVE in tree + function called + internal only → flag LOW
                   CVE in tree + function never called → flag SAFE → VEX `not_affected`
```

**Why VEX as the headline output:**
- It's the standardized auditor-readable format — GHSA, CycloneDX, OpenVEX, SPDX all align
- It carries machine-checkable *justifications* — exactly what reachability evidence provides
- The competitive surface is wide open: no OSS tool today auto-generates VEX from JS/TS code analysis
- Aligns the project with regulatory tailwinds (SBOM mandates) instead of fighting against alert-fatigue inertia

---

## 2. Prior Art & Competitive Landscape

### Commercial tools with reachability

| Tool | Approach | Weakness |
|------|----------|----------|
| Endor Labs | Function-level call graph | Expensive, enterprise-focused |
| Snyk Open Source | Static + runtime | JS/TS reachability limited |
| Xygeni | Call graph + EPSS | Closed source |
| Binarly | Environment-aware (firmware/containers) | Not application-layer JS |
| Orca Security | Cloud-level reachability | Infrastructure, not code |

### Open source tools

| Tool | Reachability? | Notes |
|------|---------------|-------|
| OSV-Scanner | No | Best free CVE scanner, no call graph |
| Trivy | No | Container + lockfile, no code analysis |
| Grype | No | Good CVE matching, no reachability |
| pip-audit | No | Python only |

**Key gap confirmed:** No OSS tool does function-level reachability for JS/TS with
attack-surface scoring. Forrester (2024) now treats reachability as "table stakes"
for commercial SCA, but the OSS ecosystem hasn't caught up.

---

## 3. Call Graph Analysis — Research Notes

### Tool evaluation: ts-morph vs alternatives

**ts-morph** (chosen)
- Wraps the TypeScript compiler API directly
- Accurate type resolution — knows that `import { template } from 'lodash'` is specifically `lodash.template`
- Handles `.d.ts` for dependency type info
- Slower on cold start than babel-based parsers but more accurate
- Good for: TypeScript projects, accurate symbol resolution

**@typescript-eslint/parser** (used for JS in Phase 1)
- Fast, AST-only (no type info)
- Good for import-level analysis (Phase 1)
- Cannot resolve whether `obj.method()` is the vulnerable method

**Babel parser**
- Fastest pure parser
- No type info
- Adequate for import scanning but not call graph

**Decision:** Use `@typescript-eslint/parser` for Phase 1 (import-level), upgrade to
`ts-morph` for Phase 2 (full call graph). ts-morph requires a `tsconfig.json` — document
this requirement clearly and provide a fallback config.

### Call graph construction strategy

A call graph edge `A → B` exists when function A calls function B.

For our purposes, we need a slightly different structure:
- Nodes: function/method definitions in user code
- Edges: calls into dependency modules
- Entry points: HTTP handlers, CLI args, etc. (see §5)

We don't need a full inter-procedural call graph of the entire codebase. We need:
1. Entry point nodes
2. BFS from entry points
3. Stop when we reach a dependency import
4. Check if that import's symbol matches a CVE's `AffectedSymbol`

This is narrower than full call graph analysis and much faster.

### Barrel file handling (important)

Many packages use barrel files (`index.ts`) that re-export everything:
```ts
export { template } from './template'
export { merge } from './merge'
```

If a user does `import { template } from 'lodash'`, we need to trace through the barrel
to know they're using `./template`, not `./merge`. ts-morph handles this correctly.

If a user does `import lodash from 'lodash'` or `import * as _ from 'lodash'`, we must
conservatively assume all exports are potentially used.

### Dynamic requires — the hard problem

`require(variableName)` is unresolvable statically. Strategy:
- Detect and flag as `confidence: low`
- Mark the entire module as potentially reachable if the variable could resolve to a vulnerable package
- Document this clearly — it's a known false positive source

---

## 4. CVE Data Sources — Field Notes

### OSV.dev (primary)

- **Endpoint:** `https://api.osv.dev/v1/querybatch`
- **Rate limit:** No auth required, generous limits (1000 req/min)
- **Best feature:** `affected[].ecosystem_specific.affected_functions` — gives us exact function names for some CVEs
- **Coverage:** ~95% of npm CVEs as of 2024
- **Structured data quality:** High — human-curated for major CVEs
- **Symbol coverage:** ~30% of CVEs have explicit function names. The rest need NVD description parsing or manual curation.

```json
// OSV response shape (simplified)
{
  "id": "GHSA-xxxx-xxxx-xxxx",
  "aliases": ["CVE-2024-XXXXX"],
  "affected": [{
    "package": { "name": "lodash", "ecosystem": "npm" },
    "ranges": [{ "type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}] }],
    "ecosystem_specific": {
      "affected_functions": ["template"]  // <-- gold
    }
  }]
}
```

### NVD API v2 (fallback)

- **Endpoint:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Auth:** API key recommended (10 req/sec vs 5 req/sec without)
- **Best feature:** CVSS v3/v4 scores are authoritative here
- **Weakness:** No function-level affected symbol data
- **Use for:** CVSS scores, descriptions, CWE classification

### GitHub Advisory Database

- **Endpoint:** GraphQL `https://api.github.com/graphql`
- **Auth:** GitHub token required
- **Best feature:** npm-specific, high quality for JS ecosystem
- **Use for:** Cross-referencing, filling gaps in OSV

### EPSS (Exploit Prediction Scoring System)

- **Endpoint:** `https://api.first.org/data/1.0/epss?cve=CVE-XXXX`
- **What it is:** Probability (0–1) that a CVE will be exploited in the wild within 30 days
- **Use in scoring:** EPSS > 0.1 elevates a LOW verdict; EPSS > 0.3 elevates a SAFE to LOW
- **Cache aggressively:** Updates daily, cache for 24h

### Symbol extraction strategy (when OSV has no function names)

1. Check OSV `affected_functions` first
2. Check NVD description — regex for function/method names in backticks
3. Check GHSA description — similar parsing
4. Fall back to package-level match with `confidence: low`
5. Maintain a community-curated lookup table in `packages/core/src/data/symbol-overrides.json`

---

## 5. Attack Surface Detection — Patterns

### Express.js entry points

```ts
// These all create HTTP entry points
app.get('/path', handler)
app.post('/path', handler)
app.use(middleware)
router.get('/path', handler)
```

Detection: find `app.*` and `router.*` call expressions where the callee is an
Express-shaped object (identified by `express()` call site or `Router()` call site).

### Authenticated route heuristic

```ts
app.get('/admin', authenticate, handler)  // middleware before handler = possibly auth
app.get('/public', handler)               // no middleware = likely unauthenticated
```

Heuristic: if a route has 3+ arguments and the penultimate is a function reference
matching patterns like `auth`, `authenticate`, `requireLogin`, `isAdmin`, treat as
authenticated. This is a heuristic — document the false positive risk.

### Fastify patterns

```ts
fastify.route({ method: 'GET', url: '/path', handler })
fastify.get('/path', handler)
fastify.addHook('preHandler', hook)
```

### CLI entry points

```ts
process.argv           // raw args — always tainted
program.argument()     // commander
yargs.option()         // yargs
minimist(process.argv) // minimist
```

### Environment variables

```ts
process.env.USER_INPUT   // any process.env read = potentially tainted
```

Note: not all env vars are attacker-controlled, but they can be in container/serverless
environments. Treat as `LOW` attack surface (external but typically controlled by operator).

### File inputs

```ts
fs.readFile(userPath, ...)     // tainted if userPath derives from user input
fs.readFileSync(req.body.path) // definitely tainted
```

---

## 6. Scoring Model

### Verdict decision tree

```
Is the vulnerable package in the dependency tree?
  No → skip (not installed)
  Yes ↓

Is the vulnerable symbol imported anywhere in the codebase?
  No → SAFE
  Yes ↓

Is the vulnerable symbol reachable via call graph from any code path?
  No → SAFE (Phase 2+)
  Yes ↓

Is the call path reachable from an attack surface entry point?
  No → LOW
  Yes ↓

Is the entry point externally accessible (unauthenticated HTTP, CLI, file)?
  No → HIGH (authenticated/internal)
  Yes → CRITICAL
```

### EPSS adjustment

```
base_verdict = above decision tree result
epss = EPSS score for this CVE

if base_verdict == SAFE and epss > 0.3:  override to LOW (widely exploited, be careful)
if base_verdict == LOW and epss > 0.1:   upgrade to MEDIUM
if base_verdict == HIGH and epss > 0.5:  upgrade to CRITICAL
```

### Confidence scoring

```
high:    ts-morph analysis, no dynamic calls in path, explicit AffectedSymbol
medium:  import-level match, symbol name from NVD description parsing
low:     dynamic require/import in path, namespace import (import * as x), no symbol data
```

---

## 7. Known Limitations & Edge Cases

### Static analysis can't see everything

- **Dynamic requires:** `require(variable)` — marked `confidence: low`
- **Eval'd code:** not analyzed
- **Runtime monkey-patching:** `lodash.template = maliciousFunction` — not detectable
- **Webpack/bundler transforms:** may change import names — analyze pre-bundle source only

### False negatives (we say SAFE but it's not)

- Plugin systems that load packages dynamically
- Packages required conditionally based on runtime env
- Test-only dependencies that share a vulnerable package with prod code
  (mitigated: we downgrade verdicts for test file paths)

### False positives (we say CRITICAL but it's fine)

- Namespace imports (`import * as _`) when only safe functions are used
- Packages used only in type positions (imports erased at runtime)
  (mitigated: ts-morph can detect type-only imports)

### Transitive dependencies

A vulnerable package at depth 4 (your dep's dep's dep's dep) may be flagged if
a call chain reaches it. This is correct behavior but can surprise users. The call
path evidence in the verdict output shows the full chain.

---

## 8. Architecture Decisions

### ADR-001: ts-morph over babel for Phase 2 call graph

**Date:** Project start
**Decision:** Use ts-morph for call graph construction in Phase 2
**Rationale:** Type resolution is required to accurately match `import { template } from 'lodash'`
to the vulnerable `template` function. Babel gives us syntax only. ts-morph gives us semantics.
**Trade-off:** Requires `tsconfig.json`. We provide a fallback minimal config.

### ADR-002: OSV as primary CVE source

**Date:** Project start
**Decision:** OSV.dev as primary, NVD v2 as fallback for CVSS scores
**Rationale:** OSV has `affected_functions` data that NVD lacks. It's free, high-quality,
and purpose-built for SCA use cases.

### ADR-003: SQLite for local cache

**Date:** Project start
**Decision:** `better-sqlite3` for caching CVE data locally
**Rationale:** No daemon, fast synchronous API, fits perfectly for a CLI tool.
Alternative (file-based JSON cache) was rejected due to concurrent write safety.

### ADR-004: Zod at all external boundaries

**Date:** Project start
**Decision:** Every API response (OSV, NVD, GHSA, EPSS) must be parsed through a Zod schema
**Rationale:** CVE data comes from external systems. Malformed responses should fail loudly,
not silently produce wrong verdicts. Security tooling must be trustworthy.

### ADR-005: Single package, JS/TS only

**Date:** Project start
**Decision:** One package (`packages/core`), no language adapter abstraction, deep JS/TS focus.
**Rationale:** The research value is in the scoring algorithm and attack-surface-aware verdicts,
not in language breadth. Multi-language from day one would spread effort across infrastructure
before the core thesis is validated. The scoring engine is already decoupled from the analysis
layer — if multi-language ever becomes relevant, extracting an interface is a one-day refactor.
Ship something excellent in one language rather than something mediocre in four.

---

## 9. Performance Benchmarks & Thesis Validation

_MVP numbers measured on 2026-04-27. V1 targets are unverified — update after
call-graph work lands. Network time dominates MVP scan time (OSV + NVD + EPSS);
pure local analysis is sub-second for all projects tested._

### MVP thesis validation — real OSS projects

Three intentionally-vulnerable / real-world Express apps scanned on 2026-04-27
using `reachble scan --ignore-dev` (prod deps only, no network mocks).

| Project | Packages | Source files | CVE verdicts | LOW (reachable) | SAFE (eliminated) | Noise reduction |
|---|---|---|---|---|---|---|
| [DVNA](https://github.com/appsecco/dvna) | 340 | 7 | 58 | 18 | 40 | **69%** |
| [NodeGoat](https://github.com/OWASP/NodeGoat) | 463 | 8 | 87 | 13 | 74 | **85%** |
| [RealWorld Express](https://github.com/gothinkster/node-express-realworld-example-app) | 107 | 17 | 24 | 10 | 14 | **58%** |

**Result: 58–85% of flagged CVEs eliminated as `not_affected` without any manual review.**
This aligns with the Endor Labs (2024) finding of 60–80% unreachable CVEs in real projects.

### Key observations

- All LOW verdicts say "no specific vulnerable symbol identified" — OSV's `affected_functions`
  coverage is sparse for these older packages. V1 fix-commit symbol extraction (§11) will
  convert many of these package-level LOWs into either SAFE (wrong symbol) or confirmed LOW.
- DVNA has intentionally vulnerable packages (`node-serialize`, `mathjs`, `libxmljs`) —
  all correctly flagged LOW because they ARE imported. None were false SAFEs.
- NodeGoat's `marked@0.3.5` accounts for 6 of 13 LOW verdicts — one package, many CVEs,
  all correctly flagged because `marked` is imported in source.
- RealWorld Express's `axios@1.6.2` accounts for 6 of 10 LOW verdicts — axios is imported and
  has many CVEs, but none have `affected_functions` in OSV so they land as package-level LOW.
  Fix-commit extraction (V1 §11) should convert several of these to SAFE if the vulnerable
  functions aren't called.
- No false SAFEs observed: every package marked SAFE was genuinely absent from the import graph.

### Scan timing (MVP, wall clock including OSV + NVD + EPSS network calls)

| Project | Cold scan | Warm scan (cache hit) |
|---|---|---|
| DVNA (340 pkgs) | ~45s | <2s |
| NodeGoat (463 pkgs) | ~3min | <3s |
| RealWorld Express (107 pkgs) | ~30s | <1s |

_NVD rate-limit (1 req/sec without API key) dominates cold scan time.
Set `NVD_API_KEY` env var for 5x speedup. Warm scans are cache-only._

### Target budgets for local analysis only (V1, excluding network)

| Project size | MVP import analysis | V1 call graph (target, unverified) |
|---|---|---|
| Small (< 50 deps, < 10k LoC) | < 0.5s | < 5s |
| Medium (50–200 deps, 10–50k LoC) | < 1s | < 30s |
| Large (200–500 deps, 50–200k LoC) | < 3s | < 90s |
| XL (500+ deps) | < 10s | needs `--incremental` (see §12) |

---

## 10. Changelog

_Append entries here as work progresses._

### [Unreleased]

- Initial PLAN.md, CLAUDE.md, GUIDE.md created
- Architecture decided: single package, JS/TS deep focus, ts-morph, OSV, SQLite, Zod
- Decided against multi-language adapter pattern — see ADR-005
- 2026-04-25: Reframed product around VEX as the headline output (PLAN, GUIDE §1).
  Reachability is the engine; VEX is the deliverable.
- 2026-04-25: Restructured roadmap from "Phase 1–4" to MVP / V1 / Research. Phase 4
  (SaaS, VS Code, GitHub App, dashboards) removed entirely from scope.
- 2026-04-25: Promoted fix-commit symbol extraction from a fallback bullet to a
  first-class V1 workstream — see §11. This is the differentiator vs OSV-Scanner.
- 2026-04-25: Marked all §9 perf budgets "unverified — benchmark first" and added
  separate MVP and V1 targets.
- 2026-04-25: Added §12 cross-run cache invariants — required spec before V1 cache work.
- 2026-04-25: Added "Non-goals" sections to PLAN.md and CLAUDE.md to lock scope.

---

## 11. Symbol Extraction from Fix Commits

The single biggest gap in OSS reachability tooling: OSV's `affected_functions`
covers only ~30% of npm CVEs. The rest match at package level — same as
OSV-Scanner. Reachble's research contribution is to close that gap by reading
the fix commit.

### Pipeline

```
CveRecord.fixCommitUrls[]                        (from OSV references[type=FIX])
  │
  ├── resolve URL host (github.com / gitlab.com / bitbucket.org)
  ├── fetch unified diff (no clone — diff endpoint only)
  ├── filter to .js/.ts/.mjs/.cjs files
  ├── filter out test paths (**/*.test.*, **/*.spec.*, __tests__/**, test/**)
  │
  ├── parse changed hunks for export-reachable symbols:
  │     • function declarations           (function NAME(…))
  │     • exported const fns              (export const NAME = …)
  │     • class / method changes          (class NAME { METHOD(…) })
  │     • module.exports.NAME / exports.NAME =
  │     • default-export wrappers         (export default function NAME)
  │
  ├── cross-check against package’s public exports (pre-fix `package.json#exports`,
  │     `index.{js,ts}` re-exports) — discard private / internal symbols
  │
  └── emit AffectedSymbol[] with confidence:
        single exported fn touched          → medium
        multiple exported fns                → low + caveat enumerating alternatives
        only test files / docs / readme      → discard (no symbol info recoverable)
        edits to public types but no fns     → low + caveat 'type-shape change'
```

### Confidence rules

- `medium` is the ceiling — even the cleanest single-function fix could be a
  refactor that *renamed* the vulnerable symbol; we don't know without reading
  the security advisory body.
- Any extraction that touches >3 exported symbols → `low` + caveat.
- Test-only diffs → discard (the fix is elsewhere; symbol unrecoverable from this commit).
- README/changelog-only diffs → discard.

### Caching

Fix commits are immutable — long TTL (30d, refresh only on lockfile update).
Cache key: `(host, owner, repo, sha)`.

### Auth & graceful degradation

- GitHub token improves rate limits (5000/hr authed vs 60/hr unauthed) but is optional.
- On rate-limit / network failure: fall back to NVD description regex, not error.
- Document the unauthed scan ceiling clearly: ~60 fix-commit lookups per IP per hour.

### Privacy / boundary

- Outbound fetches are limited to `github.com`, `gitlab.com`, `bitbucket.org` only.
- No scanned source code is ever transmitted — we fetch *their* diff, not push *our* code.
- Honors `--offline`: no network at all, fall through to overrides + package-level.

### Not in V1 (research backlog)

- Reading the security advisory body for "the bug was in `foo.bar`" prose
- LLM-assisted symbol extraction from commit message + diff (interesting but
  non-deterministic — verdicts must be reproducible, see ADR-004 spirit)
- Backporting symbols from later fixes when the same CVE has multiple patches

---

## 12. Cross-Run Cache Invariants

Per-file content-hash caching does **not** compose across a graph. Editing one
file changes the call graph reachability of every transitive consumer. Spec
this before writing the cache.

### What is cached

| Key | Value | TTL | Invalidates on |
|-----|-------|-----|----------------|
| File AST + symbol table | content hash → parsed module | until hash changes | file write |
| Per-file outgoing edges | content hash → CallEdge[] | until hash changes | file write |
| Reverse-dep map | symbol → set of files importing it | derived | any file's import set changes |
| BFS reachability result | (entry-point set hash, lockfile hash, file-graph hash) → VerdictResult[] | until any input changes | any |
| OSV / NVD / GHSA response | (api, cve_id) → record | 24h | TTL or `--rebuild` |
| EPSS score | cve_id → score | 24h | TTL |
| Fix-commit diff | (host, owner, repo, sha) → diff | 30d | TTL or `--rebuild` |
| Lockfile resolution | sha256(lockfile) → ResolvedPackage[] | until sha changes | lockfile write |

### Invariants the cache must enforce

1. **Stable node IDs.** A symbol is identified by `(file path relative to project root, exported name path)`, never by line number. Renaming a file invalidates; reformatting does not.
2. **Reverse-dep tracking.** Editing `a.ts` invalidates `a.ts`'s file entry AND every file whose outgoing edges named `a.ts` as a target. The reverse-dep map is itself part of the cache and is updated incrementally.
3. **Lockfile hash gate.** Any verdict cache entry is keyed on the lockfile hash; a `pnpm install` invalidates everything verdict-shaped. CVE/EPSS network caches survive.
4. **Tool version gate.** Every cache entry is namespaced by `reachble@<version>` and the parser tool versions. A breaking change to the call-graph algorithm must not silently reuse old graphs.
5. **No wall-clock dependency.** Same file content + same lockfile + same CVE data → byte-identical verdict, regardless of when the run happens. Tests assert this.

### Escape hatches

- `--no-cache` — read nothing, write everything (debug aid)
- `--rebuild` — wipe and rewrite (force fresh)
- `--cache-dir <path>` — relocate (CI ephemerality, monorepo isolation)

### Open questions (revisit before V1 implementation)

- Granularity: single SQLite file or one per cache "table"?
- Concurrency: multiple `reachble scan` runs in parallel against the same cache dir — `WAL` mode + advisory file lock?
- Cache size cap: when does the cache need eviction? Current guess: rare, since file-content-keyed entries naturally garbage-collect on `--rebuild`. Defer until we see a real run hit the ceiling.