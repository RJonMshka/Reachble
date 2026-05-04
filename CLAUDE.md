# CLAUDE.md — Reachble

## What this is

**Reachble** auto-generates **VEX** (Vulnerability Exploitability eXchange) for
npm/JS/TS projects, with machine-checkable reachability evidence. SBOM mandates
(US EO 14028, EU CRA) require VEX. Today it's manual triage in spreadsheets;
we make it automatic.

The technical engine: a CVE scorer that answers "can an attacker reach the
vulnerable code from user-controlled input" — not "is this CVE in the tree."

Single package. Deep JS/TS focus. No language abstraction overhead.

## Current focus

> **MVP — lockfile + OSV + import-graph + JSON/VEX out.** Nothing else.
> Update this line when focus moves. If you're touching code outside the
> current focus, stop and ask.

## Source-of-truth map

When you need a fact, look here first — don't re-derive:

| Question | Source |
|---|---|
| Verdict tier semantics | CLAUDE.md table below |
| Hard rules / invariants | CLAUDE.md "Hard rules" |
| Lockfile shape details | GUIDE.md §3 + `src/lockfile/*.ts` Zod schemas |
| CVE API response shapes | `src/cve/schemas.ts` (Zod) — authoritative |
| Symbol extraction strategy | GUIDE.md §4 + §11 |
| Entry-point detection patterns | GUIDE.md §5 |
| Why a thing is the way it is | GUIDE.md §8 (ADRs) |
| What's done / not done | Milestones table in CLAUDE.md below |

## Repo layout

```
packages/core/
  src/
    types.ts          all shared types — start here
    errors.ts         typed error classes
    lockfile/         package-lock, yarn, pnpm parsers
    cve/              OSV + NVD + GHSA + EPSS + symbol extraction, SQLite cache
    analysis/
      import.ts       MVP — @typescript-eslint/parser import graph
      callgraph.ts    V1 — ts-morph full call graph
      entrypoints.ts  V1 — Express/Fastify/Next/CLI entry point detection
      taint.ts        Research — lightweight taint propagation
    verdict.ts        scoring engine — pure functions
    vex.ts            CycloneDX VEX + OpenVEX export (headline output)
    cli.ts            commander CLI
    config.ts         .reachble.json / package.json "reachble" key
  fixtures/           real project snapshots for tests
  docs/adr/           (in /docs/adr at repo root for now)
```

## Key types

```ts
ResolvedPackage   name + version + depth + devOnly + lockfileSource
CveRecord         id + severity + cvssScore + epssScore + affectedSymbols[]
AffectedSymbol    name + type + confidence + source  (the specific fn/class a CVE is about)
CallEdge          callerFile + calleePackage + calleeSymbol + dynamic (bool)
EntryPoint        file + line + kind + framework + authenticated
Evidence          type + description + file + callPath[] + caveat?
VerdictResult     verdict + confidence + reason + evidence[] + epssScore + fixedIn
VexStatement      cveId + product + status + justification + impactStatement
```

## Verdict tiers

| Verdict  | Meaning |
|----------|---------|
| CRITICAL | Reachable from unauthenticated external input (HTTP, CLI, file, env) |
| HIGH     | Reachable from authenticated route or internal service |
| LOW      | Reachable in code, no external input path found |
| SAFE     | No call path to the vulnerable symbol |

EPSS > 0.3 elevates SAFE → LOW. EPSS > 0.5 elevates any verdict one tier.

VEX status mapping: SAFE → `not_affected`; LOW → `affected` w/ `impact_low`;
HIGH/CRITICAL → `affected`. Justifications are derived from evidence, never
hand-written.

## Milestones

| Stage | What | Status |
|-------|------|--------|
| MVP | Lockfile + OSV + import-graph + JSON/VEX out | Building |
| V1  | ts-morph call graph + entry-point detection + fix-commit symbol extraction | Planned |
| Research | Taint propagation, cross-procedural analysis | Speculative |
| Future (out of scope for now) | SaaS, VS Code, GitHub App, dashboard | Not in plan |

## Tech

| Concern | Tool | Why |
|---------|------|-----|
| MVP analysis | `@typescript-eslint/parser` | Fast, no tsconfig needed |
| V1 call graph | `ts-morph` | Accurate type resolution |
| Lockfile parsing | `@pnpm/lockfile-file`, `@yarnpkg/lockfile` | Official parsers |
| CVE data | OSV.dev + NVD + GHSA | OSV has `affected_functions` |
| Symbol extraction | OSV → fix-commit diff → NVD desc parse → manual override | See GUIDE §11 |
| Local cache | `better-sqlite3` | Fast, sync, no daemon |
| Validation | `zod` | All external data validated at boundary |
| CLI | `commander` | Lightweight, typed |
| Build | `tsup` | Dual CJS/ESM, .d.ts |
| Tests | `vitest` | Native ESM, fast |

## Hard rules

- `strict: true`, `exactOptionalPropertyTypes: true`, `noUncheckedIndexedAccess: true`
- No `eval`, no `new Function`, no `child_process` in core
- Zod schema on every external API response before it touches any logic
- File access scoped to project dir + `~/.cache/reachble/` only
- No telemetry, no tracking
- `devOnly: true` packages: max verdict is LOW, never CRITICAL/HIGH
- Dynamic call edges (`dynamic: true`): always produce `confidence: low`
- Every `Evidence` carries a `caveat` field if confidence is not `high` — be honest in output
- Verdict engine is **pure**: same inputs → byte-identical output (deterministic for CI gating)
- VEX output is the headline; JSON/SARIF are secondary views of the same data
- Tests required for every new module — no exceptions

## Non-goals (be ruthless)

- Multi-language (Python, Go, etc.) — see ADR-005
- Bundled-output analysis (webpack, esbuild) — analyze pre-bundle source only
- IDE/editor plugins, GitHub App, hosted SaaS — not in current scope
- Full inter-procedural taint engine — research only, never blocks V1
- Hapi/Koa entry-point detection — Express + Fastify + Next covers >90%
- Watch mode, dashboards, anything not on the MVP/V1 critical path

## Commands

```bash
pnpm install           # install
pnpm test              # vitest
pnpm test:watch        # vitest --watch
pnpm build             # tsup
pnpm lint              # eslint + prettier check
pnpm lint:fix          # eslint + prettier fix
reachble scan          # scan cwd → JSON + VEX
reachble scan --path . --format vex
reachble scan --format sarif --fail-on critical
```

## When adding a module

1. Types first → `src/types.ts`
2. Zod schema if touching external data → `src/<area>/schemas.ts`
3. Tests with fixtures before implementation
4. Export from `src/index.ts`
5. Update GUIDE.md §10 changelog
6. If it changes a hard rule or adds a non-goal → update CLAUDE.md
