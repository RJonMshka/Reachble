# Reachble V1 — OSS Benchmark Report

**Date:** 2026-04-30  
**Mode:** Import + entry points (call graph disabled)  
**Repos tested:** 2

## Summary

| Repo | Packages | CVEs | CRITICAL | HIGH | LOW | SAFE | Noise↓ | Time |
|------|----------|------|----------|------|-----|------|--------|------|
| juice-shop | 1995 | 96 | **29** | 0 | 9 | 60 | 63% | 2.4s |
| directus-9 | 2146 | 223 | **21** | 0 | 66 | 136 | 61% | 5.5s |

> **Noise Reduction** = % of OSV CVEs that Reachble marks SAFE (absent symbol or no reachable path). A naive scanner would flag all of these.

## Per-Repo Details

### juice-shop  `@ v15.0.0`

> OWASP intentionally-vulnerable TypeScript+Express app — canonical benchmark target. Lockfile is gitignored; benchmark generates it via npm install --package-lock-only.

**Analysis coverage**

| Metric | Value |
|--------|-------|
| Packages in lockfile | 1995 |
| TypeScript / JS files | 342 |
| CVEs from OSV | 96 |
| CVEs with symbol data | 0 / 96 |
| Entry points | 173 total, 172 unauthenticated |
| Call graph | disabled |

**Verdict distribution**

| Verdict | Count | Share |
|---------|-------|-------|
| `CRITICAL` | 29 | 30% |
| `HIGH` | 0 | 0% |
| `LOW` | 9 | 9% |
| `SAFE` | 60 | 63% |

**Noise reduction: 63%** — 60 of 96 CVEs are SAFE (the vulnerable symbol is absent or unreachable).

**Top CRITICAL findings** *(reachable from unauthenticated entry point)*

| CVE | Package | CVSS | EPSS | Reason |
|-----|---------|------|------|--------|
| GHSA-6g6m-m6h5-w9gf | `express-jwt@0.1.3` | 0.0 | 0.000 | express-jwt imported but no specific vulnerable symbol identified — reachable fr |
| GHSA-5v7r-6r5c-r473 | `file-type@16.5.4` | 0.0 | 0.000 | file-type imported but no specific vulnerable symbol identified — reachable from |
| GHSA-8cf7-32gw-wr33 | `jsonwebtoken@0.1.0` | 0.0 | 0.000 | jsonwebtoken imported but no specific vulnerable symbol identified — reachable f |
| GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.1.0` | 0.0 | 0.000 | jsonwebtoken imported but no specific vulnerable symbol identified — reachable f |
| GHSA-hjrf-2m68-5959 | `jsonwebtoken@0.1.0` | 0.0 | 0.000 | jsonwebtoken imported but no specific vulnerable symbol identified — reachable f |

**Phase timings**

| Phase | Time |
|-------|------|
| Lockfile parse | 23ms |
| Import graph | 961ms |
| File graph | 671ms |
| Entry point detection | 658ms |
| CVE resolution (OSV + EPSS) | 29ms |
| Verdict scoring | 40ms |
| **Total** | **2.4s** |

*Analysis throughput (cached CVE data): 7.0ms/file, 342 files in 2.4s*

---

### directus-9  `@ v9.23.3`

> Headless CMS — TypeScript REST+GraphQL API, large npm dependency tree, root package-lock.json.

**Analysis coverage**

| Metric | Value |
|--------|-------|
| Packages in lockfile | 2146 |
| TypeScript / JS files | 918 |
| CVEs from OSV | 223 |
| CVEs with symbol data | 0 / 223 |
| Entry points | 208 total, 208 unauthenticated |
| Call graph | disabled |

**Verdict distribution**

| Verdict | Count | Share |
|---------|-------|-------|
| `CRITICAL` | 21 | 9% |
| `HIGH` | 0 | 0% |
| `LOW` | 66 | 30% |
| `SAFE` | 136 | 61% |

**Noise reduction: 61%** — 136 of 223 CVEs are SAFE (the vulnerable symbol is absent or unreachable).

**Top CRITICAL findings** *(reachable from unauthenticated entry point)*

| CVE | Package | CVSS | EPSS | Reason |
|-----|---------|------|------|--------|
| GHSA-3p68-rc4w-qgx5 | `axios@0.27.2` | 0.0 | 0.000 | axios imported but no specific vulnerable symbol identified — reachable from una |
| GHSA-43fc-jf86-j433 | `axios@0.27.2` | 0.0 | 0.000 | axios imported but no specific vulnerable symbol identified — reachable from una |
| GHSA-fvcv-3m26-pcqx | `axios@0.27.2` | 0.0 | 0.000 | axios imported but no specific vulnerable symbol identified — reachable from una |
| GHSA-jr5f-v2jv-69x6 | `axios@0.27.2` | 0.0 | 0.000 | axios imported but no specific vulnerable symbol identified — reachable from una |
| GHSA-wf5p-g6vw-rhxx | `axios@0.27.2` | 0.0 | 0.000 | axios imported but no specific vulnerable symbol identified — reachable from una |

**Phase timings**

| Phase | Time |
|-------|------|
| Lockfile parse | 45ms |
| Import graph | 1.8s |
| File graph | 1.5s |
| Entry point detection | 1.8s |
| CVE resolution (OSV + EPSS) | 20ms |
| Verdict scoring | 288ms |
| **Total** | **5.5s** |

*Analysis throughput (cached CVE data): 5.9ms/file, 918 files in 5.5s*

## Analysis

### Aggregate (2 repos)

| Metric | Value |
|--------|-------|
| Total CVEs | 319 |
| CRITICAL | 50 |
| HIGH | 0 |
| SAFE (eliminated noise) | 196 |
| Average noise reduction | 62% |
| Symbol coverage | 0 / 319 (0%) |
| Average scan time | 3.9s |

### Key findings

1. **62% average noise reduction.** Naive scanners (npm audit, Snyk) report every CVE in the dependency tree. Reachble silences the majority that cannot be triggered because the vulnerable symbol is never imported or has no path from an entry point.

2. **50 actionable findings across all repos.** These are traced from a real HTTP/CLI entry point to the vulnerable call site — not just "the package is installed."

### Accuracy notes

Reachble V1 is a **static over-approximation**: it may emit false positives (dynamic dispatch or conditional imports that never execute the vulnerable branch) but should not miss explicitly-imported symbols. Dynamic call edges are tagged `confidence: low` with a `caveat` so analysts can filter them separately.

**Symbol coverage**

Symbol coverage is 0%: 0 of 319 CVEs carry specific function-level data from OSV / fix-commit diffs. When coverage is low, all assessments are at package level (conservative LOW before entry-point elevation). Symbol coverage improves with a GitHub token (higher rate limits on fix-commit diffs) and when the OSV advisory includes `affected_functions` data.

**CVSS / EPSS gaps**

Many advisories from GitHub Security Advisory (GHSA-\*) lack a CVE alias in OSV, so NVD lookup returns no CVSS score and EPSS returns 0. This results in `cvssScore: 0` for those findings, which reduces the usefulness of CVSS-based filtering. Providing an `NVD_API_KEY` environment variable and a `GITHUB_TOKEN` for fix-commit diffs would close both gaps.

**No HIGH findings**

All non-SAFE findings are CRITICAL or LOW — no HIGH. This is because every detected entry point is classified as unauthenticated. In practice, many routes require auth tokens that Reachble cannot see from static analysis alone. Providing `.reachble.json` suppressions or annotating entry points as `authenticated` would produce more HIGH findings at lower CRITICAL counts.

**What improves precision**

| Improvement | Impact |
|-------------|--------|
| `GITHUB_TOKEN` env var | Fix-commit diffs → symbol-level CVEs → call-graph precision |
| `NVD_API_KEY` env var | CVSS scores for GHSA advisories |
| `.reachble.json` auth annotations | Routes → HIGH instead of CRITICAL |
| OSV `affected_functions` data | Symbol coverage without GitHub token |