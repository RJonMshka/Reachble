# Reachble — Architecture Diagrams

Four diagrams covering the two static analysis approaches, fix-commit diff symbol extraction, and the CVE cache layer.

---

## 1. Import-Level Analysis

Operates on file text only — no type checker, no `tsconfig.json` needed.
Parser: `@typescript-eslint/parser` (AST only, ~10–40 ms per file).

```mermaid
flowchart TD
    A([Project directory]) --> B["discoverFiles<br/>walk dir · skip node_modules<br/>respect .gitignore"]
    B --> C{For each JS/TS file}
    C --> D["Read file · parse AST<br/>@typescript-eslint/parser<br/>no tsconfig needed"]
    D --> E{Top-level AST node type}

    E -->|ImportDeclaration| F["named / default / namespace import"]
    E -->|Export re-declaration| G["re-export / re-export-all"]
    E -->|Variable or Call expression| H["require — static or dynamic"]

    F --> I["ImportRecord<br/>package · symbols · kind · line.  "]
    G --> I
    H --> I

    I --> J[("ImportGraph<br/>Map: file → ImportRecord list.  ")]

    J --> K["matchImports — check CVE package"]
    K --> L{Symbol resolution}

    L -->|named import with known symbols| M["Exact symbol match<br/>confidence: high"]
    L -->|default / namespace / dynamic require| N["Conservative — all symbols assumed present<br/>confidence: low"]
    L -->|package not imported at all| O["No match<br/>SAFE verdict eligible"]
```

**What gets flagged conservative (lower confidence):**

| Import form | Example | Why conservative |
|---|---|---|
| Default import | `import _ from 'lodash'` | Can't tell which methods are used |
| Namespace import | `import * as pkg from 'x'` | All exports potentially used |
| Dynamic require | `require(variable)` | Package unknown at parse time |
| `export *` | `export * from 'x'` | All symbols re-exported |

---

## 2. Call Graph Analysis

Uses ts-morph (TypeScript compiler API) — requires `tsconfig.json`, resolves types precisely.
Cost: 500–2000 ms per file on first load (full type checker initialization).

```mermaid
flowchart TD
    A([Project directory]) --> B["findTsConfig<br/>look for tsconfig.json / jsconfig.json"]
    B -->|not found| C["return null<br/>CLI falls back to import-level analysis"]
    B -->|found| D["new ts-morph Project<br/>tsConfigFilePath — full type resolution"]

    D --> E["getSourceFiles — exclude node_modules"]
    E --> F{For each source file}
    F --> G["forEachDescendant — visit every AST node"]
    G --> H{isCallExpression?}
    H -->|no| G
    H -->|yes| I{Expression shape}

    I -->|Identifier — direct call| J["resolveDecl<br/>getSymbol · getAliasedSymbol<br/>getValueDeclaration"]
    I -->|PropertyAccess — ns.method| K["resolveDecl on property<br/>OR resolveMemberDecl<br/>on namespace object"]

    J --> L{Declaration file in node_modules?}
    K --> L
    L -->|no — local code| G
    L -->|yes — external package| M["packageFromPath<br/>extract package name<br/>strip @types/ prefix"]
    M --> N["getEnclosingFunction<br/>walk ancestors: fn / method / arrow / module"]
    N --> O["CallEdge<br/>callerFile · callerFunction · line<br/>calleePackage · calleeSymbol · dynamic=false"]
    O --> P[("CallGraph<br/>Map: file → CallEdge list")]
```

---

## 3. Import vs Call Graph — Approach Comparison

```mermaid
flowchart LR
    subgraph Import["Import-Level — MVP"]
        direction TB
        I1["Parser: @typescript-eslint/parser<br/>AST only · no tsconfig needed"]
        I2["Output: which packages imported<br/>and which named symbols"]
        I3["Speed: ~1s per 300 files"]
        I4["Accuracy: conservative<br/>default/namespace flags whole package"]
        I1 --> I2 --> I3 --> I4
    end

    subgraph CG["Call Graph — V1"]
        direction TB
        C1["Parser: ts-morph<br/>full type checker · needs tsconfig.json"]
        C2["Output: exact call site<br/>caller function · line number"]
        C3["Speed: ~2s per file on first load<br/>cached in ts-morph program after"]
        C4["Accuracy: precise<br/>resolves re-exports and aliases"]
        C1 --> C2 --> C3 --> C4
    end

    subgraph Verdict["Verdict impact"]
        direction TB
        V1["Import only<br/>confidence: medium<br/>no call path in evidence"]
        V2["Call graph<br/>confidence: high<br/>callerFile · callerFunction · line"]
    end

    Import --> Verdict
    CG --> Verdict

    style Import fill:#1e3a5f,color:#cce
    style CG fill:#3a1e1e,color:#fcc
    style Verdict fill:#1e3a1e,color:#cfc
```

| | Import-level | Call graph |
|---|---|---|
| Requires `tsconfig.json` | No | Yes |
| Startup cost | ~50 ms | ~1–3 s (type checker init) |
| Per-file cost | ~10–40 ms | ~500–2000 ms |
| False positive rate | Higher (conservative imports) | Lower (exact resolution) |
| Identifies caller function | No | Yes |
| Identifies call-site line | Import line only | Exact call line |
| Follows re-exports / aliases | No | Yes |
| Dynamic call edges | Detected, flagged dynamic | Static calls are dynamic=false |

---

## 4. Fix-Commit Diff Symbol Extraction

Runs when a CVE has no `affected_functions` in its OSV record.
Hits the **original OSS repo** via GitHub API — no fork needed.

```mermaid
flowchart TD
    A([CVE record from OSV]) --> B{Has affected_functions in OSV?}
    B -->|yes — high confidence| Z(["Use OSV symbols directly<br/>source: osv · confidence: high"])
    B -->|no — try fix diff| C["Filter references where type = FIX"]

    C --> D{Any GitHub commit URLs?}
    D -->|no| E(["No symbols found<br/>fall back to NVD description parse"])
    D -->|yes| F["parseGithubCommitUrl<br/>extract owner / repo / sha<br/>handles /commit/sha and /pull/N/commits/sha"]

    F --> G{Valid GitHub URL?}
    G -->|no — not GitHub or malformed| H["skip URL · try next"]
    G -->|yes| I["fetchCommitDiff<br/>GET github.com API · repos/owner/repo/commits/sha<br/>Accept: application/vnd.github.diff<br/>Authorization: Bearer token — optional"]

    I --> J{HTTP 200?}
    J -->|no / network error| H
    J -->|yes| K["parseSymbolsFromDiff<br/>unified diff text"]

    K --> L["Split diff into lines"]
    L --> M{Line type}

    M -->|diff header line| N{JS/TS file extension?}
    N -->|no| M
    N -->|yes| O["set inJsFile = true · continue"]
    O --> M

    M -->|hunk header — starts with @@| P["Extract fn name from<br/>hunk context suffix<br/>format: -a,b +c,d funcName"]
    M -->|changed line — starts with + or -| Q["Match DEF_PATTERNS<br/>function / class / const arrow"]
    M -->|end of diff| R

    P --> S["emit AffectedSymbol<br/>name · type · confidence: medium · source: fix-diff"]
    Q --> S
    S --> T{Already seen?}
    T -->|yes — skip| M
    T -->|no — add to set| M

    R(["AffectedSymbol list<br/>confidence: medium"])
```

**Rate limits:**

| Mode | GitHub API limit | p-limit concurrency |
|---|---|---|
| No token | 60 req/hr | 2 concurrent |
| With `GITHUB_TOKEN` | 5,000 req/hr | 5 concurrent |

---

## 5. CVE Cache Layer

SQLite via `better-sqlite3` (synchronous, no daemon). Location: `~/.cache/reachble/cve-cache.db`.

```mermaid
flowchart TD
    A([resolveCves called]) --> B["new CveCache<br/>open SQLite · WAL mode<br/>DELETE expired rows on startup"]

    B --> C["Step 1 — OSV batch query<br/>one check per package"]
    C --> D{"cache.get<br/>osv:npm:pkg@ver"}
    D -->|hit| E["use cached OsvVulnerability list"]
    D -->|miss + offline flag| F(["throw CveResolverError"])
    D -->|miss + online| G["queryOsvBatch<br/>api.osv.dev/v1/querybatch"]
    G --> H["cache.set osv:npm:pkg@ver<br/>TTL: 24 hr"]
    H --> E

    E --> I["Step 2 — CVSS score<br/>per unique CVE ID"]
    I --> J{OSV has severity field?}
    J -->|yes| K["use OSV score directly"]
    J -->|no| L{"cache.get<br/>nvd:CVE-xxx"}
    L -->|hit — absent sentinel| M["skip NVD call — advisory has no NVD entry"]
    L -->|hit — score object| K
    L -->|miss| N["fetchNvdCvss<br/>services.nvd.nist.gov<br/>p-limit 1 anon · 5 with API key"]
    N -->|found| O["cache.set nvd:CVE-xxx score<br/>TTL: 24 hr"]
    N -->|not found| P["cache.set nvd:CVE-xxx absent sentinel<br/>TTL: 24 hr — prevents repeat lookups"]
    O --> K
    P --> M

    K --> Q["Step 3 — EPSS scores"]
    M --> Q
    Q --> R{"cache.get<br/>epss:CVE-xxx"}
    R -->|hit — number| S["use cached EPSS score"]
    R -->|miss| T["fetchEpssScores<br/>api.first.org/data/v1/epss<br/>batch all uncached IDs in one request"]
    T --> U["cache.set epss:CVE-xxx score<br/>store 0 for IDs not in response<br/>TTL: 24 hr"]
    U --> S

    S --> V["Step 4 — Fix-diff symbols<br/>for CVEs with no OSV affected_functions"]
    V --> W{"cache.get<br/>fix-diff-symbols:CVE-xxx"}
    W -->|hit — array| X["use cached AffectedSymbol list"]
    W -->|miss| Y["resolveFixDiffSymbols<br/>GitHub API diff fetch — see diagram 4"]
    Y --> Z["cache.set fix-diff-symbols:CVE-xxx<br/>TTL: 24 hr"]
    Z --> X

    X --> AA["Step 5 — Build CveRecord list<br/>per package · assemble all resolved data"]
    AA --> AB(["Map: pkg@ver to CveRecord list"])

    style B fill:#2a2a1e,color:#ffd
    style AB fill:#1e3a1e,color:#cfc
```

**Cache key schema:**

| Prefix | Key example | What is stored | TTL |
|---|---|---|---|
| `osv:npm:` | `osv:npm:lodash@4.17.20` | OSV vulnerability list | 24 hr |
| `nvd:` | `nvd:CVE-2021-23337` | CVSS score object or `__absent__` sentinel | 24 hr |
| `epss:` | `epss:CVE-2021-23337` | Number 0–1 exploit probability | 24 hr |
| `fix-diff-symbols:` | `fix-diff-symbols:CVE-2021-23337` | AffectedSymbol list | 24 hr |

The `__absent__` sentinel for NVD prevents re-fetching GHSA-only advisories that NVD will never have a record for — a common case with GitHub Security Advisories.
