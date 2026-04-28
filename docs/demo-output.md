# Reachble Demo Output

Thesis validation: `reachble scan` on the `fixtures/demo-express` app.

The demo app is a minimal Express server that imports **`template`** from lodash
(`src/routes/render.ts:8`). It does **not** import `trim`, `trimStart`, or
`trimEnd`. Lodash@4.17.18 has two CVEs that cover these function sets.

---

## App source

```ts
// src/routes/render.ts
import { template } from 'lodash'          // ← reachable CVE-2021-23337

const compiled = template('Hello, <%= user %>!')
```

```ts
// src/server.ts
import express from 'express'
import { renderPage } from './routes/render.js'

app.get('/render', renderPage)             // ← unauthenticated HTTP route (V1 will trace to CRITICAL)
```

---

## Scan output (MVP — import-level analysis)

```
$ reachble scan --path fixtures/demo-express --format table

Package   Version   CVE              Verdict   CVSS   Reason
──────────────────────────────────────────────────────────────────────────
lodash    4.17.18   CVE-2020-28500   SAFE      5.0    Vulnerable symbol(s) not imported from lodash
lodash    4.17.18   CVE-2021-23337   LOW       7.5    Vulnerable symbol(s) imported from lodash

2 packages · 2 CVEs · 0 CRITICAL · 0 HIGH · 1 LOW · 1 SAFE
VEX written to fixtures/demo-express/reachble-vex.cdx.json
```

---

## VEX output (CycloneDX excerpt)

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2020-28500",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "Vulnerable symbol(s) not imported from lodash — trim/trimStart/trimEnd do not appear in any import statement"
      }
    },
    {
      "id": "CVE-2021-23337",
      "analysis": {
        "state": "exploitable",
        "detail": "Vulnerable symbol(s) imported from lodash at src/routes/render.ts:8 — import-level analysis only; V1 call graph will refine reachability"
      }
    }
  ]
}
```

---

## Thesis validation

| Claim | Result |
|---|---|
| Import-level analysis cuts CVE noise | ✓ CVE-2020-28500 eliminated (SAFE) without manual review |
| Reachable CVEs correctly flagged | ✓ CVE-2021-23337 flagged (LOW) because `template` is imported |
| VEX `not_affected` is machine-checkable | ✓ CycloneDX justification carries the import evidence |
| Output is byte-stable across runs | ✓ Determinism test passes |
| `--fail-on high` would not block CI | ✓ No HIGH/CRITICAL results at import level |

---

## V1 upgrade path

Once V1 call-graph analysis lands (ts-morph + entry-point detection):

- The `/render` route is unauthenticated HTTP → `template` traces from `app.get` → `renderPage` → `compiled`
- CVE-2021-23337 verdict upgrades: **LOW → CRITICAL**
- VEX state updates: `exploitable` with full `callPath` evidence

The import-level LOW verdict is a conservative lower bound; V1 refines it upward
when a real attack path exists.
