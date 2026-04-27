# /lockfile-parser

You are working on the **Reachble lockfile parser** (`packages/core/src/lockfile/`).
Load this skill when adding, fixing, or testing any lockfile parser code.

---

## What this module does

Reads a project's lockfile (npm/yarn/pnpm) and returns a deterministic
`ResolvedPackage[]` — the canonical list of all installed packages with
depth, devOnly flag, and direct-depender names.

This is M3 in PLAN.md. The output feeds the CVE resolver (M4) and verdict engine (M6).

---

## File map

```
src/lockfile/
  schemas.ts      Zod schemas for each lockfile format (source of truth for shapes)
  npm.ts          package-lock.json v2/v3 parser
  yarn.ts         yarn.lock v1 (classic) + berry (v2+) parser
  pnpm.ts         pnpm-lock.yaml v6/v9 parser
  detect.ts       auto-detects lockfile, reads files, calls the right parser
  index.ts        re-exports: parseNpmLock, parseYarnLock, parsePnpmLock, detectAndParse

fixtures/
  npm-v2/package-lock.json    npm lockfileVersion:2 fixture (express + typescript)
  npm-v3/package-lock.json    npm lockfileVersion:3 fixture
  yarn-v1/yarn.lock           yarn classic fixture
  yarn-v1/package.json        root package.json (needed for devOnly)
  pnpm-v6/pnpm-lock.yaml      pnpm v6 fixture
```

---

## Parser contracts

Every parser must return `ResolvedPackage[]` satisfying these invariants:

| Property | Rule |
|----------|------|
| `name` | npm package name, including scope (`@scope/pkg`) |
| `version` | exact resolved version string |
| `depth` | minimum hops from root (direct deps = 1) |
| `dependents` | names of packages that **directly** depend on this one; `'.'` means the root project |
| `devOnly` | `true` only if package is **exclusively** reachable from devDependencies |
| `lockfileSource` | `'npm'` \| `'yarn'` \| `'pnpm'` |

**Determinism**: output array must be sorted by `${name}@${version}` ascending —
same lockfile → byte-identical output, always.

**Root package** is never included in the output (it's not a dependency).

---

## Format-specific notes

### npm `package-lock.json` v2/v3

- `lockfileVersion: 2` has both `packages` and `dependencies` (legacy compat). **Use only `packages`.**
- `lockfileVersion: 3` has only `packages`.
- Root entry key is `""` (empty string) — skip it.
- Package key format: `node_modules/foo` (depth 1), `node_modules/foo/node_modules/bar` (depth 2).
- Scoped: `node_modules/@scope/foo`.
- Depth = count of `node_modules/` occurrences in the key.
- `entry.link === true` → workspace symlink → **skip** (not an external dep).
- `entry.dev === true` → exclusively dev dep (npm marks this automatically).
- `entry.devOptional === true` → dev optional dep → treat as devOnly.

### yarn.lock v1 (classic)

- Detected by first line `# yarn lockfile v1`.
- Parsed by `@yarnpkg/lockfile`. Returns `{type, object}`.
- Object keys are specifiers: `"express@^4.18.2"` or comma-separated `"pkg@^1, pkg@~1"`.
- Key parsing: for `@scope/pkg@spec` the first `@` is the scope, second is the specifier separator.
- Entry `dependencies` values are **resolved versions** (not specifiers).
- devOnly requires cross-referencing root `package.json` devDependencies.
- Depth requires BFS from root package.json deps (yarn hoists, but BFS gives logical depth).

### yarn.lock v2+ (berry)

- Detected by presence of `__metadata:` key in the YAML.
- Entry keys format: `"express@npm:^4.18.2"` (includes protocol prefix).
- Best-effort parse via `js-yaml`. Same BFS logic for depth/devOnly.
- Throw `LockfileParseError` with helpful message if js-yaml cannot parse.

### pnpm-lock.yaml v6/v9

- `lockfileVersion: '6.0'` — package keys have leading `/`: `/express@4.18.2`
- `lockfileVersion: '9.0'` — package keys have no leading `/`: `express@4.18.2`
- Normalize: always strip leading `/` from keys.
- devOnly: use `dev: true` on package entries if present; otherwise BFS from `importers['.'].devDependencies`.
- `importers` section lists workspace packages. For non-monorepo, only `.` importer exists.
- Depth: BFS from `importers['.'].dependencies` (prod) and `importers['.'].devDependencies` (dev).

---

## devOnly BFS algorithm (yarn/pnpm without explicit flags)

```
prodReachable = BFS from root.dependencies
devReachable  = BFS from root.devDependencies
devOnly       = devReachable AND NOT prodReachable
```

Use resolved `name@version` as BFS nodes. Build adjacency list from lockfile entries' `dependencies`.

---

## Zod schema usage

All external data (lockfile content) is validated at parse time. `safeParse()` is used;
on failure, throw `LockfileParseError(filename, error.message)`.

Type exports from `schemas.ts`:
- `RootPackageJson` — shape for cross-referencing yarn/pnpm devDeps
- `NpmLockfileSchema`, `YarnV1LockfileSchema`, `PnpmLockfileSchema`

---

## Common tasks

**Add support for a new lockfile version:**
1. Update the relevant schema in `schemas.ts` to accept the new `lockfileVersion` value.
2. Add a new fixture in `fixtures/` for that version.
3. Add a test case in the relevant `*.test.ts`.
4. Adjust the parser if the shape changed (see format notes above).

**Debug devOnly misclassification:**
- For npm: check `entry.dev` in the raw lockfile.
- For yarn/pnpm: trace the BFS — is the package in both prod and dev subtrees?

**Debug depth miscalculation:**
- npm: count `node_modules/` substrings in the key path.
- yarn/pnpm: check BFS level from root deps.

**Add a test:**
1. Create or update a fixture file under `fixtures/`.
2. Add a `describe` block in the corresponding `*.test.ts`.
3. Assert the exact `ResolvedPackage` shape (name, version, depth, devOnly, dependents, lockfileSource).

---

## Hard rules (from CLAUDE.md, lockfile-specific)

- `devOnly: true` packages: max verdict is LOW, never CRITICAL/HIGH. Parser correctness here is security-relevant.
- Zod schema on every external file before touching logic — no raw `JSON.parse` without schema validation.
- No `child_process` in parsers.
- Tests required — no exceptions.
- Determinism is tested explicitly: run the same fixture twice and `deepStrictEqual` the outputs.
