import { load as yamlLoad } from 'js-yaml'
import { LockfileParseError } from '../errors.js'
import type { ResolvedPackage } from '../types.js'
import type { PnpmDepEntry } from './schemas.js'
import { PnpmLockfileSchema } from './schemas.js'

/** Extract the resolved version from a pnpm dep entry (v5 string or v6/v9 object). */
function depVer(entry: PnpmDepEntry): string {
  return typeof entry === 'string' ? entry : entry.version
}

/**
 * Normalize a pnpm package key to "name@version" form.
 *
 * v5:   "/express/4.18.2"          → "express@4.18.2"
 *        "/@scope/pkg/1.0.0"       → "@scope/pkg@1.0.0"
 * v6:   "/express@4.18.2"          → "express@4.18.2"
 *        "/@scope/pkg@1.0.0"       → "@scope/pkg@1.0.0"
 * v9:   "express@4.18.2"           → "express@4.18.2"  (no change)
 */
function normKey(key: string): string {
  const k = key.startsWith('/') ? key.slice(1) : key

  if (k.startsWith('@')) {
    // Scoped package: v6/v9 has "@" after the name ("@scope/name@ver");
    // v5 has only the initial "@" ("@scope/name/ver").
    const secondAt = k.indexOf('@', 1)
    if (secondAt > 0) return k // already "name@version"
    // v5: replace last "/" with "@"
    const lastSlash = k.lastIndexOf('/')
    return lastSlash > 0 ? k.slice(0, lastSlash) + '@' + k.slice(lastSlash + 1) : k
  }

  if (k.includes('@')) return k // v6/v9: "name@version"

  // v5 non-scoped: "name/version"
  const lastSlash = k.lastIndexOf('/')
  return lastSlash > 0 ? k.slice(0, lastSlash) + '@' + k.slice(lastSlash + 1) : k
}

// Extract name from "name@version" or "@scope/name@version"
function nameFromNv(nv: string): string {
  if (nv.startsWith('@')) {
    const second = nv.indexOf('@', 1)
    return nv.slice(0, second)
  }
  return nv.slice(0, nv.indexOf('@'))
}

// ── BFS helpers ──────────────────────────────────────────────────────────────

// adjacency: nv → Set<direct-depender-nv> but we store depender *names* for the dependents field
type AdjMap = Map<string, Set<string>>

function buildAdjMap(packages: Record<string, { deps: Record<string, string> }>): AdjMap {
  const m: AdjMap = new Map()
  for (const nv of Object.keys(packages)) {
    if (!m.has(nv)) m.set(nv, new Set())
  }
  for (const [nv, { deps }] of Object.entries(packages)) {
    const name = nameFromNv(nv)
    for (const [depName, depVersion] of Object.entries(deps)) {
      const depNv = `${depName}@${depVersion}`
      const adjSet = m.get(depNv) ?? new Set<string>()
      adjSet.add(name)
      m.set(depNv, adjSet)
    }
  }
  return m
}

function bfsDepths(
  rootNvs: string[],
  packages: Record<string, { deps: Record<string, string> }>,
): Map<string, number> {
  const dist = new Map<string, number>()
  const queue: Array<{ nv: string; depth: number }> = []
  for (const nv of rootNvs) {
    if (!dist.has(nv)) {
      dist.set(nv, 1)
      queue.push({ nv, depth: 1 })
    }
  }
  while (queue.length > 0) {
    const item = queue.shift()
    if (item === undefined) break
    const { nv, depth } = item
    const pkg = packages[nv]
    if (pkg === undefined) continue
    for (const [depName, depVersion] of Object.entries(pkg.deps)) {
      const depNv = `${depName}@${depVersion}`
      if (!dist.has(depNv)) {
        dist.set(depNv, depth + 1)
        queue.push({ nv: depNv, depth: depth + 1 })
      }
    }
  }
  return dist
}

function bfsReachable(
  rootNvs: string[],
  packages: Record<string, { deps: Record<string, string> }>,
): Set<string> {
  const visited = new Set<string>()
  const queue: string[] = [...rootNvs]
  for (const nv of rootNvs) visited.add(nv)
  while (queue.length > 0) {
    const nv = queue.shift()
    if (nv === undefined) break
    const pkg = packages[nv]
    if (pkg === undefined) continue
    for (const [depName, depVersion] of Object.entries(pkg.deps)) {
      const depNv = `${depName}@${depVersion}`
      if (!visited.has(depNv) && packages[depNv] !== undefined) {
        visited.add(depNv)
        queue.push(depNv)
      }
    }
  }
  return visited
}

// ── Public API ───────────────────────────────────────────────────────────────

export function parsePnpmLock(content: string): ResolvedPackage[] {
  let raw: unknown
  try {
    raw = yamlLoad(content)
  } catch (err) {
    throw new LockfileParseError('pnpm-lock.yaml', `YAML parse failed: ${String(err)}`, {
      cause: err,
    })
  }

  const parsed = PnpmLockfileSchema.safeParse(raw)
  if (!parsed.success) {
    throw new LockfileParseError('pnpm-lock.yaml', parsed.error.message)
  }

  const { importers = {}, packages: rawPackages = {} } = parsed.data

  // Normalize all package keys (strip leading "/")
  const packages: Record<string, { deps: Record<string, string>; devExplicit?: boolean }> = {}
  for (const [key, entry] of Object.entries(rawPackages)) {
    const nv = normKey(key)
    packages[nv] = {
      deps: { ...entry.dependencies, ...entry.optionalDependencies },
      ...(entry.dev !== undefined ? { devExplicit: entry.dev } : {}),
    }
  }

  // Root importer is always "."
  const rootImporter = importers['.'] ?? {}
  const prodDeps = rootImporter.dependencies ?? {}
  const devDeps = rootImporter.devDependencies ?? {}

  const prodRootNvs = Object.entries(prodDeps).map(([name, e]) => `${name}@${depVer(e)}`)
  const devRootNvs = Object.entries(devDeps).map(([name, e]) => `${name}@${depVer(e)}`)
  const prodRootNames = Object.keys(prodDeps)
  const devRootNames = Object.keys(devDeps)

  // Check if explicit dev flags are present on all packages
  const hasExplicitDevFlags = Object.values(packages).every((p) => p.devExplicit !== undefined)

  let prodReachable: Set<string>
  let devReachable: Set<string>
  if (hasExplicitDevFlags) {
    // Use the explicit flags — no BFS needed
    prodReachable = new Set(
      Object.keys(packages).filter((nv) => packages[nv]?.devExplicit !== true),
    )
    devReachable = new Set(Object.keys(packages).filter((nv) => packages[nv]?.devExplicit === true))
  } else {
    prodReachable = bfsReachable(prodRootNvs, packages)
    devReachable = bfsReachable(devRootNvs, packages)
  }

  const depthMap = bfsDepths([...prodRootNvs, ...devRootNvs], packages)
  const adjMap = buildAdjMap(packages)

  const result: ResolvedPackage[] = []

  for (const nv of Object.keys(packages)) {
    const name = nameFromNv(nv)
    const version = nv.slice(nv.lastIndexOf('@') + 1)

    const dependents = new Set<string>()
    if (prodRootNames.includes(name) || devRootNames.includes(name)) dependents.add('.')
    for (const dependerName of adjMap.get(nv) ?? []) {
      dependents.add(dependerName)
    }

    const devOnly = hasExplicitDevFlags
      ? packages[nv]?.devExplicit === true
      : !prodReachable.has(nv) && devReachable.has(nv)

    result.push({
      name,
      version,
      depth: depthMap.get(nv) ?? 1,
      dependents: [...dependents].sort(),
      devOnly,
      lockfileSource: 'pnpm',
    })
  }

  return result.sort((a, b) => {
    const ka = `${a.name}@${a.version}`
    const kb = `${b.name}@${b.version}`
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
}
