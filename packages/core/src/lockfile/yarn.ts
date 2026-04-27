import { parse as parseYarnV1 } from '@yarnpkg/lockfile'
import { load as yamlLoad } from 'js-yaml'
import { LockfileParseError } from '../errors.js'
import type { ResolvedPackage } from '../types.js'
import type { RootPackageJson } from './schemas.js'
import { YarnV1LockfileSchema } from './schemas.js'

// ── Key parsing ──────────────────────────────────────────────────────────────

// Yarn v1: "express@^4.18.2" or "@scope/pkg@^1.0.0"
function nameFromYarnKey(key: string): string {
  if (key.startsWith('@')) {
    const second = key.indexOf('@', 1)
    return key.slice(0, second)
  }
  return key.slice(0, key.indexOf('@'))
}

// ── Shared BFS helpers ───────────────────────────────────────────────────────

type Entries = Map<string, { version: string; deps: Record<string, string> }>

// Returns a map: nv → Set<depender-names> (the packages that depend on nv)
function buildDependentsMap(entries: Entries): Map<string, Set<string>> {
  const m = new Map<string, Set<string>>()
  for (const [nv] of entries) {
    if (!m.has(nv)) m.set(nv, new Set())
  }
  for (const [nv, { deps }] of entries) {
    const name = nv.slice(0, nv.lastIndexOf('@'))
    for (const [depName, depVersion] of Object.entries(deps)) {
      const depNv = `${depName}@${depVersion}`
      if (!m.has(depNv)) m.set(depNv, new Set())
      m.get(depNv)!.add(name)
    }
  }
  return m
}

// BFS from named roots → min depth per nv
function bfsDepths(roots: string[], entries: Entries): Map<string, number> {
  const dist = new Map<string, number>()
  const queue: Array<{ nv: string; depth: number }> = []
  for (const name of roots) {
    for (const [nv] of entries) {
      if (nv.slice(0, nv.lastIndexOf('@')) === name && !dist.has(nv)) {
        dist.set(nv, 1)
        queue.push({ nv, depth: 1 })
      }
    }
  }
  while (queue.length > 0) {
    const { nv, depth } = queue.shift()!
    const entry = entries.get(nv)
    if (entry === undefined) continue
    for (const [depName, depVersion] of Object.entries(entry.deps)) {
      const depNv = `${depName}@${depVersion}`
      if (!dist.has(depNv)) {
        dist.set(depNv, depth + 1)
        queue.push({ nv: depNv, depth: depth + 1 })
      }
    }
  }
  return dist
}

// BFS from named roots → set of reachable nv strings
function bfsReachable(roots: string[], entries: Entries): Set<string> {
  const visited = new Set<string>()
  const queue: string[] = []
  for (const name of roots) {
    for (const [nv] of entries) {
      if (nv.slice(0, nv.lastIndexOf('@')) === name && !visited.has(nv)) {
        visited.add(nv)
        queue.push(nv)
      }
    }
  }
  while (queue.length > 0) {
    const nv = queue.shift()!
    const entry = entries.get(nv)
    if (entry === undefined) continue
    for (const [depName, depVersion] of Object.entries(entry.deps)) {
      const depNv = `${depName}@${depVersion}`
      if (!visited.has(depNv) && entries.has(depNv)) {
        visited.add(depNv)
        queue.push(depNv)
      }
    }
  }
  return visited
}

function buildResult(entries: Entries, packageJson: RootPackageJson): ResolvedPackage[] {
  const prodRoots = Object.keys(packageJson.dependencies ?? {})
  const devRoots = Object.keys(packageJson.devDependencies ?? {})

  const prodReachable = bfsReachable(prodRoots, entries)
  const devReachable = bfsReachable(devRoots, entries)
  const depthMap = bfsDepths([...prodRoots, ...devRoots], entries)
  const dependentsMap = buildDependentsMap(entries)

  const result: ResolvedPackage[] = []

  for (const [nv, { version }] of entries) {
    const name = nv.slice(0, nv.lastIndexOf('@'))
    const dependents = new Set<string>()
    if (prodRoots.includes(name) || devRoots.includes(name)) dependents.add('.')
    for (const dependerName of (dependentsMap.get(nv) ?? [])) {
      dependents.add(dependerName)
    }
    result.push({
      name,
      version,
      depth: depthMap.get(nv) ?? 1,
      dependents: [...dependents].sort(),
      devOnly: !prodReachable.has(nv) && devReachable.has(nv),
      lockfileSource: 'yarn',
    })
  }

  return result.sort((a, b) => {
    const ka = `${a.name}@${a.version}`
    const kb = `${b.name}@${b.version}`
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
}

// ── Classic (v1) ─────────────────────────────────────────────────────────────

function parseYarnClassic(content: string, packageJson: RootPackageJson): ResolvedPackage[] {
  let raw: unknown
  try {
    raw = parseYarnV1(content)
  } catch (err) {
    throw new LockfileParseError('yarn.lock', `parse failed: ${String(err)}`, { cause: err })
  }
  const parsed = YarnV1LockfileSchema.safeParse(raw)
  if (!parsed.success) {
    throw new LockfileParseError('yarn.lock', parsed.error.message)
  }

  const entries: Entries = new Map()
  for (const [rawKey, entry] of Object.entries(parsed.data.object)) {
    for (const key of rawKey.split(', ')) {
      const name = nameFromYarnKey(key.trim())
      const nv = `${name}@${entry.version}`
      if (!entries.has(nv)) {
        entries.set(nv, {
          version: entry.version,
          deps: { ...entry.dependencies, ...entry.optionalDependencies },
        })
      }
    }
  }

  return buildResult(entries, packageJson)
}

// ── Berry (v2+) ──────────────────────────────────────────────────────────────

function parseYarnBerry(content: string, packageJson: RootPackageJson): ResolvedPackage[] {
  let obj: Record<string, unknown>
  try {
    const parsed = yamlLoad(content)
    if (typeof parsed !== 'object' || parsed === null) throw new Error('unexpected shape')
    obj = parsed as Record<string, unknown>
  } catch (err) {
    throw new LockfileParseError('yarn.lock', `berry parse failed: ${String(err)}`, { cause: err })
  }

  const entries: Entries = new Map()
  for (const [rawKey, value] of Object.entries(obj)) {
    if (rawKey === '__metadata') continue
    if (typeof value !== 'object' || value === null) continue
    const v = value as Record<string, unknown>
    if (typeof v['version'] !== 'string') continue

    // Keys: "pkg@npm:^1.0, pkg@npm:~1.0" — strip protocol prefix
    for (const key of rawKey.split(', ')) {
      const trimmed = key.trim().replace(/@(?:npm|workspace|patch|portal|link|exec|file):/g, '@')
      const name = nameFromYarnKey(trimmed)
      const version = v['version'] as string
      const nv = `${name}@${version}`
      if (!entries.has(nv)) {
        const rawDeps = (v['dependencies'] ?? {}) as Record<string, string>
        const deps: Record<string, string> = {}
        for (const [dn, dv] of Object.entries(rawDeps)) {
          // dep values may include protocol: "npm:1.20.1" → strip prefix
          deps[dn] = dv.startsWith('npm:') ? dv.slice(4) : dv
        }
        entries.set(nv, { version, deps })
      }
    }
  }

  return buildResult(entries, packageJson)
}

// ── Public API ───────────────────────────────────────────────────────────────

export function parseYarnLock(content: string, packageJson: RootPackageJson): ResolvedPackage[] {
  if (content.includes('# yarn lockfile v1')) {
    return parseYarnClassic(content, packageJson)
  }
  return parseYarnBerry(content, packageJson)
}
