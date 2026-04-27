import { LockfileParseError } from '../errors.js'
import type { ResolvedPackage } from '../types.js'
import { NpmLockfileSchema } from './schemas.js'

const NM = 'node_modules/'

function nameFromKey(key: string): string {
  const i = key.lastIndexOf(NM)
  return key.slice(i + NM.length)
}

function depthFromKey(key: string): number {
  let n = 0
  let pos = 0
  while ((pos = key.indexOf(NM, pos)) !== -1) {
    n++
    pos += NM.length
  }
  return n
}

function sortedPackages(pkgs: ResolvedPackage[]): ResolvedPackage[] {
  return pkgs.sort((a, b) => {
    const ka = `${a.name}@${a.version}`
    const kb = `${b.name}@${b.version}`
    return ka < kb ? -1 : ka > kb ? 1 : 0
  })
}

export function parseNpmLock(content: string): ResolvedPackage[] {
  let raw: unknown
  try {
    raw = JSON.parse(content)
  } catch (err) {
    throw new LockfileParseError('package-lock.json', 'invalid JSON', { cause: err })
  }

  // Detect unsupported v1 format before Zod to give a clear message
  const maybeV1 = raw as Record<string, unknown>
  if (maybeV1['lockfileVersion'] === 1) {
    throw new LockfileParseError(
      'package-lock.json',
      'lockfileVersion 1 (npm 5/6) is not supported — re-run `npm install` with npm 7+ to upgrade',
    )
  }

  const parsed = NpmLockfileSchema.safeParse(raw)
  if (!parsed.success) {
    throw new LockfileParseError('package-lock.json', parsed.error.message)
  }

  const { packages } = parsed.data

  // dependentsMap: package name → set of direct depender names
  const depMap = new Map<string, Set<string>>()

  // Seed the map with all real packages (skip root '' and workspace links)
  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || entry.link === true || entry.version === undefined) continue
    const name = nameFromKey(key)
    if (!depMap.has(name)) depMap.set(name, new Set())
  }

  // Root package adds '.' as depender for its direct deps
  const root = packages['']
  if (root !== undefined) {
    for (const name of Object.keys({
      ...root.dependencies,
      ...root.devDependencies,
      ...root.optionalDependencies,
    })) {
      const rootDepSet = depMap.get(name) ?? new Set<string>()
      rootDepSet.add('.')
      depMap.set(name, rootDepSet)
    }
  }

  // Each package adds itself as depender for its deps
  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || entry.link === true || entry.version === undefined) continue
    const name = nameFromKey(key)
    for (const depName of Object.keys({ ...entry.dependencies, ...entry.optionalDependencies })) {
      const pkgDepSet = depMap.get(depName) ?? new Set<string>()
      pkgDepSet.add(name)
      depMap.set(depName, pkgDepSet)
    }
  }

  const result: ResolvedPackage[] = []

  for (const [key, entry] of Object.entries(packages)) {
    if (key === '' || entry.link === true || entry.version === undefined) continue
    result.push({
      name: nameFromKey(key),
      version: entry.version,
      depth: depthFromKey(key),
      dependents: [...(depMap.get(nameFromKey(key)) ?? [])].sort(),
      devOnly: entry.dev === true || entry.devOptional === true,
      lockfileSource: 'npm',
    })
  }

  return sortedPackages(result)
}
