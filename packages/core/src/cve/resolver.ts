import pLimit from 'p-limit'

import { CveResolverError } from '../errors.js'
import type { CveRecord } from '../types.js'
import type { ResolvedPackage } from '../types.js'
import { CveCache } from './cache.js'
import { fetchEpssScores } from './epss.js'
import { fetchNvdCvss } from './nvd.js'
import { queryOsvBatch } from './osv.js'
import type { OsvVulnerability, OsvRange } from './schemas.js'
import { extractSymbols } from './symbols.js'
import type { SymbolOverride } from './symbols.js'

export interface ResolverOptions {
  offline?: boolean
  cacheDir?: string
  nvdApiKey?: string
  overrides?: SymbolOverride[]
}

// ── Severity helpers ─────────────────────────────────────────────────────────

type Severity = CveRecord['severity']

function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'CRITICAL'
  if (score >= 7.0) return 'HIGH'
  if (score >= 4.0) return 'MEDIUM'
  return 'LOW'
}

function severityStringToScore(s: string): number {
  const up = s.toUpperCase()
  if (up === 'CRITICAL') return 9.5
  if (up === 'HIGH') return 7.5
  if (up === 'MEDIUM' || up === 'MODERATE') return 5.0
  return 2.0
}

// ── Fix-version extraction ───────────────────────────────────────────────────

function extractFixedIn(ranges: OsvRange[] | undefined): string | undefined {
  if (!ranges) return undefined
  for (const range of ranges) {
    if (range.type !== 'SEMVER') continue
    for (const ev of range.events) {
      if (ev.fixed) return ev.fixed
    }
  }
  return undefined
}

function buildVersionRange(ranges: OsvRange[] | undefined): string {
  if (!ranges) return '*'
  const parts: string[] = []
  for (const range of ranges) {
    if (range.type !== 'SEMVER') continue
    let intro: string | undefined
    let fixed: string | undefined
    for (const ev of range.events) {
      if (ev.introduced) intro = ev.introduced
      if (ev.fixed) fixed = ev.fixed
    }
    if (intro === '0' || intro === undefined) {
      parts.push(fixed ? `<${fixed}` : '*')
    } else {
      parts.push(fixed ? `>=${intro} <${fixed}` : `>=${intro}`)
    }
  }
  return parts.length > 0 ? parts.join(' || ') : '*'
}

// ── OSV vuln → CveRecord ─────────────────────────────────────────────────────

function buildCveRecord(
  vuln: OsvVulnerability,
  cvssScore: number,
  severity: Severity,
  epssScore: number,
  opts: ResolverOptions,
): CveRecord {
  const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id
  const aliases = [vuln.id, ...(vuln.aliases?.filter((a) => a !== cveId) ?? [])].filter(
    (a): a is string => a !== cveId,
  )

  const npmAffected = vuln.affected.find((a) => a.package.ecosystem === 'npm')
  const fixedIn = extractFixedIn(npmAffected?.ranges)
  const affectedVersionRange = buildVersionRange(npmAffected?.ranges)

  const symbols = extractSymbols(
    vuln,
    opts.overrides !== undefined ? { overrides: opts.overrides } : {},
  )

  const record: CveRecord = {
    id: cveId,
    aliases,
    severity,
    cvssScore,
    epssScore,
    affectedVersionRange,
    affectedSymbols: symbols,
    fixCommitUrls: (vuln.references ?? []).filter((r) => r.type === 'FIX').map((r) => r.url),
    description: vuln.details ?? vuln.summary ?? '',
    publishedAt: new Date(vuln.published),
  }

  if (fixedIn !== undefined) record.fixedIn = fixedIn

  return record
}

// ── CVSS resolution: OSV → NVD fallback ─────────────────────────────────────

function extractOsvCvssScore(
  vuln: OsvVulnerability,
): { score: number; severity: Severity } | undefined {
  const dbSev = vuln.database_specific?.severity
  if (dbSev) {
    const score = severityStringToScore(dbSev)
    return { score, severity: scoreToSeverity(score) }
  }

  for (const aff of vuln.affected) {
    const affSev = aff.database_specific?.severity
    if (affSev) {
      const score = severityStringToScore(affSev)
      return { score, severity: scoreToSeverity(score) }
    }
  }

  return undefined
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

const OSV_CACHE_PREFIX = 'osv:npm:'
const NVD_CACHE_PREFIX = 'nvd:'
const EPSS_CACHE_PREFIX = 'epss:'

// ── Main resolver ────────────────────────────────────────────────────────────

export async function resolveCves(
  packages: ResolvedPackage[],
  opts: ResolverOptions = {},
): Promise<Map<string, CveRecord[]>> {
  const cache = new CveCache(opts.cacheDir)

  try {
    return await resolveWithCache(packages, opts, cache)
  } finally {
    cache.close()
  }
}

async function resolveWithCache(
  packages: ResolvedPackage[],
  opts: ResolverOptions,
  cache: CveCache,
): Promise<Map<string, CveRecord[]>> {
  // ── 1. OSV batch query (with cache) ────────────────────────────────────────
  const uncachedPkgs: ResolvedPackage[] = []
  const cachedResults = new Map<string, OsvVulnerability[]>()

  for (const pkg of packages) {
    const key = `${OSV_CACHE_PREFIX}${pkg.name}@${pkg.version}`
    const hit = cache.get(key)
    if (Array.isArray(hit)) {
      cachedResults.set(`${pkg.name}@${pkg.version}`, hit as OsvVulnerability[])
    } else {
      uncachedPkgs.push(pkg)
    }
  }

  if (uncachedPkgs.length > 0 && opts.offline) {
    throw new CveResolverError(
      `Offline mode: ${String(uncachedPkgs.length)} packages not in cache. Run without --offline to populate.`,
    )
  }

  if (uncachedPkgs.length > 0) {
    const osvResponse = await queryOsvBatch(uncachedPkgs)
    for (let i = 0; i < uncachedPkgs.length; i++) {
      const pkg = uncachedPkgs[i]
      if (!pkg) continue
      const vulns = osvResponse.results[i]?.vulns ?? []
      const key = `${OSV_CACHE_PREFIX}${pkg.name}@${pkg.version}`
      cache.set(key, vulns)
      cachedResults.set(`${pkg.name}@${pkg.version}`, vulns)
    }
  }

  // ── 2. Collect all unique CVE IDs needing CVSS / EPSS ──────────────────────
  const allVulns = new Map<string, OsvVulnerability>()
  const vulnsByCveId = new Map<string, { score: number; severity: Severity }>()
  const cveIdsNeedingNvd: string[] = []

  for (const vulns of cachedResults.values()) {
    for (const vuln of vulns) {
      const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id
      if (!allVulns.has(cveId)) {
        allVulns.set(cveId, vuln)
        const osvCvss = extractOsvCvssScore(vuln)
        if (osvCvss) {
          vulnsByCveId.set(cveId, osvCvss)
        } else {
          cveIdsNeedingNvd.push(cveId)
        }
      }
    }
  }

  // ── 3. NVD CVSS for those OSV couldn't provide ─────────────────────────────
  if (cveIdsNeedingNvd.length > 0 && !opts.offline) {
    const nvdLimit = pLimit(opts.nvdApiKey ? 5 : 1)
    await Promise.all(
      cveIdsNeedingNvd.map((cveId) =>
        nvdLimit(async () => {
          const cacheKey = `${NVD_CACHE_PREFIX}${cveId}`
          const cached = cache.get(cacheKey)
          let result: { score: number; severity: Severity } | undefined

          if (cached !== null && typeof cached === 'object' && 'score' in cached) {
            result = cached as { score: number; severity: Severity }
          } else {
            const nvd = await fetchNvdCvss(cveId, opts.nvdApiKey)
            if (nvd) {
              result = { score: nvd.score, severity: nvd.severity }
              cache.set(cacheKey, result)
            }
          }

          if (result) vulnsByCveId.set(cveId, result)
        }),
      ),
    )
  }

  // ── 4. EPSS scores ─────────────────────────────────────────────────────────
  const allCveIds = [...allVulns.keys()]
  const epssMap = new Map<string, number>()

  const uncachedEpssIds: string[] = []
  for (const id of allCveIds) {
    const cached = cache.get(`${EPSS_CACHE_PREFIX}${id}`)
    if (typeof cached === 'number') {
      epssMap.set(id, cached)
    } else {
      uncachedEpssIds.push(id)
    }
  }

  if (uncachedEpssIds.length > 0 && !opts.offline) {
    const fetched = await fetchEpssScores(uncachedEpssIds)
    for (const [id, score] of fetched) {
      epssMap.set(id, score)
      cache.set(`${EPSS_CACHE_PREFIX}${id}`, score)
    }
  }

  // ── 5. Build CveRecord[] per package ───────────────────────────────────────
  const result = new Map<string, CveRecord[]>()

  for (const pkg of packages) {
    const pkgKey = `${pkg.name}@${pkg.version}`
    const vulns = cachedResults.get(pkgKey) ?? []
    const records: CveRecord[] = []

    for (const vuln of vulns) {
      const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id
      const cvssInfo = vulnsByCveId.get(cveId)
      const cvssScore = cvssInfo?.score ?? 0
      const severity = cvssInfo?.severity ?? 'LOW'
      const epssScore = epssMap.get(cveId) ?? 0

      records.push(buildCveRecord(vuln, cvssScore, severity, epssScore, opts))
    }

    result.set(pkgKey, records)
  }

  return result
}
