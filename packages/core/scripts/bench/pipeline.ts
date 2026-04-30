import { join } from 'node:path'

import {
  buildCallGraph,
  buildFileGraph,
  buildImportGraph,
  detectEntryPoints,
} from '../../src/analysis/index.js'
import { resolveCves } from '../../src/cve/resolver.js'
import { detectAndParse } from '../../src/lockfile/detect.js'
import type { CallGraph } from '../../src/types.js'
import { scoreVerdicts } from '../../src/verdict.js'

import type { BenchRepo, BenchResult, PhaseTimings, TopFinding } from './types.js'

// ── Timing helpers ─────────────────────────────────────────────────────────────

function timed<T>(fn: () => T): { result: T; ms: number } {
  const t = performance.now()
  const result = fn()
  return { result, ms: Math.round(performance.now() - t) }
}

async function timedAsync<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const t = performance.now()
  const result = await fn()
  return { result, ms: Math.round(performance.now() - t) }
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

export interface PipelineOptions {
  callGraph: boolean
  githubToken?: string
  /** Skip NVD/EPSS/fix-diff network calls; use cached data only. Useful for measuring analysis speed. */
  offlineCve?: boolean
}

export async function runPipeline(
  repo: BenchRepo,
  cloneDir: string,
  opts: PipelineOptions,
): Promise<BenchResult> {
  const scanDir = repo.subdir ? join(cloneDir, repo.subdir) : cloneDir
  const totalStart = performance.now()

  // Phase 1 — Lockfile
  const { result: packages, ms: lockfileParse } = await timedAsync(() =>
    detectAndParse(scanDir),
  )

  // Phase 2 — Import graph
  const { result: importGraph, ms: importGraphMs } = timed(() => buildImportGraph(scanDir))

  // Phase 3 — File graph (BFS reachability)
  const { result: fileGraph, ms: fileGraphMs } = timed(() => buildFileGraph(scanDir))

  // Phase 4 — Entry points
  const { result: entryPoints, ms: entryPointsMs } = timed(() => detectEntryPoints(scanDir))

  // Phase 5 — Call graph (ts-morph; skipped when --no-callgraph or no tsconfig)
  let callGraphResult: CallGraph | null = null
  let callGraphMs = 0
  if (opts.callGraph) {
    const cg = timed(() => buildCallGraph(scanDir))
    callGraphResult = cg.result
    callGraphMs = cg.ms
  }

  // Phase 6 — CVE resolution
  const { result: cveMap, ms: cveResolutionMs } = await timedAsync(() =>
    resolveCves(packages, {
      ...(opts.githubToken !== undefined ? { githubToken: opts.githubToken } : {}),
      ...(opts.offlineCve === true ? { offline: true } : {}),
    }),
  )

  // Phase 7 — Verdict scoring (full V1: import + entry-point + call graph)
  const verdictOpts = {
    entryPoints,
    fileGraph,
    ...(callGraphResult !== null ? { callGraph: callGraphResult } : {}),
  }
  const { result: verdicts, ms: verdictScoringMs } = timed(() =>
    scoreVerdicts(packages, cveMap, importGraph, verdictOpts),
  )

  // Secondary pass: import+EP only (no call graph) — to measure call-graph elevation delta
  const verdictsImportOnly =
    opts.callGraph && callGraphResult !== null
      ? scoreVerdicts(packages, cveMap, importGraph, { entryPoints, fileGraph })
      : verdicts

  const total = Math.round(performance.now() - totalStart)

  // ── Metrics ────────────────────────────────────────────────────────────────

  const totalCves = [...cveMap.values()].reduce((n, a) => n + a.length, 0)
  const cvesWithSymbols = [...cveMap.values()].reduce(
    (n, a) => n + a.filter((c) => c.affectedSymbols.length > 0).length,
    0,
  )

  let callEdgeCount = 0
  if (callGraphResult !== null) {
    for (const edges of callGraphResult.values()) callEdgeCount += edges.length
  }

  const vd = { CRITICAL: 0, HIGH: 0, LOW: 0, SAFE: 0 }
  for (const v of verdicts) vd[v.verdict]++

  // Count elevations caused specifically by call graph (was LOW w/o CG, now HIGH/CRITICAL with CG)
  let callGraphElevations = 0
  if (opts.callGraph && callGraphResult !== null) {
    const importOnlyMap = new Map(
      verdictsImportOnly.map((v) => [`${v.cveId}::${v.package}`, v.verdict]),
    )
    for (const v of verdicts) {
      const prev = importOnlyMap.get(`${v.cveId}::${v.package}`)
      if (
        prev !== undefined &&
        (v.verdict === 'CRITICAL' || v.verdict === 'HIGH') &&
        (prev === 'LOW' || prev === 'SAFE')
      ) {
        callGraphElevations++
      }
    }
  }

  const noiseReduction = totalCves > 0 ? Math.round((vd.SAFE / totalCves) * 100) : 0

  function toTopFinding(v: (typeof verdicts)[number]): TopFinding {
    return {
      cveId: v.cveId,
      package: v.package,
      version: v.version,
      cvssScore: v.cvssScore,
      epssScore: v.epssScore,
      reason: v.reason,
      evidence: v.evidence[0]?.description ?? '',
    }
  }

  const topCritical = verdicts
    .filter((v) => v.verdict === 'CRITICAL')
    .sort((a, b) => b.cvssScore - a.cvssScore)
    .slice(0, 5)
    .map(toTopFinding)

  const topHigh = verdicts
    .filter((v) => v.verdict === 'HIGH')
    .sort((a, b) => b.cvssScore - a.cvssScore)
    .slice(0, 5)
    .map(toTopFinding)

  const timings: PhaseTimings = {
    lockfileParse,
    importGraph: importGraphMs,
    fileGraph: fileGraphMs,
    entryPoints: entryPointsMs,
    callGraph: callGraphMs,
    cveResolution: cveResolutionMs,
    verdictScoring: verdictScoringMs,
    total,
  }

  return {
    repo: repo.name,
    url: repo.url,
    ref: repo.ref,
    framework: repo.framework,
    ...(repo.notes !== undefined ? { notes: repo.notes } : {}),

    packageCount: packages.length,
    fileCount: importGraph.size,
    totalCves,
    cvesWithSymbols,

    entryPointCount: entryPoints.length,
    unauthenticatedEpCount: entryPoints.filter((ep) => !ep.authenticated).length,

    callGraphEnabled: opts.callGraph && callGraphResult !== null,
    callEdgeCount,

    verdicts: vd,
    noiseReduction,
    actionableFindings: vd.CRITICAL + vd.HIGH,
    callGraphElevations,

    topCritical,
    topHigh,
    timings,
  }
}
