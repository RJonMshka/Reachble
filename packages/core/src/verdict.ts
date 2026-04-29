import { matchImports } from './analysis/index.js'
import { bfsPath, findCallPath, isTestFile } from './analysis/reach.js'
import type { Suppression } from './config.js'
import type {
  CallEdge,
  CallGraph,
  CveRecord,
  EntryPoint,
  Evidence,
  FileGraph,
  ImportGraph,
  ImportMatchResult,
  ResolvedPackage,
  VerdictResult,
} from './types.js'

type Verdict = VerdictResult['verdict']
type Confidence = VerdictResult['confidence']

const VERDICT_TIERS: readonly Verdict[] = ['SAFE', 'LOW', 'HIGH', 'CRITICAL']

function elevate(verdict: Verdict): Verdict {
  const idx = VERDICT_TIERS.indexOf(verdict)
  return VERDICT_TIERS[Math.min(idx + 1, VERDICT_TIERS.length - 1)] as Verdict
}

function applyEpss(verdict: Verdict, epss: number): Verdict {
  if (epss > 0.5) return elevate(verdict)
  if (epss > 0.3 && verdict === 'SAFE') return 'LOW'
  return verdict
}

function clampToLow(verdict: Verdict): Verdict {
  return verdict === 'CRITICAL' || verdict === 'HIGH' ? 'LOW' : verdict
}

/** Return call edges in `callGraph` where the callee matches package + any of the symbols. */
function findCallSites(
  callGraph: CallGraph,
  packageName: string,
  symbolNames: string[],
): CallEdge[] {
  const symbolSet = new Set(symbolNames)
  const sites: CallEdge[] = []
  for (const edges of callGraph.values()) {
    for (const edge of edges) {
      if (edge.calleePackage === packageName && symbolSet.has(edge.calleeSymbol)) {
        sites.push(edge)
      }
    }
  }
  return sites
}

interface EpReachResult {
  verdict: Verdict
  evidence: Evidence[]
  /** True when the path to the vulnerable call goes through a dynamic dispatch. */
  hasDynamicPath: boolean
  /** True when every call site for the vulnerable symbol lives in a test file. */
  isTestOnlyPath: boolean
}

interface AssessEpOpts {
  fileGraph?: FileGraph
  callSites?: CallEdge[]
  depthLimit?: number
}

function assessEntryPointReachability(
  matchResult: ImportMatchResult,
  entryPoints: EntryPoint[],
  opts: AssessEpOpts,
): EpReachResult | null {
  const { fileGraph, callSites, depthLimit = 25 } = opts

  // Call graph provided but no matching call site → symbol never called; don't elevate.
  if (callSites !== undefined && callSites.length === 0) return null

  // ── Call graph path (precise) ──────────────────────────────────────────────
  if (callSites !== undefined && fileGraph !== undefined) {
    type Hit = { ep: EntryPoint; path: import('./analysis/reach.js').ReachPath }
    const hits: Hit[] = []
    for (const ep of entryPoints) {
      const path = findCallPath(ep, callSites, fileGraph, depthLimit)
      if (path !== null) hits.push({ ep, path })
    }
    if (hits.length === 0) return null

    const unauthed = hits.filter((h) => !h.ep.authenticated)
    const targetVerdict: Verdict = unauthed.length > 0 ? 'CRITICAL' : 'HIGH'
    const relevant = unauthed.length > 0 ? unauthed : hits

    const hasDynamicPath = relevant.some((h) => h.path.hasDynamicEdge)
    const isTestOnlyPath = relevant.every((h) => isTestFile(h.path.callSite.callerFile))

    const evidence: Evidence[] = relevant.map(({ ep, path }) => {
      const { callSite: site, filePath } = path
      const caveats: string[] = []
      if (site.dynamic) caveats.push('dynamic call — cannot statically confirm symbol dispatch')

      // Build full call path: entry point → intermediate files → caller→symbol
      const callPath = [
        ep.description,
        ...filePath.slice(1, -1),
        `${site.callerFunction}() → ${matchResult.packageName}.${site.calleeSymbol}`,
      ]

      return {
        type: 'call-path' as const,
        description: `${site.callerFunction}() in ${ep.description} calls ${matchResult.packageName}.${site.calleeSymbol} at line ${String(site.line)}`,
        file: site.callerFile,
        line: site.line,
        callPath,
        ...(caveats.length > 0 ? { caveat: caveats.join('; ') } : {}),
      }
    })

    return { verdict: targetVerdict, evidence, hasDynamicPath, isTestOnlyPath }
  }

  // ── Import-level fallback (no call graph) ──────────────────────────────────
  const sourceFiles = new Set(matchResult.matches.map((m) => m.file))
  if (sourceFiles.size === 0) return null

  type ImportHit = { ep: EntryPoint; path: string[] }
  const importHits: ImportHit[] = []

  for (const ep of entryPoints) {
    if (sourceFiles.has(ep.file)) {
      importHits.push({ ep, path: [ep.file] })
    } else if (fileGraph !== undefined) {
      const path = bfsPath(ep.file, sourceFiles, fileGraph, depthLimit)
      if (path !== null) importHits.push({ ep, path })
    }
  }

  if (importHits.length === 0) return null

  const unauthed = importHits.filter((h) => !h.ep.authenticated)
  const targetVerdict: Verdict = unauthed.length > 0 ? 'CRITICAL' : 'HIGH'
  const relevant = unauthed.length > 0 ? unauthed : importHits

  const isTestOnlyPath = relevant.every((h) => {
    const lastFile = h.path[h.path.length - 1]
    return lastFile !== undefined && isTestFile(lastFile)
  })

  const evidence: Evidence[] = relevant.map(({ ep, path }) => {
    const callPath = path.length > 1 ? path : undefined
    return {
      type: 'entry-point' as const,
      description: `${matchResult.packageName} imported in ${ep.description}`,
      file: ep.file,
      line: ep.line,
      ...(callPath !== undefined ? { callPath } : {}),
      caveat: 'import-level co-location — call graph not available',
    }
  })

  return { verdict: targetVerdict, evidence, hasDynamicPath: false, isTestOnlyPath }
}

interface BaseAssessment {
  verdict: Verdict
  confidence: Confidence
  reason: string
  evidence: Evidence[]
}

function symbolConfidenceToOverall(
  matchedNames: string[],
  affectedSymbols: CveRecord['affectedSymbols'],
): Confidence {
  const matched = affectedSymbols.filter((s) => matchedNames.includes(s.name))
  if (matched.some((s) => s.confidence === 'low')) return 'low'
  if (matched.some((s) => s.confidence === 'medium')) return 'low'
  // All high-confidence symbols — but import-level is at most medium
  return 'medium'
}

function assessImportMatch(matchResult: ImportMatchResult, cve: CveRecord): BaseAssessment {
  // Package completely absent from the codebase
  if (!matchResult.packageSeen) {
    return {
      verdict: 'SAFE',
      confidence: 'high',
      reason: `${matchResult.packageName} is not imported in any analyzed file`,
      evidence: [
        {
          type: 'import',
          description: `Package ${matchResult.packageName} not found in import graph`,
        },
      ],
    }
  }

  // Package imported but no specific vulnerable symbols known — package-level only
  if (cve.affectedSymbols.length === 0) {
    const evidence: Evidence[] = matchResult.matches.map((m) => ({
      type: 'import' as const,
      description: `${matchResult.packageName} imported at ${m.file}:${String(m.line)}`,
      file: m.file,
      line: m.line,
      caveat: 'no specific vulnerable symbol identified — package-level assessment only',
    }))
    return {
      verdict: 'LOW',
      confidence: 'low',
      reason: `${matchResult.packageName} imported but no specific vulnerable symbol identified`,
      evidence:
        evidence.length > 0
          ? evidence
          : [
              {
                type: 'import' as const,
                description: `${matchResult.packageName} is imported`,
                caveat: 'no specific vulnerable symbol identified — package-level assessment only',
              },
            ],
    }
  }

  // Conservative import (namespace / default / dynamic require) — can't rule out the symbol
  if (matchResult.conservative) {
    const evidence: Evidence[] = matchResult.matches.map((m) => ({
      type: 'import' as const,
      description: `${matchResult.packageName} imported at ${m.file}:${String(m.line)} (${m.kind})`,
      file: m.file,
      line: m.line,
      caveat:
        m.caveat ?? 'conservative import — cannot statically determine which symbols are used',
    }))
    return {
      verdict: 'LOW',
      confidence: 'low',
      reason: `${matchResult.packageName} imported conservatively — cannot rule out vulnerable symbol`,
      evidence,
    }
  }

  // Named imports present — check for exact symbol match
  const exactMatches = matchResult.matches.filter((m) => m.matchedSymbols.length > 0)

  if (exactMatches.length > 0) {
    const allMatchedNames = exactMatches.flatMap((m) => m.matchedSymbols)
    const confidence = symbolConfidenceToOverall(allMatchedNames, cve.affectedSymbols)
    const evidence: Evidence[] = exactMatches.map((m) => ({
      type: 'import' as const,
      description: `Vulnerable symbol(s) ${m.matchedSymbols.join(', ')} imported from ${matchResult.packageName} at ${m.file}:${String(m.line)}`,
      file: m.file,
      line: m.line,
      caveat: 'import-level analysis only — V1 call graph will refine reachability',
    }))
    return {
      verdict: 'LOW',
      confidence,
      reason: `Vulnerable symbol(s) imported from ${matchResult.packageName}`,
      evidence,
    }
  }

  // Package imported with named imports, none match the affected symbols
  return {
    verdict: 'SAFE',
    confidence: 'high',
    reason: `Vulnerable symbol(s) not imported from ${matchResult.packageName}`,
    evidence: [
      {
        type: 'import',
        description: `${matchResult.packageName} imported but none of the vulnerable symbols (${cve.affectedSymbols.map((s) => s.name).join(', ')}) appear in any import statement`,
      },
    ],
  }
}

export interface ComputeVerdictOptions {
  suppression?: Suppression
  entryPoints?: EntryPoint[]
  fileGraph?: FileGraph
  callGraph?: CallGraph
  /** Maximum BFS depth when tracing call paths. Default: 25. */
  depthLimit?: number
}

/**
 * Pure function: given a single (package, CVE, import match) triple, compute the verdict.
 * Same inputs always produce byte-identical output.
 */
export function computeVerdict(
  pkg: ResolvedPackage,
  cve: CveRecord,
  matchResult: ImportMatchResult,
  opts: ComputeVerdictOptions = {},
): VerdictResult {
  const assessment = assessImportMatch(matchResult, cve)
  let { verdict, confidence, reason, evidence } = assessment

  // Entry point elevation: LOW → CRITICAL/HIGH when an entry point can reach the call/import site
  if (verdict === 'LOW' && opts.entryPoints !== undefined && opts.entryPoints.length > 0) {
    const callSites =
      opts.callGraph !== undefined
        ? findCallSites(
            opts.callGraph,
            pkg.name,
            cve.affectedSymbols.map((s) => s.name),
          )
        : undefined
    const epOpts: AssessEpOpts = {}
    if (opts.fileGraph !== undefined) epOpts.fileGraph = opts.fileGraph
    if (callSites !== undefined) epOpts.callSites = callSites
    if (opts.depthLimit !== undefined) epOpts.depthLimit = opts.depthLimit
    const epResult = assessEntryPointReachability(matchResult, opts.entryPoints, epOpts)
    if (epResult !== null) {
      if (epResult.isTestOnlyPath) {
        // Vulnerable call only reachable through test files → stay LOW
        reason = `${reason} — call path only traverses test files`
        evidence = [
          ...evidence,
          ...epResult.evidence,
          {
            type: 'import' as const,
            description: 'all paths to the vulnerable symbol pass through test files',
            caveat: 'test-file-only path — real-world reachability not confirmed',
          },
        ]
      } else {
        const tier = epResult.verdict === 'CRITICAL' ? 'unauthenticated' : 'authenticated'
        verdict = epResult.verdict
        reason = `${reason} — reachable from ${tier} entry point`
        evidence = [...evidence, ...epResult.evidence]

        if (epResult.hasDynamicPath) {
          confidence = 'low'
          evidence = [
            ...evidence,
            {
              type: 'call-path' as const,
              description:
                'path includes a dynamic dispatch — symbol target cannot be statically confirmed',
              caveat: 'dynamic call edge reduces confidence to low',
            },
          ]
        }
      }
    }
  }

  // EPSS adjustment (statistical elevation)
  const epssAdjusted = applyEpss(verdict, cve.epssScore)
  if (epssAdjusted !== verdict) {
    evidence = [
      ...evidence,
      {
        type: 'symbol-source' as const,
        description: `EPSS score ${cve.epssScore.toFixed(3)} elevated verdict from ${verdict} to ${epssAdjusted}`,
        caveat:
          'EPSS is a statistical exploit-probability score; does not confirm reachability in this codebase',
      },
    ]
    verdict = epssAdjusted
  }

  // devOnly cap — hard rule: dev-only deps never exceed LOW
  if (pkg.devOnly) {
    const clamped = clampToLow(verdict)
    if (clamped !== verdict) {
      reason = `${reason} (clamped to LOW — dev-only dependency)`
      verdict = clamped
      // confidence stays as-is; if it was elevated to HIGH/CRITICAL by EPSS, it's now LOW
    }
  }

  // Suppression override
  if (opts.suppression !== undefined) {
    const sup = opts.suppression
    const reviewNote = sup.reviewedBy !== undefined ? ` (reviewed by ${sup.reviewedBy})` : ''
    return {
      cveId: cve.id,
      package: pkg.name,
      version: pkg.version,
      verdict: 'SAFE',
      confidence: 'high',
      reason: `Suppressed by .reachble.json: ${sup.reason}`,
      evidence: [
        ...evidence,
        {
          type: 'suppression',
          description: `User suppression: ${sup.reason}${reviewNote}`,
        },
      ],
      epssScore: cve.epssScore,
      cvssScore: cve.cvssScore,
      ...(cve.fixedIn !== undefined ? { fixedIn: cve.fixedIn } : {}),
    }
  }

  const result: VerdictResult = {
    cveId: cve.id,
    package: pkg.name,
    version: pkg.version,
    verdict,
    confidence,
    reason,
    evidence,
    epssScore: cve.epssScore,
    cvssScore: cve.cvssScore,
  }
  if (cve.fixedIn !== undefined) result.fixedIn = cve.fixedIn

  return result
}

export interface ScoreOptions {
  suppressions?: Suppression[]
  entryPoints?: EntryPoint[]
  fileGraph?: FileGraph
  callGraph?: CallGraph
  depthLimit?: number
}

/**
 * Compose ResolvedPackage[] + CveRecord map + ImportGraph into VerdictResult[].
 * Output is deterministic: sorted by package name, version, then CVE id.
 */
export function scoreVerdicts(
  packages: ResolvedPackage[],
  cveMap: Map<string, CveRecord[]>,
  graph: ImportGraph,
  opts: ScoreOptions = {},
): VerdictResult[] {
  const results: VerdictResult[] = []

  const sortedPackages = [...packages].sort((a, b) => {
    const nameOrder = a.name.localeCompare(b.name)
    return nameOrder !== 0 ? nameOrder : a.version.localeCompare(b.version)
  })

  for (const pkg of sortedPackages) {
    const pkgKey = `${pkg.name}@${pkg.version}`
    const cves = [...(cveMap.get(pkgKey) ?? [])].sort((a, b) => a.id.localeCompare(b.id))

    for (const cve of cves) {
      const matchResult = matchImports(graph, pkg.name, cve.affectedSymbols)
      const suppression = opts.suppressions?.find(
        (s) => s.cveId === cve.id && s.package === pkg.name,
      )
      const verdictOpts: ComputeVerdictOptions = {}
      if (suppression !== undefined) verdictOpts.suppression = suppression
      if (opts.entryPoints !== undefined) verdictOpts.entryPoints = opts.entryPoints
      if (opts.fileGraph !== undefined) verdictOpts.fileGraph = opts.fileGraph
      if (opts.callGraph !== undefined) verdictOpts.callGraph = opts.callGraph
      if (opts.depthLimit !== undefined) verdictOpts.depthLimit = opts.depthLimit
      results.push(computeVerdict(pkg, cve, matchResult, verdictOpts))
    }
  }

  return results
}
