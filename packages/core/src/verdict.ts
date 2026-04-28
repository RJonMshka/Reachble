import { matchImports } from './analysis/index.js'
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

function transitiveReachable(start: string, fileGraph: FileGraph): Set<string> {
  const visited = new Set<string>([start])
  const queue = [start]
  while (queue.length > 0) {
    const current = queue.shift()
    if (current === undefined) break
    for (const dep of fileGraph.get(current) ?? []) {
      if (!visited.has(dep)) {
        visited.add(dep)
        queue.push(dep)
      }
    }
  }
  return visited
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

function assessEntryPointReachability(
  matchResult: ImportMatchResult,
  entryPoints: EntryPoint[],
  fileGraph?: FileGraph,
  callSites?: CallEdge[],
): { verdict: Verdict; evidence: Evidence[] } | null {
  // Call graph provided but no matching call site → the symbol is never called; don't elevate.
  if (callSites !== undefined && callSites.length === 0) return null

  // If call-graph data is available, use it for precision; fall back to import sites.
  const hasCallGraph = callSites !== undefined
  const sourceFiles: Set<string> = hasCallGraph
    ? new Set(callSites.map((e) => e.callerFile))
    : new Set(matchResult.matches.map((m) => m.file))

  if (sourceFiles.size === 0) return null

  function epReaches(ep: EntryPoint): boolean {
    if (sourceFiles.has(ep.file)) return true
    if (fileGraph === undefined) return false
    const reachable = transitiveReachable(ep.file, fileGraph)
    for (const f of sourceFiles) {
      if (reachable.has(f)) return true
    }
    return false
  }

  const reachable = entryPoints.filter(epReaches)
  if (reachable.length === 0) return null

  const unauthed = reachable.filter((ep) => !ep.authenticated)
  const targetVerdict: Verdict = unauthed.length > 0 ? 'CRITICAL' : 'HIGH'
  const relevant = unauthed.length > 0 ? unauthed : reachable

  const evidence: Evidence[] = relevant.map((ep) => {
    if (hasCallGraph) {
      // Find the first call site reachable from this entry point
      const site = callSites.find((e) => {
        if (e.callerFile === ep.file) return true
        if (fileGraph === undefined) return false
        return transitiveReachable(ep.file, fileGraph).has(e.callerFile)
      })
      return {
        type: 'call-path' as const,
        description:
          site !== undefined
            ? `${site.callerFunction}() in ${ep.description} calls ${matchResult.packageName}.${site.calleeSymbol} at line ${String(site.line)}`
            : `${matchResult.packageName} called from ${ep.description}`,
        file: site?.callerFile ?? ep.file,
        line: site?.line ?? ep.line,
        ...(site !== undefined ? { callPath: [ep.description, `${site.callerFunction}()`] } : {}),
      }
    }
    return {
      type: 'entry-point' as const,
      description: `${matchResult.packageName} imported in ${ep.description}`,
      file: ep.file,
      line: ep.line,
      caveat: 'import-level co-location — call graph not available',
    }
  })

  return { verdict: targetVerdict, evidence }
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
  const { confidence } = assessment
  let { verdict, reason, evidence } = assessment

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
    const epResult = assessEntryPointReachability(
      matchResult,
      opts.entryPoints,
      opts.fileGraph,
      callSites,
    )
    if (epResult !== null) {
      const tier = epResult.verdict === 'CRITICAL' ? 'unauthenticated' : 'authenticated'
      verdict = epResult.verdict
      reason = `${reason} — reachable from ${tier} entry point`
      evidence = [...evidence, ...epResult.evidence]
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
      results.push(computeVerdict(pkg, cve, matchResult, verdictOpts))
    }
  }

  return results
}
