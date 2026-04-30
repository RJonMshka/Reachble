export interface BenchRepo {
  name: string
  url: string
  /** Git tag or commit SHA */
  ref: string
  framework: 'express' | 'fastify' | 'next' | 'koa' | 'none'
  /** Subdirectory to scan inside the clone (for monorepo sub-packages) */
  subdir?: string
  notes?: string
}

export interface PhaseTimings {
  lockfileParse: number
  importGraph: number
  fileGraph: number
  entryPoints: number
  callGraph: number
  cveResolution: number
  verdictScoring: number
  total: number
}

export interface TopFinding {
  cveId: string
  package: string
  version: string
  cvssScore: number
  epssScore: number
  reason: string
  evidence: string
}

export interface BenchResult {
  repo: string
  url: string
  ref: string
  framework: string
  notes?: string
  error?: string

  packageCount: number
  fileCount: number

  totalCves: number
  cvesWithSymbols: number

  entryPointCount: number
  unauthenticatedEpCount: number

  callGraphEnabled: boolean
  callEdgeCount: number

  verdicts: {
    CRITICAL: number
    HIGH: number
    LOW: number
    SAFE: number
  }

  /** SAFE / totalCves × 100 — false-positive rate of naive scanners */
  noiseReduction: number
  /** CRITICAL + HIGH */
  actionableFindings: number
  /** Verdicts elevated LOW→HIGH/CRITICAL by call graph vs import-only */
  callGraphElevations: number

  topCritical: TopFinding[]
  topHigh: TopFinding[]

  timings: PhaseTimings
}

export interface BenchOptions {
  callGraph: boolean
  reuse: boolean
  /** Skip NVD/EPSS/fix-diff fetching; use cached OSV data only. Shows true analysis speed. */
  offlineCve: boolean
  benchDir: string
  outJson: string
  outMd: string
  githubToken: string | undefined
  /** Filter by repo name; empty = all */
  repoFilter: string[]
}
