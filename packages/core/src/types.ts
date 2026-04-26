export interface ResolvedPackage {
  name: string
  version: string
  depth: number
  dependents: string[]
  devOnly: boolean
  lockfileSource: 'npm' | 'yarn' | 'pnpm'
}

export interface AffectedSymbol {
  name: string
  type: 'function' | 'class' | 'method' | 'export' | 'unknown'
  confidence: 'high' | 'medium' | 'low'
  source: 'osv' | 'fix-diff' | 'nvd-desc' | 'ghsa-desc' | 'override'
}

export interface CveRecord {
  id: string
  aliases: string[]
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  cvssScore: number
  epssScore: number
  affectedVersionRange: string
  affectedSymbols: AffectedSymbol[]
  fixCommitUrls: string[]
  description: string
  publishedAt: Date
}

export interface CallEdge {
  callerFile: string
  callerFunction: string
  calleePackage: string
  calleeSymbol: string
  line: number
  dynamic: boolean
}

export interface EntryPoint {
  file: string
  line: number
  kind: 'http' | 'cli' | 'env' | 'file-input' | 'ipc' | 'custom'
  framework?: 'express' | 'fastify' | 'nextjs' | 'other'
  authenticated: boolean
  description: string
}

export interface Evidence {
  type: 'import' | 'call-path' | 'entry-point' | 'symbol-source'
  description: string
  file?: string
  line?: number
  callPath?: string[]
  caveat?: string
}

export interface VerdictResult {
  cveId: string
  package: string
  version: string
  verdict: 'CRITICAL' | 'HIGH' | 'LOW' | 'SAFE'
  confidence: 'high' | 'medium' | 'low'
  reason: string
  evidence: Evidence[]
  epssScore: number
  cvssScore: number
  fixedIn?: string
}

export interface VexStatement {
  cveId: string
  product: { name: string; version: string }
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation'
  justification?:
    | 'vulnerable_code_not_present'
    | 'vulnerable_code_not_in_execute_path'
    | 'inline_mitigations_already_exist'
  impactStatement?: string
  evidenceRefs: string[]
}
