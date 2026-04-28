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
  fixedIn?: string
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
  type: 'import' | 'call-path' | 'entry-point' | 'symbol-source' | 'suppression'
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

// M5 — Import graph types

export interface ImportRecord {
  package: string
  /** Named symbols imported; empty means all-symbols (namespace/default/dynamic require). */
  symbols: string[]
  kind:
    | 'named'
    | 'default'
    | 'namespace'
    | 'require-static'
    | 'require-dynamic'
    | 're-export'
    | 're-export-all'
  line: number
  caveat?: string
}

/** file path → list of import records found in that file */
export type ImportGraph = Map<string, ImportRecord[]>

/** file path → list of resolved local file paths it directly imports */
export type FileGraph = Map<string, string[]>

/** file path → call edges originating from that file */
export type CallGraph = Map<string, CallEdge[]>

export interface FileImportMatch {
  file: string
  line: number
  kind: ImportRecord['kind']
  /** Symbols from the import that appear in the CVE's affected symbol list. */
  matchedSymbols: string[]
  caveat?: string
}

export interface ImportMatchResult {
  packageName: string
  matches: FileImportMatch[]
  /**
   * True when at least one match is namespace / default / dynamic-require,
   * meaning we cannot rule out the vulnerable symbol being used.
   */
  conservative: boolean
  /**
   * True when the package appears in at least one import statement,
   * even if no affected symbol matched. Distinguishes "not imported at all"
   * from "imported but vulnerable symbols not used".
   */
  packageSeen: boolean
}
