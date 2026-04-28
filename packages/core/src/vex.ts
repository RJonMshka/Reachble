import { createHash } from 'node:crypto'
import type { VerdictResult } from './types.js'

const TOOL_NAME = 'reachble'
const TOOL_VERSION = '0.1.0'

// ─── Options ─────────────────────────────────────────────────────────────────

export interface VexOptions {
  projectName: string
  projectVersion?: string
  /** Override tool version (useful in tests). */
  toolVersion?: string
  /**
   * ISO 8601 timestamp. Pass a fixed value for byte-stable golden-file tests.
   * Defaults to current time.
   */
  timestamp?: string
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function resolvedTs(opts: VexOptions): string {
  return opts.timestamp ?? new Date().toISOString()
}

function resolvedVersion(opts: VexOptions): string {
  return opts.toolVersion ?? TOOL_VERSION
}

/**
 * Build a purl for an npm package per the purl spec.
 * Scoped packages: @babel/core → pkg:npm/%40babel/core@version
 */
function purl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/', 1)
    if (slash !== -1) {
      const scope = encodeURIComponent(name.slice(0, slash))
      const pkg = name.slice(slash + 1)
      return `pkg:npm/${scope}/${pkg}@${version}`
    }
  }
  return `pkg:npm/${name}@${version}`
}

function contentHash(results: VerdictResult[]): string {
  return createHash('sha256').update(JSON.stringify(results)).digest('hex')
}

function hashToUrnUuid(hex: string): string {
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`
}

function isSuppressed(result: VerdictResult): boolean {
  return result.evidence.some((e) => e.type === 'suppression')
}

function impactStatement(result: VerdictResult): string {
  const parts: string[] = [result.reason]
  for (const ev of result.evidence) {
    const suffix = ev.caveat !== undefined ? ` (${ev.caveat})` : ''
    parts.push(`${ev.description}${suffix}`)
  }
  return parts.join('. ')
}

function cveSource(cveId: string): { name: string; url: string } {
  if (cveId.startsWith('CVE-'))
    return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cveId}` }
  if (cveId.startsWith('GHSA-'))
    return { name: 'GHSA', url: `https://github.com/advisories/${cveId}` }
  return { name: 'OSV', url: `https://osv.dev/vulnerability/${cveId}` }
}

function cveUri(cveId: string): string {
  if (cveId.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${cveId}`
  if (cveId.startsWith('GHSA-')) return `https://github.com/advisories/${cveId}`
  return `https://osv.dev/vulnerability/${cveId}`
}

function severityLabel(score: number): string {
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

// ─── CycloneDX VEX 1.5 ───────────────────────────────────────────────────────

type CdxAnalysisState = 'not_affected' | 'exploitable' | 'in_triage' | 'resolved' | 'false_positive'

type CdxJustification =
  | 'code_not_present'
  | 'code_not_reachable'
  | 'requires_configuration'
  | 'requires_dependency'
  | 'requires_environment'
  | 'protected_by_compiler'
  | 'protected_at_runtime'
  | 'protected_at_perimeter'
  | 'protected_by_mitigations'

export interface CdxAnalysis {
  state: CdxAnalysisState
  justification?: CdxJustification
  detail?: string
}

export interface CdxRating {
  score: number
  severity: string
  method: string
}

export interface CdxAffects {
  ref: string
  versions: Array<{ version: string; status: 'affected' | 'unaffected' }>
}

export interface CdxVulnerability {
  id: string
  source: { name: string; url: string }
  ratings?: CdxRating[]
  analysis: CdxAnalysis
  affects: CdxAffects[]
}

export interface CycloneDxVex {
  bomFormat: 'CycloneDX'
  specVersion: string
  serialNumber: string
  version: number
  metadata: {
    timestamp: string
    tools: Array<{ vendor: string; name: string; version: string }>
    component: { type: string; name: string; version?: string }
  }
  vulnerabilities: CdxVulnerability[]
}

function cdxState(result: VerdictResult): CdxAnalysisState {
  return result.verdict === 'SAFE' ? 'not_affected' : 'exploitable'
}

function cdxJustification(result: VerdictResult): CdxJustification | undefined {
  if (result.verdict !== 'SAFE') return undefined
  if (isSuppressed(result)) return 'protected_by_mitigations'
  // Package absent from all imports → code_not_present; symbol absent → code_not_reachable
  if (result.reason.includes('not imported in any analyzed file')) return 'code_not_present'
  return 'code_not_reachable'
}

/**
 * Build a CycloneDX VEX 1.5 document from scored verdicts.
 * Pure function: pass a fixed `timestamp` for byte-stable output.
 */
export function buildCycloneDxVex(results: VerdictResult[], opts: VexOptions): CycloneDxVex {
  const timestamp = resolvedTs(opts)
  const version = resolvedVersion(opts)
  const hash = contentHash(results)

  const component: CycloneDxVex['metadata']['component'] = {
    type: 'application',
    name: opts.projectName,
  }
  if (opts.projectVersion !== undefined) component.version = opts.projectVersion

  const vulnerabilities: CdxVulnerability[] = results.map((r) => {
    const state = cdxState(r)
    const justification = cdxJustification(r)
    const analysis: CdxAnalysis = { state, detail: impactStatement(r) }
    if (justification !== undefined) analysis.justification = justification

    const status = r.verdict === 'SAFE' ? ('unaffected' as const) : ('affected' as const)
    const vuln: CdxVulnerability = {
      id: r.cveId,
      source: cveSource(r.cveId),
      analysis,
      affects: [{ ref: purl(r.package, r.version), versions: [{ version: r.version, status }] }],
    }
    if (r.cvssScore > 0) {
      vuln.ratings = [
        { score: r.cvssScore, severity: severityLabel(r.cvssScore), method: 'CVSSv31' },
      ]
    }
    return vuln
  })

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: hashToUrnUuid(hash),
    version: 1,
    metadata: { timestamp, tools: [{ vendor: 'Reachble', name: TOOL_NAME, version }], component },
    vulnerabilities,
  }
}

// ─── OpenVEX 0.2 ─────────────────────────────────────────────────────────────

type OpenVexStatus = 'not_affected' | 'affected' | 'fixed' | 'under_investigation'

type OpenVexJustification =
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist'

export interface OpenVexStatement {
  vulnerability: { '@id': string; name: string }
  products: Array<{ '@id': string }>
  status: OpenVexStatus
  justification?: OpenVexJustification
  impact_statement: string
  timestamp: string
}

export interface OpenVexDocument {
  '@context': string
  '@id': string
  author: string
  timestamp: string
  version: number
  statements: OpenVexStatement[]
}

function openVexStatus(result: VerdictResult): OpenVexStatus {
  return result.verdict === 'SAFE' ? 'not_affected' : 'affected'
}

function openVexJustification(result: VerdictResult): OpenVexJustification | undefined {
  if (result.verdict !== 'SAFE') return undefined
  if (isSuppressed(result)) return 'inline_mitigations_already_exist'
  if (result.reason.includes('not imported in any analyzed file'))
    return 'vulnerable_code_not_present'
  return 'vulnerable_code_not_in_execute_path'
}

/**
 * Build an OpenVEX 0.2 document from scored verdicts.
 * Pure function: pass a fixed `timestamp` for byte-stable output.
 */
export function buildOpenVex(results: VerdictResult[], opts: VexOptions): OpenVexDocument {
  const timestamp = resolvedTs(opts)
  const hash = contentHash(results)

  const statements: OpenVexStatement[] = results.map((r) => {
    const status = openVexStatus(r)
    const justification = openVexJustification(r)
    const stmt: OpenVexStatement = {
      vulnerability: { '@id': cveUri(r.cveId), name: r.cveId },
      products: [{ '@id': purl(r.package, r.version) }],
      status,
      impact_statement: impactStatement(r),
      timestamp,
    }
    if (justification !== undefined) stmt.justification = justification
    return stmt
  })

  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://reachble.dev/vex/${hash}`,
    author: 'Reachble',
    timestamp,
    version: 1,
    statements,
  }
}

// ─── JSON v1 ─────────────────────────────────────────────────────────────────

export interface ReachbleJsonV1Summary {
  total: number
  critical: number
  high: number
  low: number
  safe: number
}

export interface ReachbleJsonV1 {
  $schema: string
  version: 'v1'
  generatedAt: string
  tool: { name: string; version: string }
  project: { name: string; version?: string }
  summary: ReachbleJsonV1Summary
  verdicts: VerdictResult[]
}

function summarize(results: VerdictResult[]): ReachbleJsonV1Summary {
  const s: ReachbleJsonV1Summary = { total: results.length, critical: 0, high: 0, low: 0, safe: 0 }
  for (const r of results) {
    if (r.verdict === 'CRITICAL') s.critical++
    else if (r.verdict === 'HIGH') s.high++
    else if (r.verdict === 'LOW') s.low++
    else s.safe++
  }
  return s
}

/**
 * Build a Reachble JSON v1 document — native format, versioned for future evolution.
 * Pure function: pass a fixed `timestamp` for byte-stable output.
 */
export function buildJsonV1(results: VerdictResult[], opts: VexOptions): ReachbleJsonV1 {
  const project: ReachbleJsonV1['project'] = { name: opts.projectName }
  if (opts.projectVersion !== undefined) project.version = opts.projectVersion

  return {
    $schema: 'https://reachble.dev/schema/v1/results.json',
    version: 'v1',
    generatedAt: resolvedTs(opts),
    tool: { name: TOOL_NAME, version: resolvedVersion(opts) },
    project,
    summary: summarize(results),
    verdicts: results,
  }
}

// ─── SARIF 2.1.0 ─────────────────────────────────────────────────────────────

type SarifLevel = 'error' | 'warning' | 'note' | 'none'

function sarifLevel(verdict: VerdictResult['verdict']): SarifLevel {
  switch (verdict) {
    case 'CRITICAL':
      return 'error'
    case 'HIGH':
      return 'warning'
    case 'LOW':
      return 'note'
    case 'SAFE':
      return 'none'
  }
}

interface SarifPhysicalLocation {
  artifactLocation: { uri: string; uriBaseId: string }
  region?: { startLine: number }
}

interface SarifLocation {
  physicalLocation: SarifPhysicalLocation
}

interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  properties: { tags: string[] }
}

interface SarifResultEntry {
  ruleId: string
  level: SarifLevel
  message: { text: string }
  locations: SarifLocation[]
  properties: {
    verdict: string
    confidence: string
    epssScore: number
    cvssScore: number
    package: string
    version: string
  }
}

export interface SarifDocument {
  $schema: string
  version: '2.1.0'
  runs: Array<{
    tool: {
      driver: {
        name: string
        version: string
        informationUri: string
        rules: SarifRule[]
      }
    }
    results: SarifResultEntry[]
  }>
}

function sarifLocations(result: VerdictResult): SarifLocation[] {
  const locs: SarifLocation[] = []
  for (const ev of result.evidence) {
    if (ev.file === undefined) continue
    const physLoc: SarifPhysicalLocation = {
      artifactLocation: { uri: ev.file, uriBaseId: '%SRCROOT%' },
    }
    if (ev.line !== undefined && ev.line > 0) physLoc.region = { startLine: ev.line }
    locs.push({ physicalLocation: physLoc })
  }
  if (locs.length === 0) {
    locs.push({ physicalLocation: { artifactLocation: { uri: '.', uriBaseId: '%SRCROOT%' } } })
  }
  return locs
}

/**
 * Build a SARIF 2.1.0 document from scored verdicts.
 * Pure function: output is deterministic for the same inputs.
 */
export function buildSarif(results: VerdictResult[], opts: VexOptions): SarifDocument {
  const version = resolvedVersion(opts)

  const seen = new Set<string>()
  const rules: SarifRule[] = []
  for (const r of results) {
    if (!seen.has(r.cveId)) {
      seen.add(r.cveId)
      rules.push({
        id: r.cveId,
        name: r.cveId.replace(/-/g, '_'),
        shortDescription: { text: `${r.cveId} affects ${r.package}` },
        properties: { tags: ['security', 'supply-chain'] },
      })
    }
  }

  const sarifResults: SarifResultEntry[] = results.map((r) => ({
    ruleId: r.cveId,
    level: sarifLevel(r.verdict),
    message: { text: impactStatement(r) },
    locations: sarifLocations(r),
    properties: {
      verdict: r.verdict,
      confidence: r.confidence,
      epssScore: r.epssScore,
      cvssScore: r.cvssScore,
      package: r.package,
      version: r.version,
    },
  }))

  return {
    $schema:
      'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Reachble',
            version,
            informationUri: 'https://github.com/reachble/reachble',
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  }
}
