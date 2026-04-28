/**
 * M10 — Demo integration test.
 *
 * Validates the end-to-end pipeline (lockfile → import graph → verdict → VEX)
 * on the fixtures/demo-express app without any network calls.
 *
 * Expected outcomes:
 *   CVE-2021-23337  lodash template  → LOW   (template IS imported)
 *   CVE-2020-28500  lodash trim/etc  → SAFE  (trim/trimStart/trimEnd NOT imported)
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { buildImportGraph } from './analysis/import.js'
import { detectAndParse } from './lockfile/detect.js'
import { OsvQueryBatchResponseSchema } from './cve/schemas.js'
import { scoreVerdicts } from './verdict.js'
import { buildCycloneDxVex } from './vex.js'
import type { CveRecord, ResolvedPackage } from './types.js'
import { extractSymbols } from './cve/symbols.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEMO_DIR = path.resolve(__dirname, '../fixtures/demo-express')
const OSV_FIXTURE = path.resolve(__dirname, '../fixtures/osv/demo-lodash-batch-response.json')

function loadDemoCveMap(packages: ResolvedPackage[]): Map<string, CveRecord[]> {
  const raw: unknown = JSON.parse(readFileSync(OSV_FIXTURE, 'utf8'))
  const response = OsvQueryBatchResponseSchema.parse(raw)

  const lodashPkg = packages.find((p) => p.name === 'lodash')
  if (!lodashPkg) return new Map()

  const vulns = response.results[0]?.vulns ?? []
  const records: CveRecord[] = vulns.map((vuln) => {
    const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id
    const npmAffected = vuln.affected.find((a) => a.package.ecosystem === 'npm')
    const severity = npmAffected?.database_specific?.severity ?? 'MEDIUM'
    const cvssScore = severity === 'HIGH' ? 7.5 : severity === 'CRITICAL' ? 9.5 : 5.0
    const symbols = extractSymbols(vuln)
    return {
      id: cveId,
      aliases: (vuln.aliases ?? []).filter((a) => a !== cveId),
      severity: severity as CveRecord['severity'],
      cvssScore,
      epssScore: 0.05,
      affectedVersionRange: '<4.17.21',
      affectedSymbols: symbols,
      fixCommitUrls: (vuln.references ?? []).filter((r) => r.type === 'FIX').map((r) => r.url),
      description: vuln.details ?? vuln.summary ?? '',
      publishedAt: new Date(vuln.published),
      fixedIn: '4.17.21',
    }
  })

  return new Map([[`${lodashPkg.name}@${lodashPkg.version}`, records]])
}

describe('M10 — demo-express integration', () => {
  it('parses the lockfile and finds lodash@4.17.18', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const lodash = packages.find((p) => p.name === 'lodash')
    expect(lodash).toBeDefined()
    expect(lodash?.version).toBe('4.17.18')
    expect(lodash?.devOnly).toBe(false)
  })

  it('builds import graph and finds template imported from lodash', () => {
    const graph = buildImportGraph(DEMO_DIR)
    const allRecords = [...graph.values()].flat()
    const lodashImports = allRecords.filter((r) => r.package === 'lodash')
    const symbols = lodashImports.flatMap((r) => r.symbols)
    expect(symbols).toContain('template')
    // Trim, merge, set, etc. are NOT imported
    expect(symbols).not.toContain('trim')
    expect(symbols).not.toContain('trimStart')
    expect(symbols).not.toContain('trimEnd')
    expect(symbols).not.toContain('merge')
  })

  it('CVE-2021-23337 (template) → LOW because template is imported', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const graph = buildImportGraph(DEMO_DIR)
    const cveMap = loadDemoCveMap(packages)

    const results = scoreVerdicts(packages, cveMap, graph)

    const templateCve = results.find((r) => r.cveId === 'CVE-2021-23337')
    expect(templateCve).toBeDefined()
    expect(templateCve?.verdict).toBe('LOW')
    expect(templateCve?.evidence[0]?.description).toMatch(/template/)
  })

  it('CVE-2020-28500 (trim/etc) → SAFE because trim is not imported', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const graph = buildImportGraph(DEMO_DIR)
    const cveMap = loadDemoCveMap(packages)

    const results = scoreVerdicts(packages, cveMap, graph)

    const trimCve = results.find((r) => r.cveId === 'CVE-2020-28500')
    expect(trimCve).toBeDefined()
    expect(trimCve?.verdict).toBe('SAFE')
  })

  it('VEX for CVE-2020-28500 has status not_affected', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const graph = buildImportGraph(DEMO_DIR)
    const cveMap = loadDemoCveMap(packages)
    const results = scoreVerdicts(packages, cveMap, graph)

    const cdx = buildCycloneDxVex(results, { projectName: 'demo-express', projectVersion: '1.0.0' })
    const trimStatement = cdx.vulnerabilities.find(
      (v: { id?: string }) => v.id === 'CVE-2020-28500',
    )
    expect(trimStatement?.analysis.state).toBe('not_affected')
  })

  it('VEX for CVE-2021-23337 has status exploitable', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const graph = buildImportGraph(DEMO_DIR)
    const cveMap = loadDemoCveMap(packages)
    const results = scoreVerdicts(packages, cveMap, graph)

    const cdx = buildCycloneDxVex(results, { projectName: 'demo-express', projectVersion: '1.0.0' })
    const templateStatement = cdx.vulnerabilities.find(
      (v: { id?: string }) => v.id === 'CVE-2021-23337',
    )
    expect(templateStatement?.analysis.state).not.toBe('not_affected')
  })

  it('output is deterministic across two runs', async () => {
    const packages = await detectAndParse(DEMO_DIR)
    const graph = buildImportGraph(DEMO_DIR)
    const cveMap = loadDemoCveMap(packages)

    const run1 = scoreVerdicts(packages, cveMap, graph)
    const run2 = scoreVerdicts(packages, cveMap, graph)
    expect(JSON.stringify(run1)).toBe(JSON.stringify(run2))
  })
})
