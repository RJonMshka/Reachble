import { describe, expect, it } from 'vitest'
import type { VerdictResult } from './types.js'
import { buildCycloneDxVex, buildJsonV1, buildOpenVex, buildSarif, type VexOptions } from './vex.js'

// ── Fixtures ──────────────────────────────────────────────────────────────────

const FIXED_OPTS: VexOptions = {
  projectName: 'my-app',
  projectVersion: '1.0.0',
  toolVersion: '0.1.0',
  timestamp: '2026-04-26T00:00:00.000Z',
}

const safeAbsent: VerdictResult = {
  cveId: 'CVE-2021-23369',
  package: 'handlebars',
  version: '4.7.6',
  verdict: 'SAFE',
  confidence: 'high',
  reason: 'handlebars is not imported in any analyzed file',
  evidence: [
    {
      type: 'import',
      description: 'Package handlebars not found in import graph',
    },
  ],
  epssScore: 0.01,
  cvssScore: 9.8,
  fixedIn: '4.7.7',
}

const safeSymbol: VerdictResult = {
  cveId: 'CVE-2021-23370',
  package: 'handlebars',
  version: '4.7.6',
  verdict: 'SAFE',
  confidence: 'high',
  reason: 'Vulnerable symbol(s) not imported from handlebars',
  evidence: [
    {
      type: 'import',
      description:
        'handlebars imported but none of the vulnerable symbols (compile) appear in any import statement',
    },
  ],
  epssScore: 0.01,
  cvssScore: 7.5,
}

const safeSuppressed: VerdictResult = {
  cveId: 'CVE-2020-28500',
  package: 'lodash',
  version: '4.17.20',
  verdict: 'SAFE',
  confidence: 'high',
  reason: 'Suppressed by .reachble.json: template() never called — reviewed 2026-04-25',
  evidence: [
    {
      type: 'suppression',
      description:
        'User suppression: template() never called — reviewed 2026-04-25 (reviewed by rajat)',
    },
  ],
  epssScore: 0.05,
  cvssScore: 7.5,
}

const lowResult: VerdictResult = {
  cveId: 'CVE-2021-23337',
  package: 'lodash',
  version: '4.17.20',
  verdict: 'LOW',
  confidence: 'medium',
  reason: 'Vulnerable symbol(s) imported from lodash',
  evidence: [
    {
      type: 'import',
      description: 'Vulnerable symbol(s) template imported from lodash at src/utils.ts:5',
      file: 'src/utils.ts',
      line: 5,
      caveat: 'import-level analysis only — V1 call graph will refine reachability',
    },
  ],
  epssScore: 0.15,
  cvssScore: 7.2,
}

const highResult: VerdictResult = {
  cveId: 'CVE-2022-31129',
  package: 'moment',
  version: '2.29.3',
  verdict: 'HIGH',
  confidence: 'medium',
  reason: 'Vulnerable symbol(s) imported from moment',
  evidence: [
    {
      type: 'import',
      description: 'Vulnerable symbol(s) parseZone imported from moment at src/api/dates.ts:3',
      file: 'src/api/dates.ts',
      line: 3,
      caveat: 'import-level analysis only — V1 call graph will refine reachability',
    },
  ],
  epssScore: 0.65,
  cvssScore: 7.5,
}

const ALL_RESULTS: VerdictResult[] = [safeAbsent, safeSymbol, safeSuppressed, lowResult, highResult]

// ── CycloneDX VEX ─────────────────────────────────────────────────────────────

describe('buildCycloneDxVex', () => {
  it('sets top-level bomFormat and specVersion', () => {
    const doc = buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS)
    expect(doc.bomFormat).toBe('CycloneDX')
    expect(doc.specVersion).toBe('1.5')
  })

  it('includes serialNumber as urn:uuid', () => {
    const doc = buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS)
    expect(doc.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/)
  })

  it('maps SAFE (absent) → not_affected + code_not_present', () => {
    const doc = buildCycloneDxVex([safeAbsent], FIXED_OPTS)
    const vuln = doc.vulnerabilities[0]
    expect(vuln?.analysis.state).toBe('not_affected')
    expect(vuln?.analysis.justification).toBe('code_not_present')
  })

  it('maps SAFE (symbol unused) → not_affected + code_not_reachable', () => {
    const doc = buildCycloneDxVex([safeSymbol], FIXED_OPTS)
    const vuln = doc.vulnerabilities[0]
    expect(vuln?.analysis.state).toBe('not_affected')
    expect(vuln?.analysis.justification).toBe('code_not_reachable')
  })

  it('maps SAFE (suppression) → not_affected + protected_by_mitigations', () => {
    const doc = buildCycloneDxVex([safeSuppressed], FIXED_OPTS)
    const vuln = doc.vulnerabilities[0]
    expect(vuln?.analysis.state).toBe('not_affected')
    expect(vuln?.analysis.justification).toBe('protected_by_mitigations')
  })

  it('maps LOW → exploitable, no justification', () => {
    const doc = buildCycloneDxVex([lowResult], FIXED_OPTS)
    const vuln = doc.vulnerabilities[0]
    expect(vuln?.analysis.state).toBe('exploitable')
    expect(vuln?.analysis.justification).toBeUndefined()
  })

  it('maps HIGH → exploitable', () => {
    const doc = buildCycloneDxVex([highResult], FIXED_OPTS)
    expect(doc.vulnerabilities[0]?.analysis.state).toBe('exploitable')
  })

  it('includes CVSS rating when cvssScore > 0', () => {
    const doc = buildCycloneDxVex([safeAbsent], FIXED_OPTS)
    expect(doc.vulnerabilities[0]?.ratings).toHaveLength(1)
    expect(doc.vulnerabilities[0]?.ratings?.[0]?.score).toBe(9.8)
  })

  it('omits ratings when cvssScore is 0', () => {
    const noCvss: VerdictResult = { ...safeAbsent, cvssScore: 0 }
    const doc = buildCycloneDxVex([noCvss], FIXED_OPTS)
    expect(doc.vulnerabilities[0]?.ratings).toBeUndefined()
  })

  it('sets unaffected/affected version status correctly', () => {
    const doc = buildCycloneDxVex([safeAbsent, lowResult], FIXED_OPTS)
    expect(doc.vulnerabilities[0]?.affects[0]?.versions[0]?.status).toBe('unaffected')
    expect(doc.vulnerabilities[1]?.affects[0]?.versions[0]?.status).toBe('affected')
  })

  it('uses NVD source for CVE- ids, OSV for others', () => {
    const osvResult: VerdictResult = { ...safeAbsent, cveId: 'GHSA-abc-def-1234' }
    const doc = buildCycloneDxVex([osvResult], FIXED_OPTS)
    expect(doc.vulnerabilities[0]?.source.name).toBe('GHSA')
  })

  it('includes project version when provided', () => {
    const doc = buildCycloneDxVex([], FIXED_OPTS)
    expect(doc.metadata.component.version).toBe('1.0.0')
  })

  it('omits project version when not provided', () => {
    const doc = buildCycloneDxVex([], { ...FIXED_OPTS, projectVersion: undefined })
    expect(doc.metadata.component.version).toBeUndefined()
  })

  it('is deterministic: same inputs → identical output', () => {
    const out1 = JSON.stringify(buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS))
    const out2 = JSON.stringify(buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS))
    expect(out1).toBe(out2)
  })

  it('matches golden file', async () => {
    const out = JSON.stringify(buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS), null, 2)
    await expect(out).toMatchFileSnapshot('../fixtures/golden/cyclonedx-vex.json')
  })
})

// ── OpenVEX ───────────────────────────────────────────────────────────────────

describe('buildOpenVex', () => {
  it('sets @context and version', () => {
    const doc = buildOpenVex(ALL_RESULTS, FIXED_OPTS)
    expect(doc['@context']).toBe('https://openvex.dev/ns/v0.2.0')
    expect(doc.version).toBe(1)
  })

  it('@id is a deterministic URL containing content hash', () => {
    const doc = buildOpenVex(ALL_RESULTS, FIXED_OPTS)
    expect(doc['@id']).toMatch(/^https:\/\/github\.com\/RJonMshka\/reachble\/vex\/[0-9a-f]{64}$/)
  })

  it('maps SAFE (absent) → not_affected + vulnerable_code_not_present', () => {
    const doc = buildOpenVex([safeAbsent], FIXED_OPTS)
    const stmt = doc.statements[0]
    expect(stmt?.status).toBe('not_affected')
    expect(stmt?.justification).toBe('vulnerable_code_not_present')
  })

  it('maps SAFE (symbol unused) → not_affected + vulnerable_code_not_in_execute_path', () => {
    const doc = buildOpenVex([safeSymbol], FIXED_OPTS)
    const stmt = doc.statements[0]
    expect(stmt?.status).toBe('not_affected')
    expect(stmt?.justification).toBe('vulnerable_code_not_in_execute_path')
  })

  it('maps SAFE (suppression) → not_affected + inline_mitigations_already_exist', () => {
    const doc = buildOpenVex([safeSuppressed], FIXED_OPTS)
    const stmt = doc.statements[0]
    expect(stmt?.status).toBe('not_affected')
    expect(stmt?.justification).toBe('inline_mitigations_already_exist')
  })

  it('maps LOW/HIGH → affected, no justification', () => {
    const doc = buildOpenVex([lowResult, highResult], FIXED_OPTS)
    for (const stmt of doc.statements) {
      expect(stmt.status).toBe('affected')
      expect(stmt.justification).toBeUndefined()
    }
  })

  it('uses purl for products', () => {
    const doc = buildOpenVex([lowResult], FIXED_OPTS)
    expect(doc.statements[0]?.products[0]?.['@id']).toBe('pkg:npm/lodash@4.17.20')
  })

  it('uses correct CVE URI', () => {
    const doc = buildOpenVex([lowResult], FIXED_OPTS)
    expect(doc.statements[0]?.vulnerability['@id']).toBe(
      'https://www.cve.org/CVERecord?id=CVE-2021-23337',
    )
  })

  it('impact_statement includes reason and evidence', () => {
    const doc = buildOpenVex([lowResult], FIXED_OPTS)
    const stmt = doc.statements[0]
    expect(stmt?.impact_statement).toContain('Vulnerable symbol(s) imported from lodash')
    expect(stmt?.impact_statement).toContain('import-level analysis only')
  })

  it('is deterministic: same inputs → identical output', () => {
    const out1 = JSON.stringify(buildOpenVex(ALL_RESULTS, FIXED_OPTS))
    const out2 = JSON.stringify(buildOpenVex(ALL_RESULTS, FIXED_OPTS))
    expect(out1).toBe(out2)
  })

  it('matches golden file', async () => {
    const out = JSON.stringify(buildOpenVex(ALL_RESULTS, FIXED_OPTS), null, 2)
    await expect(out).toMatchFileSnapshot('../fixtures/golden/openvex.json')
  })
})

// ── JSON v1 ───────────────────────────────────────────────────────────────────

describe('buildJsonV1', () => {
  it('sets version to v1', () => {
    const doc = buildJsonV1(ALL_RESULTS, FIXED_OPTS)
    expect(doc.version).toBe('v1')
  })

  it('summary counts match results', () => {
    const doc = buildJsonV1(ALL_RESULTS, FIXED_OPTS)
    expect(doc.summary.total).toBe(5)
    expect(doc.summary.safe).toBe(3)
    expect(doc.summary.low).toBe(1)
    expect(doc.summary.high).toBe(1)
    expect(doc.summary.critical).toBe(0)
  })

  it('verdicts array is the same reference content', () => {
    const doc = buildJsonV1(ALL_RESULTS, FIXED_OPTS)
    expect(doc.verdicts).toHaveLength(ALL_RESULTS.length)
    expect(doc.verdicts[0]?.cveId).toBe(ALL_RESULTS[0]?.cveId)
  })

  it('includes project version when provided', () => {
    const doc = buildJsonV1(ALL_RESULTS, FIXED_OPTS)
    expect(doc.project.version).toBe('1.0.0')
  })

  it('omits project version when not provided', () => {
    const doc = buildJsonV1(ALL_RESULTS, { ...FIXED_OPTS, projectVersion: undefined })
    expect(doc.project.version).toBeUndefined()
  })

  it('is deterministic: same inputs → identical output', () => {
    const out1 = JSON.stringify(buildJsonV1(ALL_RESULTS, FIXED_OPTS))
    const out2 = JSON.stringify(buildJsonV1(ALL_RESULTS, FIXED_OPTS))
    expect(out1).toBe(out2)
  })

  it('matches golden file', async () => {
    const out = JSON.stringify(buildJsonV1(ALL_RESULTS, FIXED_OPTS), null, 2)
    await expect(out).toMatchFileSnapshot('../fixtures/golden/reachble-v1.json')
  })
})

// ── SARIF 2.1.0 ───────────────────────────────────────────────────────────────

describe('buildSarif', () => {
  it('sets version and schema', () => {
    const doc = buildSarif(ALL_RESULTS, FIXED_OPTS)
    expect(doc.version).toBe('2.1.0')
    expect(doc.$schema).toContain('sarif')
  })

  it('maps verdict levels correctly', () => {
    const doc = buildSarif(ALL_RESULTS, FIXED_OPTS)
    const results = doc.runs[0]?.results ?? []
    const byId = Object.fromEntries(results.map((r) => [r.ruleId, r.level]))
    expect(byId['CVE-2021-23369']).toBe('none') // SAFE absent
    expect(byId['CVE-2021-23370']).toBe('none') // SAFE symbol
    expect(byId['CVE-2020-28500']).toBe('none') // SAFE suppressed
    expect(byId['CVE-2021-23337']).toBe('note') // LOW
    expect(byId['CVE-2022-31129']).toBe('warning') // HIGH
  })

  it('de-duplicates rules for the same CVE id', () => {
    const dup: VerdictResult = { ...lowResult, package: 'other-pkg' }
    const doc = buildSarif([lowResult, dup], FIXED_OPTS)
    const rules = doc.runs[0]?.tool.driver.rules ?? []
    expect(rules.filter((r) => r.id === 'CVE-2021-23337')).toHaveLength(1)
  })

  it('includes file location from evidence', () => {
    const doc = buildSarif([lowResult], FIXED_OPTS)
    const loc = doc.runs[0]?.results[0]?.locations[0]
    expect(loc?.physicalLocation.artifactLocation.uri).toBe('src/utils.ts')
    expect(loc?.physicalLocation.region?.startLine).toBe(5)
  })

  it('falls back to "." location when evidence has no file', () => {
    const doc = buildSarif([safeAbsent], FIXED_OPTS)
    const loc = doc.runs[0]?.results[0]?.locations[0]
    expect(loc?.physicalLocation.artifactLocation.uri).toBe('.')
  })

  it('omits region when line is 0', () => {
    const zeroLine: VerdictResult = {
      ...lowResult,
      evidence: [{ type: 'import', description: 'test', file: 'src/x.ts', line: 0 }],
    }
    const doc = buildSarif([zeroLine], FIXED_OPTS)
    const loc = doc.runs[0]?.results[0]?.locations[0]
    expect(loc?.physicalLocation.region).toBeUndefined()
  })

  it('properties include verdict and scores', () => {
    const doc = buildSarif([lowResult], FIXED_OPTS)
    const props = doc.runs[0]?.results[0]?.properties
    expect(props?.verdict).toBe('LOW')
    expect(props?.epssScore).toBe(0.15)
    expect(props?.cvssScore).toBe(7.2)
  })

  it('is deterministic: same inputs → identical output', () => {
    const out1 = JSON.stringify(buildSarif(ALL_RESULTS, FIXED_OPTS))
    const out2 = JSON.stringify(buildSarif(ALL_RESULTS, FIXED_OPTS))
    expect(out1).toBe(out2)
  })

  it('matches golden file', async () => {
    const out = JSON.stringify(buildSarif(ALL_RESULTS, FIXED_OPTS), null, 2)
    await expect(out).toMatchFileSnapshot('../fixtures/golden/sarif.json')
  })
})

// ── Cross-format determinism ──────────────────────────────────────────────────

describe('cross-format determinism', () => {
  it('different result orderings produce different CycloneDX serial numbers', () => {
    const reversed = [...ALL_RESULTS].reverse()
    const doc1 = buildCycloneDxVex(ALL_RESULTS, FIXED_OPTS)
    const doc2 = buildCycloneDxVex(reversed, FIXED_OPTS)
    expect(doc1.serialNumber).not.toBe(doc2.serialNumber)
  })

  it('different result orderings produce different OpenVEX @id', () => {
    const reversed = [...ALL_RESULTS].reverse()
    const doc1 = buildOpenVex(ALL_RESULTS, FIXED_OPTS)
    const doc2 = buildOpenVex(reversed, FIXED_OPTS)
    expect(doc1['@id']).not.toBe(doc2['@id'])
  })

  it('empty results produces valid CycloneDX document', () => {
    const doc = buildCycloneDxVex([], FIXED_OPTS)
    expect(doc.vulnerabilities).toHaveLength(0)
    expect(doc.bomFormat).toBe('CycloneDX')
  })

  it('scoped package produces correct purl', () => {
    const scoped: VerdictResult = { ...safeAbsent, package: '@babel/core', version: '7.21.0' }
    const doc = buildOpenVex([scoped], FIXED_OPTS)
    expect(doc.statements[0]?.products[0]?.['@id']).toBe('pkg:npm/%40babel/core@7.21.0')
  })
})
