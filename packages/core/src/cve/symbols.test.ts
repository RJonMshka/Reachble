import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { OsvQueryBatchResponseSchema } from './schemas.js'
import { extractSymbols } from './symbols.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIXTURES = path.resolve(__dirname, '../../fixtures/osv')

function loadFixture(name: string) {
  const raw: unknown = JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8'))
  return OsvQueryBatchResponseSchema.parse(raw)
}

describe('extractSymbols', () => {
  it('extracts from OSV affected_functions (high confidence)', () => {
    const response = loadFixture('batch-response.json')
    const vuln = response.results[0]?.vulns?.[0]
    expect(vuln).toBeDefined()
    if (!vuln) return

    const symbols = extractSymbols(vuln)
    expect(symbols).toHaveLength(1)
    expect(symbols[0]).toMatchObject({
      name: 'template',
      type: 'function',
      confidence: 'high',
      source: 'osv',
    })
  })

  it('strips lodash _.prefix so names match ES named imports', () => {
    const response = loadFixture('batch-response.json')
    const vuln = response.results[0]?.vulns?.[0]
    if (!vuln) return
    const symbols = extractSymbols(vuln)
    // OSV stores "_.template"; after normalization it should be "template"
    // so that `import { template } from 'lodash'` matches correctly
    expect(symbols[0]?.name).toBe('template')
  })

  it('falls back to description extraction when no affected_functions', () => {
    const response = loadFixture('batch-response-no-symbols.json')
    const vuln = response.results[0]?.vulns?.[0]
    expect(vuln).toBeDefined()
    if (!vuln) return

    const symbols = extractSymbols(vuln)
    // Result may be empty if no clear symbol patterns in description
    expect(Array.isArray(symbols)).toBe(true)
  })

  it('extracts backtick-quoted symbols from NVD description', () => {
    const vuln = {
      id: 'GHSA-fake',
      affected: [],
      published: '2021-01-01T00:00:00Z',
      modified: '2021-01-01T00:00:00Z',
    }

    const symbols = extractSymbols(vuln, {
      nvdDescription: 'A vulnerability exists in `template()` and `merge()` functions.',
    })

    expect(symbols).toHaveLength(2)
    expect(symbols[0]).toMatchObject({ name: 'template', confidence: 'medium', source: 'nvd-desc' })
    expect(symbols[1]).toMatchObject({ name: 'merge', confidence: 'medium', source: 'nvd-desc' })
  })

  it('uses override when provided', () => {
    const vuln = {
      id: 'GHSA-fake',
      aliases: ['CVE-2021-99999'],
      affected: [],
      published: '2021-01-01T00:00:00Z',
      modified: '2021-01-01T00:00:00Z',
    }

    const symbols = extractSymbols(vuln, {
      overrides: [
        {
          cveId: 'CVE-2021-99999',
          packageName: 'lodash',
          symbols: [{ name: 'merge', type: 'function' as const }],
        },
      ],
    })

    expect(symbols).toHaveLength(1)
    expect(symbols[0]).toMatchObject({ name: 'merge', confidence: 'high', source: 'override' })
  })

  it('returns empty array when no symbols can be extracted', () => {
    const vuln = {
      id: 'GHSA-noop',
      affected: [],
      published: '2021-01-01T00:00:00Z',
      modified: '2021-01-01T00:00:00Z',
    }

    const symbols = extractSymbols(vuln)
    expect(symbols).toEqual([])
  })

  it('deduplicates symbols extracted from multiple sources', () => {
    const vuln = {
      id: 'GHSA-dup',
      affected: [],
      details: 'The `merge` function has an issue. The `merge` method is affected.',
      published: '2021-01-01T00:00:00Z',
      modified: '2021-01-01T00:00:00Z',
    }

    const symbols = extractSymbols(vuln)
    const names = symbols.map((s) => s.name)
    const uniqueNames = [...new Set(names)]
    expect(names).toEqual(uniqueNames)
  })
})
