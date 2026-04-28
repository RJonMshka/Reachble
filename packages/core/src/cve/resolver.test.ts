import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ResolvedPackage } from '../types.js'
import { resolveCves } from './resolver.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIXTURES = path.resolve(__dirname, '../../fixtures/osv')

let tmpDir: string

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachble-resolver-test-'))
})

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

function mockFetch(responses: Array<{ status: number; body: unknown }>) {
  let call = 0
  vi.stubGlobal(
    'fetch',
    vi.fn((_url: string, _init?: RequestInit) => {
      const r = responses[call++ % responses.length] ?? { status: 200, body: { results: [] } }
      return Promise.resolve({
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        statusText: r.status === 200 ? 'OK' : 'Error',
        headers: { get: (_h: string) => null },
        json: () => Promise.resolve(r.body),
      } as Response)
    }),
  )
}

const lodash4_17_19: ResolvedPackage = {
  name: 'lodash',
  version: '4.17.19',
  depth: 1,
  dependents: ['.'],
  devOnly: false,
  lockfileSource: 'npm',
}

const express4_18: ResolvedPackage = {
  name: 'express',
  version: '4.18.2',
  depth: 1,
  dependents: ['.'],
  devOnly: false,
  lockfileSource: 'npm',
}

describe('resolveCves', () => {
  it('returns an empty map for an empty package list', async () => {
    const result = await resolveCves([], { cacheDir: tmpDir })
    expect(result.size).toBe(0)
  })

  it('maps OSV vulns to CveRecords with correct shape', async () => {
    const osvFixture: unknown = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, 'batch-response.json'), 'utf8'),
    )
    const epssEmpty = { status: 'OK', data: [] }

    mockFetch([
      { status: 200, body: osvFixture },
      { status: 200, body: epssEmpty },
    ])

    const result = await resolveCves([lodash4_17_19], { cacheDir: tmpDir })

    const records = result.get('lodash@4.17.19')
    expect(records).toBeDefined()
    expect(records?.length).toBeGreaterThan(0)

    const record = records?.[0]
    expect(record?.id).toBe('CVE-2021-23337')
    expect(record?.severity).toBe('HIGH')
    expect(record?.affectedVersionRange).toBe('<4.17.21')
    expect(record?.affectedSymbols).toHaveLength(1)
    expect(record?.affectedSymbols[0]?.name).toBe('template')
    expect(record?.fixCommitUrls.length).toBeGreaterThan(0)
    expect(record?.publishedAt).toBeInstanceOf(Date)
  })

  it('returns empty records for packages with no vulns', async () => {
    const noVulns = { results: [{ vulns: [] }] }
    const epssEmpty = { status: 'OK', data: [] }

    mockFetch([
      { status: 200, body: noVulns },
      { status: 200, body: epssEmpty },
    ])

    const result = await resolveCves([express4_18], { cacheDir: tmpDir })
    expect(result.get('express@4.18.2')).toEqual([])
  })

  it('is deterministic — two runs produce identical output', async () => {
    const osvFixture: unknown = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, 'batch-response.json'), 'utf8'),
    )
    const epssEmpty = { status: 'OK', data: [] }

    // First run — populates cache
    mockFetch([
      { status: 200, body: osvFixture },
      { status: 200, body: epssEmpty },
    ])
    const run1 = await resolveCves([lodash4_17_19], { cacheDir: tmpDir })

    // Second run — served from cache, no fetch calls needed
    mockFetch([])
    const run2 = await resolveCves([lodash4_17_19], { cacheDir: tmpDir, offline: true })

    expect(JSON.stringify([...run1])).toBe(JSON.stringify([...run2]))
  })

  it('throws in offline mode when cache is empty', async () => {
    await expect(resolveCves([lodash4_17_19], { cacheDir: tmpDir, offline: true })).rejects.toThrow(
      'Offline mode',
    )
  })

  it('applies EPSS scores when available', async () => {
    const osvFixture: unknown = JSON.parse(
      fs.readFileSync(path.join(FIXTURES, 'batch-response.json'), 'utf8'),
    )
    const epssResponse = {
      status: 'OK',
      data: [{ cve: 'CVE-2021-23337', epss: '0.0152', percentile: '0.85', date: '2024-01-01' }],
    }

    mockFetch([
      { status: 200, body: osvFixture },
      { status: 200, body: epssResponse },
    ])

    const result = await resolveCves([lodash4_17_19], { cacheDir: tmpDir })
    const record = result.get('lodash@4.17.19')?.[0]
    expect(record?.epssScore).toBeCloseTo(0.0152, 4)
  })
})
