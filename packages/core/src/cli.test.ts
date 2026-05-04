import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { readProjectMeta, shouldFail } from './cli.js'
import type { FailOnLevel } from './config.js'
import type { VerdictResult } from './types.js'

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeResult(verdict: VerdictResult['verdict']): VerdictResult {
  return {
    package: 'pkg',
    version: '1.0.0',
    cveId: 'CVE-2024-0001',
    verdict,
    confidence: 'high',
    reason: 'test',
    evidence: [],
    cvssScore: 5.0,
    epssScore: 0.01,
  }
}

const TMP = join(import.meta.dirname, '__cli_test_tmp__')
const CLI = resolve(import.meta.dirname, '../dist/cli.cjs')

beforeEach(() => {
  mkdirSync(TMP, { recursive: true })
})
afterEach(() => {
  rmSync(TMP, { recursive: true, force: true })
})

// ── shouldFail ────────────────────────────────────────────────────────────────

describe('shouldFail', () => {
  const cases: Array<[FailOnLevel, VerdictResult['verdict'], boolean]> = [
    ['critical', 'CRITICAL', true],
    ['critical', 'HIGH', false],
    ['critical', 'LOW', false],
    ['critical', 'SAFE', false],
    ['high', 'CRITICAL', true],
    ['high', 'HIGH', true],
    ['high', 'LOW', false],
    ['high', 'SAFE', false],
    ['medium', 'CRITICAL', true],
    ['medium', 'HIGH', true],
    ['medium', 'LOW', true],
    ['medium', 'SAFE', false],
  ]

  for (const [level, verdict, expected] of cases) {
    it(`level=${level} verdict=${verdict} → ${String(expected)}`, () => {
      expect(shouldFail([makeResult(verdict)], level)).toBe(expected)
    })
  }

  it('returns false for empty results at any level', () => {
    expect(shouldFail([], 'critical')).toBe(false)
    expect(shouldFail([], 'high')).toBe(false)
    expect(shouldFail([], 'medium')).toBe(false)
  })

  it('returns true when any result triggers the threshold', () => {
    expect(shouldFail([makeResult('SAFE'), makeResult('CRITICAL')], 'critical')).toBe(true)
  })

  it('stops at first match (does not accumulate)', () => {
    const many = Array.from({ length: 100 }, () => makeResult('HIGH'))
    expect(shouldFail(many, 'high')).toBe(true)
  })
})

// ── readProjectMeta ───────────────────────────────────────────────────────────

describe('readProjectMeta', () => {
  it('returns dir as name when no package.json exists', () => {
    const result = readProjectMeta(TMP)
    expect(result.name).toBe(TMP)
    expect(result.version).toBeUndefined()
  })

  it('reads name and version from package.json', () => {
    writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 'my-app', version: '2.3.4' }))
    expect(readProjectMeta(TMP)).toEqual({ name: 'my-app', version: '2.3.4' })
  })

  it('reads name without version when version field is absent', () => {
    writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 'my-app' }))
    expect(readProjectMeta(TMP)).toEqual({ name: 'my-app' })
  })

  it('falls back to dir when name is not a string', () => {
    writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 42, version: '1.0.0' }))
    const result = readProjectMeta(TMP)
    expect(result.name).toBe(TMP)
  })

  it('returns dir as name when package.json is malformed JSON', () => {
    writeFileSync(join(TMP, 'package.json'), 'not json {{{')
    expect(readProjectMeta(TMP).name).toBe(TMP)
  })
})

// ── CLI subprocess ─────────────────────────────────────────────────────────────

describe.skipIf(!existsSync(CLI))('CLI binary', () => {
  it('exits 1 with an error message for unknown --format', () => {
    const r = spawnSync('node', [CLI, 'scan', '--format', 'xml'], { encoding: 'utf8' })
    expect(r.status).toBe(1)
    expect(r.stderr + r.stdout).toMatch(/xml/i)
  })

  it('exits 1 with an error message for unknown --fail-on', () => {
    const r = spawnSync('node', [CLI, 'scan', '--fail-on', 'severe'], { encoding: 'utf8' })
    expect(r.status).toBe(1)
    expect(r.stderr + r.stdout).toMatch(/severe/i)
  })

  it('exits 1 with a lockfile error when project has no lockfile', () => {
    const r = spawnSync('node', [CLI, 'scan', '--path', TMP, '--format', 'table'], {
      encoding: 'utf8',
      timeout: 15_000,
    })
    expect(r.status).toBe(1)
    expect(r.stderr + r.stdout).toMatch(/lockfile|error/i)
  })
})
