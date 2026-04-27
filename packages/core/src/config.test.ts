import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { loadConfig } from './config.js'
import { ConfigError } from './errors.js'

const TMP = join(import.meta.dirname, '__config_test_tmp__')

beforeEach(() => {
  mkdirSync(TMP, { recursive: true })
})
afterEach(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('loadConfig', () => {
  it('returns empty config when no config files exist', () => {
    expect(loadConfig(TMP)).toEqual({})
  })

  it('loads suppressions from .reachble.json', () => {
    writeFileSync(
      join(TMP, '.reachble.json'),
      JSON.stringify({
        suppressions: [
          { cveId: 'CVE-2024-1234', package: 'lodash', reason: 'reviewed — not exploitable' },
        ],
      }),
    )
    const config = loadConfig(TMP)
    expect(config.suppressions).toHaveLength(1)
    expect(config.suppressions?.[0]?.cveId).toBe('CVE-2024-1234')
    expect(config.suppressions?.[0]?.reason).toBe('reviewed — not exploitable')
  })

  it('loads suppressions from package.json "reachble" key', () => {
    writeFileSync(
      join(TMP, 'package.json'),
      JSON.stringify({
        name: 'my-app',
        reachble: {
          suppressions: [
            {
              cveId: 'CVE-2024-9999',
              package: 'express',
              reason: 'mitigated by WAF',
              reviewedBy: 'alice',
            },
          ],
        },
      }),
    )
    const config = loadConfig(TMP)
    expect(config.suppressions?.[0]?.cveId).toBe('CVE-2024-9999')
    expect(config.suppressions?.[0]?.reviewedBy).toBe('alice')
  })

  it('prefers .reachble.json over package.json', () => {
    writeFileSync(
      join(TMP, '.reachble.json'),
      JSON.stringify({ suppressions: [{ cveId: 'A', package: 'p', reason: 'from standalone' }] }),
    )
    writeFileSync(
      join(TMP, 'package.json'),
      JSON.stringify({
        reachble: { suppressions: [{ cveId: 'B', package: 'p', reason: 'from pkgjson' }] },
      }),
    )
    const config = loadConfig(TMP)
    expect(config.suppressions?.[0]?.cveId).toBe('A')
  })

  it('throws ConfigError on malformed JSON in .reachble.json', () => {
    writeFileSync(join(TMP, '.reachble.json'), '{bad json}')
    expect(() => loadConfig(TMP)).toThrowError(ConfigError)
  })

  it('throws ConfigError when suppression is missing reason', () => {
    writeFileSync(
      join(TMP, '.reachble.json'),
      JSON.stringify({ suppressions: [{ cveId: 'CVE-x', package: 'pkg', reason: '' }] }),
    )
    expect(() => loadConfig(TMP)).toThrowError(ConfigError)
  })

  it('throws ConfigError for invalid schema in package.json reachble key', () => {
    writeFileSync(
      join(TMP, 'package.json'),
      JSON.stringify({
        reachble: { suppressions: [{ cveId: 'CVE-x' }] }, // missing package and reason
      }),
    )
    expect(() => loadConfig(TMP)).toThrowError(ConfigError)
  })

  it('ignores package.json without reachble key', () => {
    writeFileSync(join(TMP, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0' }))
    expect(loadConfig(TMP)).toEqual({})
  })

  it('returns empty object when package.json is malformed JSON', () => {
    writeFileSync(join(TMP, 'package.json'), '{bad}')
    expect(loadConfig(TMP)).toEqual({})
  })
})
