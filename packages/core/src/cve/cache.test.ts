import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { CveCache } from './cache.js'

let tmpDir: string
let cache: CveCache

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachble-cache-test-'))
  cache = new CveCache(tmpDir)
})

afterEach(() => {
  cache.close()
  fs.rmSync(tmpDir, { recursive: true, force: true })
})

describe('CveCache', () => {
  it('returns undefined for a missing key', () => {
    expect(cache.get('missing')).toBeUndefined()
  })

  it('stores and retrieves a value', () => {
    cache.set('k', { foo: 'bar' })
    expect(cache.get('k')).toEqual({ foo: 'bar' })
  })

  it('overwrites an existing key', () => {
    cache.set('k', 'first')
    cache.set('k', 'second')
    expect(cache.get('k')).toBe('second')
  })

  it('returns undefined for an expired entry', () => {
    cache.set('k', 'value', -1) // already expired
    expect(cache.get('k')).toBeUndefined()
  })

  it('invalidates a specific key', () => {
    cache.set('k1', 'a')
    cache.set('k2', 'b')
    cache.invalidate('k1')
    expect(cache.get('k1')).toBeUndefined()
    expect(cache.get('k2')).toBe('b')
  })

  it('invalidates by prefix', () => {
    cache.set('osv:a', 1)
    cache.set('osv:b', 2)
    cache.set('nvd:c', 3)
    cache.invalidatePrefix('osv:')
    expect(cache.get('osv:a')).toBeUndefined()
    expect(cache.get('osv:b')).toBeUndefined()
    expect(cache.get('nvd:c')).toBe(3)
  })

  it('stores complex JSON values', () => {
    const val = { id: 'CVE-2021-23337', symbols: [{ name: 'template', confidence: 'high' }] }
    cache.set('complex', val)
    expect(cache.get('complex')).toEqual(val)
  })

  it('is deterministic — same key same value across writes', () => {
    const data = [{ id: 'CVE-1' }, { id: 'CVE-2' }]
    cache.set('pkgs', data)
    const a = cache.get('pkgs')
    const b = cache.get('pkgs')
    expect(a).toEqual(b)
  })
})
