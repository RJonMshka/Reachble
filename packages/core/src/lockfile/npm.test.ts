import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { LockfileParseError } from '../errors.js'
import { parseNpmLock } from './npm.js'

const FIXTURES = join(import.meta.dirname, '../../fixtures')

function readFixture(rel: string): string {
  return readFileSync(join(FIXTURES, rel), 'utf-8')
}

describe('parseNpmLock — v2', () => {
  const pkgs = parseNpmLock(readFixture('npm-v2/package-lock.json'))

  it('returns sorted deterministic output', () => {
    const names = pkgs.map((p) => `${p.name}@${p.version}`)
    expect(names).toEqual([...names].sort())
  })

  it('is deterministic across two calls', () => {
    const a = parseNpmLock(readFixture('npm-v2/package-lock.json'))
    const b = parseNpmLock(readFixture('npm-v2/package-lock.json'))
    expect(a).toEqual(b)
  })

  it('all lockfileSource are npm', () => {
    expect(pkgs.every((p) => p.lockfileSource === 'npm')).toBe(true)
  })

  it('includes express as prod dep at depth 1', () => {
    const express = pkgs.find((p) => p.name === 'express')
    expect(express).toBeDefined()
    expect(express!.version).toBe('4.18.2')
    expect(express!.depth).toBe(1)
    expect(express!.devOnly).toBe(false)
    expect(express!.dependents).toContain('.')
  })

  it('includes body-parser as transitive prod dep at depth 1 (hoisted)', () => {
    const bp = pkgs.find((p) => p.name === 'body-parser')
    expect(bp).toBeDefined()
    expect(bp!.depth).toBe(1)
    expect(bp!.devOnly).toBe(false)
    expect(bp!.dependents).toContain('express')
  })

  it('marks typescript as devOnly', () => {
    const ts = pkgs.find((p) => p.name === 'typescript')
    expect(ts).toBeDefined()
    expect(ts!.devOnly).toBe(true)
    expect(ts!.dependents).toContain('.')
  })

  it('includes nested debug at depth 2 (under express/node_modules)', () => {
    const debug = pkgs.find((p) => p.name === 'debug')
    expect(debug).toBeDefined()
    expect(debug!.depth).toBe(2)
  })

  it('does not include the root package', () => {
    expect(pkgs.find((p) => p.name === 'demo-app')).toBeUndefined()
  })
})

describe('parseNpmLock — v3', () => {
  const pkgs = parseNpmLock(readFixture('npm-v3/package-lock.json'))

  it('parses v3 identically to v2 for same data', () => {
    const v2 = parseNpmLock(readFixture('npm-v2/package-lock.json'))
    // Same packages, same structure — names and versions must match
    const v2names = v2.map((p) => `${p.name}@${p.version}`).sort()
    const v3names = pkgs.map((p) => `${p.name}@${p.version}`).sort()
    expect(v3names).toEqual(v2names)
  })
})

describe('parseNpmLock — error cases', () => {
  it('throws LockfileParseError on invalid JSON', () => {
    expect(() => parseNpmLock('not json')).toThrow(LockfileParseError)
  })

  it('throws LockfileParseError with helpful message for v1', () => {
    const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: {} })
    expect(() => parseNpmLock(v1)).toThrow(/lockfileVersion 1/)
  })

  it('throws LockfileParseError on schema mismatch', () => {
    const bad = JSON.stringify({ lockfileVersion: 2 }) // missing packages
    expect(() => parseNpmLock(bad)).toThrow(LockfileParseError)
  })
})
