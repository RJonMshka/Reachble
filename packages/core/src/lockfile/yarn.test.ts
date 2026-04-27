import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { LockfileParseError } from '../errors.js'
import type { RootPackageJson } from './schemas.js'
import { parseYarnLock } from './yarn.js'

const FIXTURES = join(import.meta.dirname, '../../fixtures')

function readFixture(rel: string): string {
  return readFileSync(join(FIXTURES, rel), 'utf-8')
}

const PKG_JSON: RootPackageJson = JSON.parse(
  readFileSync(join(FIXTURES, 'yarn-v1/package.json'), 'utf-8'),
) as RootPackageJson

describe('parseYarnLock — v1 classic', () => {
  const pkgs = parseYarnLock(readFixture('yarn-v1/yarn.lock'), PKG_JSON)

  it('returns sorted deterministic output', () => {
    const names = pkgs.map((p) => `${p.name}@${p.version}`)
    expect(names).toEqual([...names].sort())
  })

  it('is deterministic across two calls', () => {
    const a = parseYarnLock(readFixture('yarn-v1/yarn.lock'), PKG_JSON)
    const b = parseYarnLock(readFixture('yarn-v1/yarn.lock'), PKG_JSON)
    expect(a).toEqual(b)
  })

  it('all lockfileSource are yarn', () => {
    expect(pkgs.every((p) => p.lockfileSource === 'yarn')).toBe(true)
  })

  it('includes express as prod dep at depth 1', () => {
    const express = pkgs.find((p) => p.name === 'express')
    expect(express).toBeDefined()
    expect(express?.version).toBe('4.18.2')
    expect(express?.depth).toBe(1)
    expect(express?.devOnly).toBe(false)
    expect(express?.dependents).toContain('.')
  })

  it('includes body-parser as transitive dep at depth 2', () => {
    const bp = pkgs.find((p) => p.name === 'body-parser')
    expect(bp).toBeDefined()
    expect(bp?.depth).toBe(2)
    expect(bp?.devOnly).toBe(false)
    expect(bp?.dependents).toContain('express')
  })

  it('marks typescript as devOnly', () => {
    const ts = pkgs.find((p) => p.name === 'typescript')
    expect(ts).toBeDefined()
    expect(ts?.devOnly).toBe(true)
    expect(ts?.dependents).toContain('.')
  })
})

describe('parseYarnLock — error cases', () => {
  it('throws LockfileParseError when lockfile has git conflict markers', () => {
    // @yarnpkg/lockfile returns type:'conflict' for conflicted files, failing our schema
    const conflicted =
      '# yarn lockfile v1\n<<<<<<< HEAD\nexpress@^4.0.0:\n  version "4.17.0"\n=======\n'
    expect(() => parseYarnLock(conflicted, {})).toThrow(LockfileParseError)
  })
})
