import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { LockfileParseError } from '../errors.js'
import { parsePnpmLock } from './pnpm.js'

const FIXTURES = join(import.meta.dirname, '../../fixtures')

function readFixture(rel: string): string {
  return readFileSync(join(FIXTURES, rel), 'utf-8')
}

describe('parsePnpmLock — v6', () => {
  const pkgs = parsePnpmLock(readFixture('pnpm-v6/pnpm-lock.yaml'))

  it('returns sorted deterministic output', () => {
    const names = pkgs.map((p) => `${p.name}@${p.version}`)
    expect(names).toEqual([...names].sort())
  })

  it('is deterministic across two calls', () => {
    const a = parsePnpmLock(readFixture('pnpm-v6/pnpm-lock.yaml'))
    const b = parsePnpmLock(readFixture('pnpm-v6/pnpm-lock.yaml'))
    expect(a).toEqual(b)
  })

  it('all lockfileSource are pnpm', () => {
    expect(pkgs.every((p) => p.lockfileSource === 'pnpm')).toBe(true)
  })

  it('includes express as prod dep at depth 1', () => {
    const express = pkgs.find((p) => p.name === 'express')
    expect(express).toBeDefined()
    expect(express!.version).toBe('4.18.2')
    expect(express!.depth).toBe(1)
    expect(express!.devOnly).toBe(false)
    expect(express!.dependents).toContain('.')
  })

  it('includes body-parser as transitive dep at depth 2', () => {
    const bp = pkgs.find((p) => p.name === 'body-parser')
    expect(bp).toBeDefined()
    expect(bp!.depth).toBe(2)
    expect(bp!.devOnly).toBe(false)
    expect(bp!.dependents).toContain('express')
  })

  it('marks typescript as devOnly', () => {
    const ts = pkgs.find((p) => p.name === 'typescript')
    expect(ts).toBeDefined()
    expect(ts!.devOnly).toBe(true)
    expect(ts!.dependents).toContain('.')
  })
})

describe('parsePnpmLock — error cases', () => {
  it('throws LockfileParseError on invalid YAML', () => {
    expect(() => parsePnpmLock('{')).toThrow(LockfileParseError)
  })

  it('throws LockfileParseError on schema mismatch', () => {
    expect(() => parsePnpmLock('not: yaml: at: all: really: bad')).toThrow(LockfileParseError)
  })
})
