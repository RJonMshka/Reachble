import { describe, expect, it } from 'vitest'
import type {
  AffectedSymbol,
  CallEdge,
  CveRecord,
  EntryPoint,
  Evidence,
  ResolvedPackage,
  VerdictResult,
  VexStatement,
} from './types.js'

describe('types (shape smoke tests)', () => {
  it('ResolvedPackage is constructible', () => {
    const pkg: ResolvedPackage = {
      name: 'lodash',
      version: '4.17.20',
      depth: 2,
      dependents: ['my-app'],
      devOnly: false,
      lockfileSource: 'npm',
    }
    expect(pkg.name).toBe('lodash')
    expect(pkg.lockfileSource).toBe('npm')
  })

  it('AffectedSymbol confidence and source unions', () => {
    const sym: AffectedSymbol = {
      name: 'template',
      type: 'function',
      confidence: 'high',
      source: 'osv',
    }
    expect(sym.type).toBe('function')
    expect(sym.source).toBe('osv')
  })

  it('CveRecord holds all fields', () => {
    const cve: CveRecord = {
      id: 'GHSA-p6mc-m468-83gw',
      aliases: ['CVE-2021-23337'],
      severity: 'HIGH',
      cvssScore: 7.2,
      epssScore: 0.012,
      affectedVersionRange: '<4.17.21',
      affectedSymbols: [{ name: 'template', type: 'function', confidence: 'high', source: 'osv' }],
      fixCommitUrls: ['https://github.com/lodash/lodash/commit/abc123'],
      description: 'Command injection via template',
      publishedAt: new Date('2021-02-15'),
    }
    expect(cve.severity).toBe('HIGH')
    expect(cve.affectedSymbols).toHaveLength(1)
  })

  it('CallEdge dynamic flag', () => {
    const edge: CallEdge = {
      callerFile: 'src/render.ts',
      callerFunction: 'render',
      calleePackage: 'lodash',
      calleeSymbol: 'template',
      line: 42,
      dynamic: false,
    }
    expect(edge.dynamic).toBe(false)
  })

  it('EntryPoint with optional framework', () => {
    const ep: EntryPoint = {
      file: 'src/server.ts',
      line: 12,
      kind: 'http',
      framework: 'express',
      authenticated: false,
      description: 'POST /api/render',
    }
    expect(ep.kind).toBe('http')
    expect(ep.authenticated).toBe(false)

    const cli: EntryPoint = {
      file: 'src/cli.ts',
      line: 1,
      kind: 'cli',
      authenticated: false,
      description: 'CLI entry',
    }
    expect(cli.framework).toBeUndefined()
  })

  it('Evidence with optional caveat', () => {
    const ev: Evidence = {
      type: 'import',
      description: 'lodash template imported',
      file: 'src/render.ts',
      line: 1,
    }
    expect(ev.caveat).toBeUndefined()

    const withCaveat: Evidence = {
      type: 'import',
      description: 'namespace import — all symbols assumed reachable',
      caveat: 'namespace import: conservative assumption',
    }
    expect(withCaveat.caveat).toBeDefined()
  })

  it('VerdictResult SAFE with no fixedIn', () => {
    const vr: VerdictResult = {
      cveId: 'CVE-2021-23337',
      package: 'lodash',
      version: '4.17.20',
      verdict: 'SAFE',
      confidence: 'high',
      reason: 'template not imported anywhere',
      evidence: [],
      epssScore: 0.01,
      cvssScore: 7.2,
    }
    expect(vr.verdict).toBe('SAFE')
    expect(vr.fixedIn).toBeUndefined()
  })

  it('VexStatement not_affected', () => {
    const stmt: VexStatement = {
      cveId: 'CVE-2021-23337',
      product: { name: 'my-app', version: '1.0.0' },
      status: 'not_affected',
      justification: 'vulnerable_code_not_present',
      evidenceRefs: ['evidence-1'],
    }
    expect(stmt.status).toBe('not_affected')
    expect(stmt.justification).toBe('vulnerable_code_not_present')
  })
})
