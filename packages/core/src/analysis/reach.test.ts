import { describe, expect, it } from 'vitest'
import type { CallEdge, FileGraph } from '../types.js'
import type { EntryPoint } from '../types.js'
import { bfsPath, findCallPath, isTestFile } from './reach.js'

// ── helpers ───────────────────────────────────────────────────────────────────

function makeCallSite(overrides: Partial<CallEdge> = {}): CallEdge {
  return {
    callerFile: '/app/src/routes.ts',
    callerFunction: 'handleRequest',
    calleePackage: 'lodash',
    calleeSymbol: 'template',
    line: 42,
    dynamic: false,
    ...overrides,
  }
}

function makeEp(file: string): EntryPoint {
  return {
    file,
    line: 1,
    kind: 'http',
    framework: 'express',
    authenticated: false,
    description: `Express GET / (${file})`,
  }
}

// ── isTestFile ────────────────────────────────────────────────────────────────

describe('isTestFile', () => {
  it.each([
    '/app/src/foo.test.ts',
    '/app/src/foo.spec.ts',
    '/app/src/foo.test.js',
    '/app/src/foo.spec.mjs',
    '/app/src/__tests__/foo.ts',
    '/app/__tests__/bar.js',
  ])('returns true for %s', (file) => {
    expect(isTestFile(file)).toBe(true)
  })

  it.each([
    '/app/src/routes.ts',
    '/app/src/server.js',
    '/app/src/utils/helpers.ts',
    '/app/src/testing-utils.ts', // has "testing" but not .test/.spec
    '/app/src/contested.ts', // contains "test" in name
  ])('returns false for %s', (file) => {
    expect(isTestFile(file)).toBe(false)
  })
})

// ── bfsPath ───────────────────────────────────────────────────────────────────

describe('bfsPath', () => {
  it('returns [start] when start is a target', () => {
    const targets = new Set(['/a.ts'])
    const result = bfsPath('/a.ts', targets, new Map(), 25)
    expect(result).toEqual(['/a.ts'])
  })

  it('finds a direct 1-hop path', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/callee.ts']]])
    const result = bfsPath('/ep.ts', new Set(['/callee.ts']), fg)
    expect(result).toEqual(['/ep.ts', '/callee.ts'])
  })

  it('finds a multi-hop path (3 hops)', () => {
    const fg: FileGraph = new Map([
      ['/a.ts', ['/b.ts']],
      ['/b.ts', ['/c.ts']],
      ['/c.ts', ['/d.ts']],
    ])
    const result = bfsPath('/a.ts', new Set(['/d.ts']), fg)
    expect(result).toEqual(['/a.ts', '/b.ts', '/c.ts', '/d.ts'])
  })

  it('returns null when target is unreachable', () => {
    const fg: FileGraph = new Map([['/a.ts', ['/b.ts']]])
    expect(bfsPath('/a.ts', new Set(['/c.ts']), fg)).toBeNull()
  })

  it('handles cycles without infinite loop', () => {
    const fg: FileGraph = new Map([
      ['/a.ts', ['/b.ts']],
      ['/b.ts', ['/a.ts']], // cycle
    ])
    expect(bfsPath('/a.ts', new Set(['/c.ts']), fg)).toBeNull()
  })

  it('respects depthLimit — does not traverse beyond the limit', () => {
    // Path requires 3 hops but limit is 2
    const fg: FileGraph = new Map([
      ['/a.ts', ['/b.ts']],
      ['/b.ts', ['/c.ts']],
      ['/c.ts', ['/d.ts']],
    ])
    expect(bfsPath('/a.ts', new Set(['/d.ts']), fg, 2)).toBeNull()
  })

  it('finds path exactly at depthLimit', () => {
    // Path requires exactly 2 hops, limit is 2
    const fg: FileGraph = new Map([
      ['/a.ts', ['/b.ts']],
      ['/b.ts', ['/c.ts']],
    ])
    expect(bfsPath('/a.ts', new Set(['/c.ts']), fg, 2)).toEqual(['/a.ts', '/b.ts', '/c.ts'])
  })

  it('returns shortest path when multiple routes exist', () => {
    // Long: a → b → c → target; Short: a → target
    const fg: FileGraph = new Map([
      ['/a.ts', ['/b.ts', '/target.ts']],
      ['/b.ts', ['/c.ts']],
      ['/c.ts', ['/target.ts']],
    ])
    const result = bfsPath('/a.ts', new Set(['/target.ts']), fg)
    expect(result).toEqual(['/a.ts', '/target.ts'])
  })

  it('returns null for empty fileGraph', () => {
    expect(bfsPath('/a.ts', new Set(['/b.ts']), new Map())).toBeNull()
  })
})

// ── findCallPath ──────────────────────────────────────────────────────────────

describe('findCallPath', () => {
  it('returns null when callSites is empty', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/routes.ts']]])
    expect(findCallPath(makeEp('/ep.ts'), [], fg)).toBeNull()
  })

  it('returns null when call site file is not reachable', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/other.ts']]])
    const site = makeCallSite({ callerFile: '/routes.ts' })
    expect(findCallPath(makeEp('/ep.ts'), [site], fg)).toBeNull()
  })

  it('returns a ReachPath when site is directly the ep file', () => {
    const fg: FileGraph = new Map()
    const site = makeCallSite({ callerFile: '/ep.ts' })
    const result = findCallPath(makeEp('/ep.ts'), [site], fg)
    expect(result).not.toBeNull()
    expect(result.filePath).toEqual(['/ep.ts'])
    expect(result.callSite).toBe(site)
  })

  it('returns filePath from ep to call site via 1 hop', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/routes.ts']]])
    const site = makeCallSite({ callerFile: '/routes.ts' })
    const result = findCallPath(makeEp('/ep.ts'), [site], fg)
    expect(result.filePath).toEqual(['/ep.ts', '/routes.ts'])
    expect(result.callSite).toBe(site)
  })

  it('hasDynamicEdge is false for non-dynamic call site', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/routes.ts']]])
    const site = makeCallSite({ callerFile: '/routes.ts', dynamic: false })
    const result = findCallPath(makeEp('/ep.ts'), [site], fg)
    expect(result.hasDynamicEdge).toBe(false)
  })

  it('hasDynamicEdge is true when call site is dynamic', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/routes.ts']]])
    const site = makeCallSite({ callerFile: '/routes.ts', dynamic: true })
    const result = findCallPath(makeEp('/ep.ts'), [site], fg)
    expect(result.hasDynamicEdge).toBe(true)
  })

  it('respects depthLimit — returns null when path is too deep', () => {
    const fg: FileGraph = new Map([
      ['/ep.ts', ['/a.ts']],
      ['/a.ts', ['/b.ts']],
      ['/b.ts', ['/routes.ts']],
    ])
    const site = makeCallSite({ callerFile: '/routes.ts' })
    expect(findCallPath(makeEp('/ep.ts'), [site], fg, 2)).toBeNull()
  })

  it('picks the correct call site when multiple sites exist', () => {
    const fg: FileGraph = new Map([['/ep.ts', ['/routes.ts']]])
    const siteA = makeCallSite({ callerFile: '/other.ts', calleeSymbol: 'merge' })
    const siteB = makeCallSite({ callerFile: '/routes.ts', calleeSymbol: 'template' })
    const result = findCallPath(makeEp('/ep.ts'), [siteA, siteB], fg)
    expect(result.callSite).toBe(siteB)
  })
})
