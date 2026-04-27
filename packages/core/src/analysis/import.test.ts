import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import type { AffectedSymbol, ImportGraph } from '../types.js'
import { buildImportGraph, extractPackageName, matchImports } from './import.js'

const FIXTURES = join(import.meta.dirname, '../../fixtures/import-graph')

// ---------------------------------------------------------------------------
// extractPackageName
// ---------------------------------------------------------------------------

describe('extractPackageName', () => {
  it('returns null for relative imports', () => {
    expect(extractPackageName('./foo')).toBeNull()
    expect(extractPackageName('../bar')).toBeNull()
    expect(extractPackageName('/absolute')).toBeNull()
  })

  it('returns null for node: protocol builtins', () => {
    expect(extractPackageName('node:fs')).toBeNull()
    expect(extractPackageName('node:path')).toBeNull()
  })

  it('returns null for bare Node.js builtins', () => {
    expect(extractPackageName('fs')).toBeNull()
    expect(extractPackageName('path')).toBeNull()
    expect(extractPackageName('crypto')).toBeNull()
  })

  it('returns package name for simple packages', () => {
    expect(extractPackageName('lodash')).toBe('lodash')
    expect(extractPackageName('chalk')).toBe('chalk')
  })

  it('strips subpaths from simple packages', () => {
    expect(extractPackageName('lodash/pick')).toBe('lodash')
    expect(extractPackageName('express/router')).toBe('express')
  })

  it('returns scoped package name', () => {
    expect(extractPackageName('@scope/pkg')).toBe('@scope/pkg')
    expect(extractPackageName('@typescript-eslint/parser')).toBe('@typescript-eslint/parser')
  })

  it('strips subpath from scoped packages', () => {
    expect(extractPackageName('@scope/pkg/subpath')).toBe('@scope/pkg')
  })

  it('returns null for malformed scoped import', () => {
    expect(extractPackageName('@scope')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — file discovery
// ---------------------------------------------------------------------------

describe('buildImportGraph — file discovery', () => {
  it('returns a deterministic sorted file list', () => {
    const graph = buildImportGraph(FIXTURES)
    const files = [...graph.keys()]
    expect(files).toEqual([...files].sort())
  })

  it('is deterministic across two calls', () => {
    const a = buildImportGraph(FIXTURES)
    const b = buildImportGraph(FIXTURES)
    expect([...a.entries()]).toEqual([...b.entries()])
  })

  it('respects .gitignore — ignored.ts is excluded', () => {
    const graph = buildImportGraph(FIXTURES)
    const files = [...graph.keys()]
    expect(files.every((f) => !f.endsWith('ignored.ts'))).toBe(true)
  })

  it('respects .gitignore — ignored-dir/ is excluded', () => {
    const graph = buildImportGraph(FIXTURES)
    const files = [...graph.keys()]
    expect(files.every((f) => !f.includes('ignored-dir'))).toBe(true)
  })

  it('excludes node_modules', () => {
    const graph = buildImportGraph(FIXTURES)
    const files = [...graph.keys()]
    expect(files.every((f) => !f.includes('node_modules'))).toBe(true)
  })

  it('respects extra ignorePatterns', () => {
    const graph = buildImportGraph(FIXTURES, { ignorePatterns: ['*.js'] })
    const files = [...graph.keys()]
    expect(files.every((f) => !f.endsWith('.js'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — named-imports.ts
// ---------------------------------------------------------------------------

describe('buildImportGraph — named-imports.ts', () => {
  let graph: ImportGraph
  let file: string

  beforeAll(() => {
    graph = buildImportGraph(FIXTURES)
    file = [...graph.keys()].find((f) => f.endsWith('named-imports.ts')) ?? ''
  })

  it('file is present in graph', () => {
    expect(file).toBeTruthy()
  })

  it('captures lodash named imports: template and merge', () => {
    const records = graph.get(file) ?? []
    const lodash = records.filter((r) => r.package === 'lodash')
    const names = lodash.flatMap((r) => r.symbols)
    expect(names).toContain('template')
    expect(names).toContain('merge')
    expect(lodash.every((r) => r.kind === 'named')).toBe(true)
  })

  it('ignores node:path and fs builtins', () => {
    const records = graph.get(file) ?? []
    expect(records.every((r) => r.package !== 'fs' && r.package !== 'path')).toBe(true)
  })

  it('strips subpath — @scope/pkg/subpath imports resolve to @scope/pkg', () => {
    const records = graph.get(file) ?? []
    const scoped = records.filter((r) => r.package === '@scope/pkg')
    expect(scoped.length).toBeGreaterThanOrEqual(2)
    const names = scoped.flatMap((r) => r.symbols)
    expect(names).toContain('bar')
    expect(names).toContain('baz')
  })

  it('records line numbers > 0', () => {
    const records = graph.get(file) ?? []
    expect(records.every((r) => r.line > 0)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — default-import.ts
// ---------------------------------------------------------------------------

describe('buildImportGraph — default-import.ts', () => {
  let graph: ImportGraph
  let file: string

  beforeAll(() => {
    graph = buildImportGraph(FIXTURES)
    file = [...graph.keys()].find((f) => f.endsWith('default-import.ts')) ?? ''
  })

  it('file is present in graph', () => {
    expect(file).toBeTruthy()
  })

  it('records default import with kind=default, no symbols, and a caveat', () => {
    const records = graph.get(file) ?? []
    const lodash = records.find((r) => r.package === 'lodash')
    expect(lodash?.kind).toBe('default')
    expect(lodash?.symbols).toHaveLength(0)
    expect(lodash?.caveat).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — namespace-import.ts
// ---------------------------------------------------------------------------

describe('buildImportGraph — namespace-import.ts', () => {
  let graph: ImportGraph
  let file: string

  beforeAll(() => {
    graph = buildImportGraph(FIXTURES)
    file = [...graph.keys()].find((f) => f.endsWith('namespace-import.ts')) ?? ''
  })

  it('file is present in graph', () => {
    expect(file).toBeTruthy()
  })

  it('records namespace import with kind=namespace, no symbols, and a caveat', () => {
    const records = graph.get(file) ?? []
    const lodash = records.find((r) => r.package === 'lodash')
    expect(lodash?.kind).toBe('namespace')
    expect(lodash?.symbols).toHaveLength(0)
    expect(lodash?.caveat).toBeDefined()
  })

  it('does not record node:path builtin', () => {
    const records = graph.get(file) ?? []
    expect(records.every((r) => r.package !== 'path')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — require-cjs.js
// ---------------------------------------------------------------------------

describe('buildImportGraph — require-cjs.js', () => {
  let graph: ImportGraph
  let file: string

  beforeAll(() => {
    graph = buildImportGraph(FIXTURES)
    file = [...graph.keys()].find((f) => f.endsWith('require-cjs.js')) ?? ''
  })

  it('file is present in graph', () => {
    expect(file).toBeTruthy()
  })

  it('extracts named symbols from destructured require', () => {
    const records = graph.get(file) ?? []
    const lodash = records.find((r) => r.package === 'lodash' && r.kind === 'require-static')
    expect(lodash).toBeDefined()
    expect(lodash?.symbols).toContain('template')
    expect(lodash?.symbols).toContain('merge')
  })

  it('records non-destructured require with empty symbols', () => {
    const records = graph.get(file) ?? []
    const chalk = records.find((r) => r.package === 'chalk')
    expect(chalk?.kind).toBe('require-static')
    expect(chalk?.symbols).toHaveLength(0)
  })

  it('records dynamic require as require-dynamic with a caveat', () => {
    const records = graph.get(file) ?? []
    const dyn = records.find((r) => r.kind === 'require-dynamic')
    expect(dyn).toBeDefined()
    expect(dyn?.caveat).toBeDefined()
  })

  it('ignores node: and fs builtins in require', () => {
    const records = graph.get(file) ?? []
    expect(records.every((r) => r.package !== 'fs' && r.package !== 'path')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// buildImportGraph — re-exports.ts
// ---------------------------------------------------------------------------

describe('buildImportGraph — re-exports.ts', () => {
  let graph: ImportGraph
  let file: string

  beforeAll(() => {
    graph = buildImportGraph(FIXTURES)
    file = [...graph.keys()].find((f) => f.endsWith('re-exports.ts')) ?? ''
  })

  it('file is present in graph', () => {
    expect(file).toBeTruthy()
  })

  it('extracts named re-exports from lodash', () => {
    const records = graph.get(file) ?? []
    const lodash = records.filter((r) => r.package === 'lodash')
    const names = lodash.flatMap((r) => r.symbols)
    expect(names).toContain('template')
    expect(names).toContain('merge')
    expect(lodash.every((r) => r.kind === 're-export')).toBe(true)
  })

  it('records export * as re-export-all with a caveat', () => {
    const records = graph.get(file) ?? []
    const star = records.find((r) => r.package === 'some-lib')
    expect(star?.kind).toBe('re-export-all')
    expect(star?.caveat).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// matchImports
// ---------------------------------------------------------------------------

describe('matchImports', () => {
  const affected: AffectedSymbol[] = [
    { name: 'template', type: 'function', confidence: 'high', source: 'osv' },
    { name: 'merge', type: 'function', confidence: 'medium', source: 'nvd-desc' },
  ]

  it('returns empty matches and conservative=false when package not in graph', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.ts', [{ package: 'chalk', symbols: ['red'], kind: 'named', line: 1 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.matches).toHaveLength(0)
    expect(result.conservative).toBe(false)
  })

  it('matches named symbol against affected list', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.ts', [{ package: 'lodash', symbols: ['template'], kind: 'named', line: 3 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.matches).toHaveLength(1)
    expect(result.matches[0]?.matchedSymbols).toContain('template')
    expect(result.conservative).toBe(false)
  })

  it('does not match named symbol absent from affected list', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.ts', [{ package: 'lodash', symbols: ['pick'], kind: 'named', line: 3 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.matches).toHaveLength(0)
    expect(result.conservative).toBe(false)
  })

  it('sets conservative=true for namespace import', () => {
    const graph: ImportGraph = new Map([
      [
        '/src/app.ts',
        [
          {
            package: 'lodash',
            symbols: [],
            kind: 'namespace',
            line: 1,
            caveat: 'namespace import — all symbols potentially used',
          },
        ],
      ],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.conservative).toBe(true)
    expect(result.matches[0]?.matchedSymbols).toHaveLength(0)
  })

  it('sets conservative=true for default import', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.ts', [{ package: 'lodash', symbols: [], kind: 'default', line: 1 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.conservative).toBe(true)
  })

  it('sets conservative=true for require-static with empty symbols', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.js', [{ package: 'lodash', symbols: [], kind: 'require-static', line: 1 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.conservative).toBe(true)
  })

  it('matches multiple symbols across multiple files', () => {
    const graph: ImportGraph = new Map([
      ['/src/a.ts', [{ package: 'lodash', symbols: ['template'], kind: 'named', line: 1 }]],
      ['/src/b.ts', [{ package: 'lodash', symbols: ['merge', 'pick'], kind: 'named', line: 2 }]],
      ['/src/c.ts', [{ package: 'chalk', symbols: ['red'], kind: 'named', line: 1 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.matches).toHaveLength(2)
    const fileA = result.matches.find((m) => m.file.endsWith('a.ts'))
    const fileB = result.matches.find((m) => m.file.endsWith('b.ts'))
    expect(fileA?.matchedSymbols).toContain('template')
    expect(fileB?.matchedSymbols).toContain('merge')
    expect(fileB?.matchedSymbols).not.toContain('pick')
  })

  it('carries caveat from import record when present', () => {
    const graph: ImportGraph = new Map([
      [
        '/src/app.ts',
        [
          {
            package: 'lodash',
            symbols: ['template'],
            kind: 'named',
            line: 1,
            caveat: 'test caveat',
          },
        ],
      ],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(result.matches[0]?.caveat).toBe('test caveat')
  })

  it('does not add caveat key when record has none', () => {
    const graph: ImportGraph = new Map([
      ['/src/app.ts', [{ package: 'lodash', symbols: ['template'], kind: 'named', line: 1 }]],
    ])
    const result = matchImports(graph, 'lodash', affected)
    expect(Object.keys(result.matches[0] ?? {})).not.toContain('caveat')
  })

  it('packageName in result equals query', () => {
    const graph: ImportGraph = new Map()
    const result = matchImports(graph, 'lodash', affected)
    expect(result.packageName).toBe('lodash')
  })
})
