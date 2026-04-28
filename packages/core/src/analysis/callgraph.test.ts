import { ModuleResolutionKind, Project } from 'ts-morph'
import { describe, expect, it } from 'vitest'
import { buildCallGraph, extractCallEdges } from './callgraph.js'

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Build an in-memory ts-morph project.
 * Files whose paths contain 'node_modules' are written to the FS and added to the
 * project (so TypeScript's type checker can find declarations) but `extractCallEdges`
 * skips them as callers.
 */
function makeProject(sources: Record<string, string>): Project {
  const project = new Project({
    useInMemoryFileSystem: true,
    skipAddingFilesFromTsConfig: true,
    compilerOptions: {
      moduleResolution: ModuleResolutionKind.Node10, // eslint-disable-line @typescript-eslint/no-deprecated
      strict: false,
      skipLibCheck: true,
    },
  })
  const fs = project.getFileSystem()
  for (const [path, content] of Object.entries(sources)) {
    // Write to raw FS so TypeScript's module resolver finds it
    fs.writeFileSync(path, content)
    // Also add to the ts-morph program so getValueDeclaration() can navigate to it
    project.addSourceFileAtPath(path)
  }
  return project
}

const VULN_PKG = `
  export declare function dangerousFn(input: string): string;
  export declare function safeFn(): void;
  declare namespace _default { function dangerousFn(input: string): string; function safeFn(): void; }
  export default _default;
`

// ─── named import ─────────────────────────────────────────────────────────────

describe('extractCallEdges — named import call', () => {
  it('detects direct named-import call', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/handler.ts': `
        import { dangerousFn } from 'vuln-pkg'
        export function handleRequest(s: string) { return dangerousFn(s) }
      `,
    })
    const graph = extractCallEdges(project)
    const edges = graph.get('/src/handler.ts') ?? []
    expect(edges).toHaveLength(1)
    expect(edges[0]).toMatchObject({
      callerFile: '/src/handler.ts',
      calleePackage: 'vuln-pkg',
      calleeSymbol: 'dangerousFn',
      dynamic: false,
    })
  })

  it('captures the call-site line number', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': [
        'import { dangerousFn } from "vuln-pkg"',
        '',
        'export function run() {',
        '  return dangerousFn("x")',
        '}',
      ].join('\n'),
    })
    const edge = (extractCallEdges(project).get('/src/a.ts') ?? [])[0]
    expect(edge?.line).toBe(4)
  })

  it('records named-function caller', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import { dangerousFn } from 'vuln-pkg'
        export function handleRequest() { dangerousFn('x') }
      `,
    })
    const edge = (extractCallEdges(project).get('/src/a.ts') ?? [])[0]
    expect(edge?.callerFunction).toBe('handleRequest')
  })

  it('uses the arrow-function variable name as caller', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import { dangerousFn } from 'vuln-pkg'
        const processInput = () => { dangerousFn('x') }
      `,
    })
    const edge = (extractCallEdges(project).get('/src/a.ts') ?? [])[0]
    expect(edge?.callerFunction).toBe('processInput')
  })

  it('uses <module> for top-level call', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import { dangerousFn } from 'vuln-pkg'
        dangerousFn('boot')
      `,
    })
    const edge = (extractCallEdges(project).get('/src/a.ts') ?? [])[0]
    expect(edge?.callerFunction).toBe('<module>')
  })
})

// ─── namespace import ─────────────────────────────────────────────────────────

describe('extractCallEdges — namespace import call', () => {
  it('detects property call on namespace import', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import * as pkg from 'vuln-pkg'
        export function run() { return pkg.dangerousFn('x') }
      `,
    })
    const edges = extractCallEdges(project).get('/src/a.ts') ?? []
    expect(
      edges.some((e) => e.calleePackage === 'vuln-pkg' && e.calleeSymbol === 'dangerousFn'),
    ).toBe(true)
  })
})

// ─── no call to vulnerable symbol ─────────────────────────────────────────────

describe('extractCallEdges — no call to vulnerable symbol', () => {
  it('produces no edges when only safeFn is called', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import { safeFn } from 'vuln-pkg'
        export function run() { safeFn() }
      `,
    })
    const edges = extractCallEdges(project).get('/src/a.ts') ?? []
    expect(edges.every((e) => e.calleeSymbol !== 'dangerousFn')).toBe(true)
  })

  it('returns no entry for file that imports but never calls', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `import { dangerousFn } from 'vuln-pkg'`,
    })
    expect(extractCallEdges(project).get('/src/a.ts') ?? []).toHaveLength(0)
  })
})

// ─── multiple calls ───────────────────────────────────────────────────────────

describe('extractCallEdges — multiple calls in one file', () => {
  it('captures all call sites with correct caller functions', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/src/a.ts': `
        import { dangerousFn, safeFn } from 'vuln-pkg'
        export function a() { dangerousFn('1') }
        export function b() { dangerousFn('2') }
        export function c() { safeFn() }
      `,
    })
    const dangerous = (extractCallEdges(project).get('/src/a.ts') ?? []).filter(
      (e) => e.calleeSymbol === 'dangerousFn',
    )
    expect(dangerous).toHaveLength(2)
    expect(dangerous[0]?.callerFunction).toBe('a')
    expect(dangerous[1]?.callerFunction).toBe('b')
  })
})

// ─── node_modules excluded ────────────────────────────────────────────────────

describe('extractCallEdges — node_modules files excluded', () => {
  it('does not emit edges for files inside node_modules', () => {
    const project = makeProject({
      '/node_modules/vuln-pkg/index.d.ts': VULN_PKG,
      '/node_modules/other/index.ts': `
        import { dangerousFn } from 'vuln-pkg'
        dangerousFn('x')
      `,
      '/src/a.ts': `export const x = 1`,
    })
    for (const key of extractCallEdges(project).keys()) {
      expect(key).not.toContain('node_modules')
    }
  })
})

// ─── @types normalisation ─────────────────────────────────────────────────────

describe('extractCallEdges — @types/* package name normalisation', () => {
  it('strips @types/ prefix so calleePackage matches the runtime package name', () => {
    const project = makeProject({
      '/node_modules/@types/some-lib/index.d.ts': `export declare function vuln(): void`,
      '/src/a.ts': `
        import { vuln } from 'some-lib'
        export function run() { vuln() }
      `,
    })
    const edge = (extractCallEdges(project).get('/src/a.ts') ?? [])[0]
    expect(edge?.calleePackage).toBe('some-lib')
  })
})

// ─── buildCallGraph ───────────────────────────────────────────────────────────

describe('buildCallGraph', () => {
  it('returns null when no tsconfig.json exists in directory', () => {
    expect(buildCallGraph('/nonexistent/path/no/tsconfig')).toBeNull()
  })
})
