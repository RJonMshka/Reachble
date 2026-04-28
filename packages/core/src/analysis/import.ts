/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unnecessary-type-assertion */
import { parse } from '@typescript-eslint/parser'
import ignore from 'ignore'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { extname, join, relative } from 'node:path'
import type {
  AffectedSymbol,
  FileImportMatch,
  ImportGraph,
  ImportMatchResult,
  ImportRecord,
} from '../types.js'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AstNode = any

const NODE_BUILTINS = new Set([
  'assert',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'domain',
  'events',
  'fs',
  'http',
  'http2',
  'https',
  'inspector',
  'module',
  'net',
  'os',
  'path',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'repl',
  'stream',
  'string_decoder',
  'sys',
  'timers',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib',
])

export interface AnalyzeOptions {
  ignorePatterns?: string[]
  extensions?: string[]
}

/**
 * Extract the npm package name from an import source string.
 * Returns null for relative imports, node: builtins, and unresolvable sources.
 */
export function extractPackageName(source: string): string | null {
  if (source.startsWith('.') || source.startsWith('/')) return null
  if (source.startsWith('node:')) return null
  if (source.startsWith('@')) {
    const firstSlash = source.indexOf('/', 1)
    if (firstSlash === -1) return null
    const secondSlash = source.indexOf('/', firstSlash + 1)
    return secondSlash === -1 ? source : source.slice(0, secondSlash)
  }
  const bare = source.split('/')[0] ?? ''
  if (NODE_BUILTINS.has(bare)) return null
  return bare || null
}

export function discoverFiles(dir: string, opts: AnalyzeOptions): string[] {
  const exts = new Set(opts.extensions ?? ['.ts', '.tsx', '.js', '.mjs', '.cjs'])
  const ig = ignore()
  const gitignorePath = join(dir, '.gitignore')
  if (existsSync(gitignorePath)) ig.add(readFileSync(gitignorePath, 'utf8'))
  ig.add(['node_modules', '.git'])
  if (opts.ignorePatterns) ig.add(opts.ignorePatterns)

  const files: string[] = []

  function walk(current: string): void {
    const entries = (() => {
      try {
        return readdirSync(current, { withFileTypes: true })
      } catch {
        return null
      }
    })()
    if (!entries) return
    for (const entry of entries) {
      const fullPath = join(current, entry.name)
      const rel = relative(dir, fullPath)
      const checkPath = entry.isDirectory() ? `${rel}/` : rel
      if (ig.ignores(checkPath)) continue
      if (entry.isDirectory()) {
        walk(fullPath)
      } else if (entry.isFile() && exts.has(extname(entry.name))) {
        files.push(fullPath)
      }
    }
  }

  walk(dir)
  return files.sort()
}

function handleImportDeclaration(node: AstNode, records: ImportRecord[]): void {
  const sourceVal: unknown = node.source?.value
  if (typeof sourceVal !== 'string') return
  const pkg = extractPackageName(sourceVal)
  if (!pkg) return
  const line: number = (node.loc?.start?.line as number | undefined) ?? 0
  const specifiers: AstNode[] = (node.specifiers as AstNode[] | undefined) ?? []

  if (specifiers.length === 0) {
    records.push({ package: pkg, symbols: [], kind: 'named', line })
    return
  }

  for (const spec of specifiers) {
    const specType = spec.type as string
    if (specType === 'ImportSpecifier') {
      const imported = spec.imported as AstNode
      const name: string =
        (imported?.name as string | undefined) ?? (imported?.value as string | undefined) ?? ''
      if (name) records.push({ package: pkg, symbols: [name], kind: 'named', line })
    } else if (specType === 'ImportDefaultSpecifier') {
      records.push({
        package: pkg,
        symbols: [],
        kind: 'default',
        line,
        caveat: 'default import — cannot determine specific symbol usage statically',
      })
    } else if (specType === 'ImportNamespaceSpecifier') {
      records.push({
        package: pkg,
        symbols: [],
        kind: 'namespace',
        line,
        caveat: 'namespace import — all symbols potentially used',
      })
    }
  }
}

function handleNamedReExport(node: AstNode, records: ImportRecord[]): void {
  const sourceVal: unknown = node.source?.value
  if (typeof sourceVal !== 'string') return
  const pkg = extractPackageName(sourceVal)
  if (!pkg) return
  const line: number = (node.loc?.start?.line as number | undefined) ?? 0
  const specifiers: AstNode[] = (node.specifiers as AstNode[] | undefined) ?? []

  if (specifiers.length === 0) {
    records.push({ package: pkg, symbols: [], kind: 're-export', line })
    return
  }

  for (const spec of specifiers) {
    const name: string = (spec.local?.name as string | undefined) ?? ''
    if (name) records.push({ package: pkg, symbols: [name], kind: 're-export', line })
  }
}

function handleReExportAll(node: AstNode, records: ImportRecord[]): void {
  const sourceVal: unknown = node.source?.value
  if (typeof sourceVal !== 'string') return
  const pkg = extractPackageName(sourceVal)
  if (!pkg) return
  const line: number = (node.loc?.start?.line as number | undefined) ?? 0
  records.push({
    package: pkg,
    symbols: [],
    kind: 're-export-all',
    line,
    caveat: 'export * — all symbols potentially re-exported',
  })
}

function handleRequireDeclarator(decl: AstNode, records: ImportRecord[]): void {
  const init: AstNode = decl.init
  if (!init) return

  if (
    (init.type as string) !== 'CallExpression' ||
    (init.callee?.type as string) !== 'Identifier' ||
    (init.callee?.name as string) !== 'require'
  ) {
    walkRequires(init, records)
    return
  }

  const args: AstNode[] = (init.arguments as AstNode[] | undefined) ?? []
  const arg: AstNode = args[0]
  const line: number = (decl.loc?.start?.line as number | undefined) ?? 0

  if (!arg) return

  if ((arg.type as string) !== 'Literal' || typeof arg.value !== 'string') {
    records.push({
      package: '__dynamic__',
      symbols: [],
      kind: 'require-dynamic',
      line,
      caveat: 'dynamic require() — package and symbols unknown at analysis time',
    })
    return
  }

  const pkg = extractPackageName(arg.value as string)
  if (!pkg) return

  if ((decl.id?.type as string) === 'ObjectPattern') {
    const symbols: string[] = []
    const props: AstNode[] = (decl.id.properties as AstNode[] | undefined) ?? []
    let conserved = false
    for (const prop of props) {
      if ((prop.type as string) === 'Property' && (prop.key?.type as string) === 'Identifier') {
        symbols.push(prop.key.name as string)
      } else {
        conserved = true
        break
      }
    }
    if (conserved) {
      records.push({ package: pkg, symbols: [], kind: 'require-static', line })
    } else {
      records.push({ package: pkg, symbols, kind: 'require-static', line })
    }
  } else {
    records.push({ package: pkg, symbols: [], kind: 'require-static', line })
  }
}

function walkRequires(node: AstNode, records: ImportRecord[]): void {
  if (!node || typeof node !== 'object') return
  const type = node.type as string | undefined
  if (!type) return

  if (
    type === 'ImportDeclaration' ||
    type === 'ExportNamedDeclaration' ||
    type === 'ExportAllDeclaration'
  )
    return

  if (type === 'VariableDeclaration') {
    const decls: AstNode[] = (node.declarations as AstNode[] | undefined) ?? []
    for (const decl of decls) handleRequireDeclarator(decl, records)
    return
  }

  if (
    type === 'CallExpression' &&
    (node.callee?.type as string) === 'Identifier' &&
    (node.callee?.name as string) === 'require'
  ) {
    const args: AstNode[] = (node.arguments as AstNode[] | undefined) ?? []
    const arg: AstNode = args[0]
    const line: number = (node.loc?.start?.line as number | undefined) ?? 0
    if (arg && (arg.type as string) === 'Literal' && typeof arg.value === 'string') {
      const pkg = extractPackageName(arg.value as string)
      if (pkg) records.push({ package: pkg, symbols: [], kind: 'require-static', line })
    } else if (arg) {
      records.push({
        package: '__dynamic__',
        symbols: [],
        kind: 'require-dynamic',
        line,
        caveat: 'dynamic require() — package and symbols unknown at analysis time',
      })
    }
    return
  }

  for (const key of Object.keys(node as object)) {
    const val: AstNode = node[key]
    if (Array.isArray(val)) {
      for (const item of val as AstNode[]) {
        if (item && typeof item === 'object' && (item as AstNode).type) {
          walkRequires(item, records)
        }
      }
    } else if (val && typeof val === 'object' && (val as AstNode).type) {
      walkRequires(val, records)
    }
  }
}

function parseFileImports(filePath: string): ImportRecord[] {
  let code: string
  try {
    code = readFileSync(filePath, 'utf8')
  } catch {
    return []
  }

  let body: AstNode[]
  try {
    const ast = parse(code, {
      jsx: filePath.endsWith('.tsx') || filePath.endsWith('.jsx'),
      loc: true,
      range: false,
    })
    body = (ast as AstNode).body as AstNode[]
  } catch {
    return []
  }

  const records: ImportRecord[] = []

  for (const node of body) {
    const type = node.type as string
    if (type === 'ImportDeclaration') {
      handleImportDeclaration(node, records)
    } else if (type === 'ExportNamedDeclaration' && node.source) {
      handleNamedReExport(node, records)
    } else if (type === 'ExportAllDeclaration' && node.source) {
      handleReExportAll(node, records)
    } else {
      walkRequires(node, records)
    }
  }

  return records
}

/**
 * Build an import graph for all JS/TS files under dir.
 * Files are processed in sorted order for deterministic output.
 * Respects .gitignore and the ignorePatterns option.
 */
export function buildImportGraph(dir: string, options: AnalyzeOptions = {}): ImportGraph {
  const files = discoverFiles(dir, options)
  const graph: ImportGraph = new Map()

  for (const file of files) {
    const records = parseFileImports(file)
    if (records.length > 0) graph.set(file, records)
  }

  return graph
}

/**
 * Find all files importing packageName and check which affected symbols they import.
 * conservative=true means at least one match cannot enumerate specific symbols
 * (namespace, default, or dynamic require), so the vulnerable symbol cannot be ruled out.
 */
export function matchImports(
  graph: ImportGraph,
  packageName: string,
  affectedSymbols: AffectedSymbol[],
): ImportMatchResult {
  const affectedNames = new Set(affectedSymbols.map((s) => s.name))
  const matches: FileImportMatch[] = []
  let conservative = false
  let packageSeen = false

  for (const [file, records] of graph) {
    for (const record of records) {
      if (record.package !== packageName) continue
      packageSeen = true

      if (record.symbols.length === 0) {
        conservative = true
        const m: FileImportMatch = {
          file,
          line: record.line,
          kind: record.kind,
          matchedSymbols: [],
          caveat: record.caveat ?? 'conservative — specific symbols unknown',
        }
        matches.push(m)
      } else {
        const matched = record.symbols.filter((s) => affectedNames.has(s))
        if (matched.length > 0) {
          const m: FileImportMatch = {
            file,
            line: record.line,
            kind: record.kind,
            matchedSymbols: matched,
          }
          if (record.caveat !== undefined) m.caveat = record.caveat
          matches.push(m)
        }
      }
    }
  }

  return { packageName, matches, conservative, packageSeen }
}
