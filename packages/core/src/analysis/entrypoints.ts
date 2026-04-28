/* eslint-disable @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unnecessary-type-assertion */
import { parse } from '@typescript-eslint/parser'
import { readFileSync } from 'node:fs'
import { relative } from 'node:path'
import type { EntryPoint } from '../types.js'
import { discoverFiles } from './import.js'
import type { AnalyzeOptions } from './import.js'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AstNode = any

// ─── constants ────────────────────────────────────────────────────────────────

const EXPRESS_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'use'])
const FASTIFY_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all'])
const NEXTJS_HTTP_EXPORTS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const AUTH_PATTERN = /^(auth|require|verify|check|guard|protect|authenticate)/i
const CLI_PACKAGES = new Set(['commander', 'yargs', 'minimist', 'meow'])

// ─── helpers ──────────────────────────────────────────────────────────────────

function getString(node: AstNode): string | null {
  if (!node) return null
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value as string
  if (node.type === 'TemplateLiteral' && (node.quasis as AstNode[]).length === 1) {
    return ((node.quasis as AstNode[])[0]?.value?.cooked as string | undefined) ?? null
  }
  return null
}

function getLine(node: AstNode): number {
  return (node?.loc?.start?.line as number | undefined) ?? 0
}

function isAuthLike(node: AstNode): boolean {
  const name: string =
    node?.type === 'Identifier'
      ? (node.name as string)
      : node?.type === 'MemberExpression'
        ? ((node.property?.name as string | undefined) ?? '')
        : ''
  return AUTH_PATTERN.test(name)
}

// Checks any middleware arg (between path at [0] and final handler) for auth-like name
function hasAuthMiddleware(args: AstNode[]): boolean {
  return args.length >= 2 && args.slice(1, -1).some((a: AstNode) => isAuthLike(a))
}

// ─── Next.js path detection ───────────────────────────────────────────────────

function isNextjsApiFile(filePath: string, projectDir: string): boolean {
  const rel = relative(projectDir, filePath).replace(/\\/g, '/')
  return /^pages\/api\//.test(rel) || /^app\/api\/.*\/route\.[jt]sx?$/.test(rel)
}

function isNextjsPagesApi(filePath: string, projectDir: string): boolean {
  return /^pages\/api\//.test(relative(projectDir, filePath).replace(/\\/g, '/'))
}

// ─── Binding collection pass ──────────────────────────────────────────────────

interface Bindings {
  express: Set<string>
  fastify: Set<string>
  hasCli: boolean
}

function collectBindings(body: AstNode[]): Bindings {
  const b: Bindings = { express: new Set(), fastify: new Set(), hasCli: false }
  for (const node of body) visitBinding(node, b)
  return b
}

function visitBinding(node: AstNode, b: Bindings): void {
  if (!node || typeof node !== 'object' || !node.type) return
  const type = node.type as string

  if (type === 'ImportDeclaration') {
    const src = getString(node.source)
    for (const spec of node.specifiers as AstNode[]) {
      const local: string = (spec.local?.name as string | undefined) ?? ''
      const specType = spec.type as string
      if (specType === 'ImportDefaultSpecifier' || specType === 'ImportNamespaceSpecifier') {
        if (src === 'express') b.express.add(local)
        if (src === 'fastify') b.fastify.add(local)
      }
      if (src && CLI_PACKAGES.has(src)) b.hasCli = true
    }
    return
  }

  if (type === 'VariableDeclaration') {
    for (const decl of node.declarations as AstNode[]) {
      const id = decl.id as AstNode
      const init = decl.init as AstNode
      if (!init || id?.type !== 'Identifier') continue
      const varName: string = id.name as string

      if (isCallOfName(init, 'express') || isRequireCallOf(init, 'express')) {
        b.express.add(varName)
      }
      if (isMemberCall(init, 'express', 'Router')) b.express.add(varName)
      if (
        isCallOfName(init, 'Fastify') ||
        isCallOfName(init, 'fastify') ||
        isRequireCallOf(init, 'fastify')
      ) {
        b.fastify.add(varName)
      }

      const reqPkg = getRequiredPkg(init)
      if (reqPkg && CLI_PACKAGES.has(reqPkg)) b.hasCli = true
    }
  }

  recurseBinding(node, b)
}

function recurseBinding(node: AstNode, b: Bindings): void {
  for (const key of Object.keys(node as object)) {
    if (key === 'type' || key === 'loc' || key === 'range') continue
    const val = (node as Record<string, unknown>)[key]
    if (!val || typeof val !== 'object') continue
    if (Array.isArray(val)) {
      for (const item of val as AstNode[]) {
        if (item && typeof item === 'object' && (item as AstNode).type)
          visitBinding(item as AstNode, b)
      }
    } else if ((val as AstNode).type) {
      visitBinding(val as AstNode, b)
    }
  }
}

// ─── Call expression predicates ───────────────────────────────────────────────

function isCallOfName(node: AstNode, name: string): boolean {
  return (
    node?.type === 'CallExpression' &&
    node.callee?.type === 'Identifier' &&
    (node.callee.name as string) === name
  )
}

function isMemberCall(node: AstNode, obj: string, method: string): boolean {
  return (
    node?.type === 'CallExpression' &&
    node.callee?.type === 'MemberExpression' &&
    node.callee.object?.type === 'Identifier' &&
    (node.callee.object.name as string) === obj &&
    (node.callee.property?.name as string) === method
  )
}

function isRequireCallOf(node: AstNode, pkg: string): boolean {
  if (node?.type !== 'CallExpression') return false
  const callee = node.callee as AstNode
  if (
    callee?.type === 'CallExpression' &&
    callee.callee?.type === 'Identifier' &&
    (callee.callee.name as string) === 'require'
  ) {
    return getString((callee.arguments as AstNode[])[0]) === pkg
  }
  return false
}

function getRequiredPkg(node: AstNode): string | null {
  if (
    node?.type === 'CallExpression' &&
    node.callee?.type === 'Identifier' &&
    (node.callee.name as string) === 'require'
  ) {
    return getString((node.arguments as AstNode[])[0])
  }
  return null
}

// ─── Pattern detection pass ───────────────────────────────────────────────────

function detectPatterns(
  body: AstNode[],
  file: string,
  projectDir: string,
  bindings: Bindings,
): EntryPoint[] {
  const results: EntryPoint[] = []
  const seen = new Set<string>()
  const isNextjs = isNextjsApiFile(file, projectDir)
  const isPagesApi = isNextjsPagesApi(file, projectDir)

  function add(ep: EntryPoint): void {
    const key = `${ep.kind}|${ep.framework ?? ''}|${ep.description}`
    if (seen.has(key)) return
    seen.add(key)
    results.push(ep)
  }

  function visit(node: AstNode): void {
    if (!node || typeof node !== 'object' || !node.type) return
    const type = node.type as string

    // ── Express / Fastify routes ──────────────────────────────────
    if (type === 'CallExpression') {
      const callee = node.callee as AstNode
      if (callee?.type === 'MemberExpression') {
        const obj: string = (callee.object?.name as string | undefined) ?? ''
        const method: string = (callee.property?.name as string | undefined) ?? ''
        const args: AstNode[] = node.arguments as AstNode[]

        if (bindings.express.has(obj) && EXPRESS_METHODS.has(method) && args.length >= 1) {
          const path = getString(args[0]) ?? '<dynamic>'
          add({
            file,
            line: getLine(node),
            kind: 'http',
            framework: 'express',
            authenticated: hasAuthMiddleware(args),
            description: `Express ${method.toUpperCase()} ${path}`,
          })
        }

        if (bindings.fastify.has(obj) && FASTIFY_METHODS.has(method) && args.length >= 1) {
          const path = getString(args[0]) ?? '<dynamic>'
          add({
            file,
            line: getLine(node),
            kind: 'http',
            framework: 'fastify',
            authenticated: hasAuthMiddleware(args),
            description: `Fastify ${method.toUpperCase()} ${path}`,
          })
        }

        // fastify.route({ method, url, handler })
        if (bindings.fastify.has(obj) && method === 'route' && args.length >= 1) {
          const opts = args[0] as AstNode
          if (opts?.type === 'ObjectExpression') {
            const props = opts.properties as AstNode[]
            const httpMethod =
              getString(
                props.find((p: AstNode) => p.key?.name === 'method' || p.key?.value === 'method')
                  ?.value,
              ) ?? 'ROUTE'
            const url =
              getString(
                props.find((p: AstNode) => p.key?.name === 'url' || p.key?.value === 'url')?.value,
              ) ?? '<dynamic>'
            add({
              file,
              line: getLine(node),
              kind: 'http',
              framework: 'fastify',
              authenticated: false,
              description: `Fastify ${httpMethod} ${url}`,
            })
          }
        }

        // fastify.addHook('preHandler' | 'onRequest', ...) — global auth hook
        if (bindings.fastify.has(obj) && method === 'addHook') {
          const hookName = getString(args[0])
          if (hookName === 'preHandler' || hookName === 'onRequest') {
            add({
              file,
              line: getLine(node),
              kind: 'http',
              framework: 'fastify',
              authenticated: true,
              description: `Fastify ${hookName} hook`,
            })
          }
        }

        // fs.readFile / readFileSync / createReadStream with non-literal path
        if (
          obj === 'fs' &&
          (method === 'readFile' || method === 'readFileSync' || method === 'createReadStream')
        ) {
          const firstArg = args[0] as AstNode
          if (firstArg && getString(firstArg) === null) {
            add({
              file,
              line: getLine(node),
              kind: 'file-input',
              authenticated: false,
              description: `fs.${method} with dynamic path`,
            })
          }
        }

        // commander / yargs: program.parse(process.argv) or .parseAsync(process.argv)
        if (
          bindings.hasCli &&
          (method === 'parse' || method === 'parseAsync') &&
          args.length >= 1
        ) {
          const firstArg = args[0] as AstNode
          if (
            firstArg?.type === 'MemberExpression' &&
            (firstArg.object?.name as string) === 'process' &&
            (firstArg.property?.name as string) === 'argv'
          ) {
            add({
              file,
              line: getLine(node),
              kind: 'cli',
              authenticated: false,
              description: 'CLI parse(process.argv)',
            })
          }
        }
      }
    }

    // ── process.env.X ─────────────────────────────────────────────
    if (
      type === 'MemberExpression' &&
      node.object?.type === 'MemberExpression' &&
      (node.object.object?.name as string) === 'process' &&
      (node.object.property?.name as string) === 'env'
    ) {
      const envVar: string = (node.property?.name as string | undefined) ?? '<dynamic>'
      add({
        file,
        line: getLine(node),
        kind: 'env',
        authenticated: false,
        description: `process.env.${envVar}`,
      })
    }

    // ── process.argv direct access ─────────────────────────────────
    if (
      type === 'MemberExpression' &&
      node.object?.type === 'Identifier' &&
      (node.object.name as string) === 'process' &&
      (node.property?.name as string) === 'argv'
    ) {
      add({
        file,
        line: getLine(node),
        kind: 'cli',
        authenticated: false,
        description: 'process.argv',
      })
    }

    // ── Next.js named exports (app/api/**/route.ts) ────────────────
    if (isNextjs && type === 'ExportNamedDeclaration') {
      const decl = node.declaration as AstNode
      if (decl?.type === 'FunctionDeclaration') {
        const name: string = (decl.id?.name as string | undefined) ?? ''
        if (NEXTJS_HTTP_EXPORTS.has(name)) {
          add({
            file,
            line: getLine(node),
            kind: 'http',
            framework: 'nextjs',
            authenticated: false,
            description: `Next.js ${name} handler`,
          })
        }
      }
      if (decl?.type === 'VariableDeclaration') {
        for (const d of decl.declarations as AstNode[]) {
          const name: string = (d.id?.name as string | undefined) ?? ''
          if (NEXTJS_HTTP_EXPORTS.has(name)) {
            add({
              file,
              line: getLine(node),
              kind: 'http',
              framework: 'nextjs',
              authenticated: false,
              description: `Next.js ${name} handler`,
            })
          }
        }
      }
    }

    // ── Next.js pages/api default export ──────────────────────────
    if (isPagesApi && type === 'ExportDefaultDeclaration') {
      add({
        file,
        line: getLine(node),
        kind: 'http',
        framework: 'nextjs',
        authenticated: false,
        description: 'Next.js pages/api default handler',
      })
    }

    // ── Recurse into children ──────────────────────────────────────
    for (const key of Object.keys(node as object)) {
      if (key === 'type' || key === 'loc' || key === 'range') continue
      const val = (node as Record<string, unknown>)[key]
      if (!val || typeof val !== 'object') continue
      if (Array.isArray(val)) {
        for (const item of val as AstNode[]) {
          if (item && typeof item === 'object' && (item as AstNode).type) visit(item as AstNode)
        }
      } else if ((val as AstNode).type) {
        visit(val as AstNode)
      }
    }
  }

  for (const node of body) visit(node)
  return results
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface EntryPointOptions extends AnalyzeOptions {
  customEntryPoints?: string[]
}

/**
 * Detect entry points (HTTP routes, CLI, env, file-input) across all JS/TS
 * files under dir. Respects .gitignore and ignorePatterns.
 */
export function detectEntryPoints(dir: string, options: EntryPointOptions = {}): EntryPoint[] {
  const files = discoverFiles(dir, options)
  const results: EntryPoint[] = []

  for (const file of files) {
    let code: string
    try {
      code = readFileSync(file, 'utf8')
    } catch {
      continue
    }

    let body: AstNode[]
    try {
      const ast = parse(code, {
        jsx: file.endsWith('.tsx') || file.endsWith('.jsx'),
        loc: true,
        range: false,
      })
      body = (ast as AstNode).body as AstNode[]
    } catch {
      continue
    }

    const bindings = collectBindings(body)
    results.push(...detectPatterns(body, file, dir, bindings))
  }

  for (const ep of options.customEntryPoints ?? []) {
    results.push({
      file: ep,
      line: 0,
      kind: 'custom',
      authenticated: false,
      description: `custom entry point: ${ep}`,
    })
  }

  return results
}
