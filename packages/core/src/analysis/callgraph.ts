import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { Node, Project, type ProjectOptions, type Symbol as TsSymbol } from 'ts-morph'
import type { CallEdge, CallGraph } from '../types.js'
import type { AnalyzeOptions } from './import.js'

export interface CallGraphOptions extends AnalyzeOptions {
  tsConfigPath?: string
}

function findTsConfig(dir: string): string | null {
  for (const name of ['tsconfig.json', 'jsconfig.json']) {
    const p = join(dir, name)
    if (existsSync(p)) return p
  }
  return null
}

function packageFromPath(filePath: string): string | null {
  const match = /node_modules[\\/](@[^\\/]+[\\/][^\\/]+|[^\\/]+)/.exec(filePath)
  if (!match?.[1]) return null
  const pkg = match[1].replace(/\\/g, '/')
  return pkg.startsWith('@types/') ? pkg.slice('@types/'.length) : pkg
}

function getEnclosingFunction(node: Node): string {
  let current: Node | undefined = node.getParent()
  while (current !== undefined) {
    if (Node.isFunctionDeclaration(current)) return current.getName() ?? '<anonymous>'
    if (Node.isMethodDeclaration(current)) return current.getName()
    if (Node.isArrowFunction(current) || Node.isFunctionExpression(current)) {
      const parent = current.getParent()
      if (Node.isVariableDeclaration(parent)) return parent.getName()
      return '<anonymous>'
    }
    current = current.getParent()
  }
  return '<module>'
}

/** Resolve an import alias to its original declaration (follows re-exports/import bindings). */
function resolveDecl(sym: TsSymbol | undefined): Node | undefined {
  if (sym === undefined) return undefined
  const target = sym.getAliasedSymbol() ?? sym
  return target.getValueDeclaration()
}

/** For namespace/default imports: look up a named export/member on the aliased module symbol. */
function resolveMemberDecl(objSym: TsSymbol | undefined, memberName: string): Node | undefined {
  if (objSym === undefined) return undefined
  const target = objSym.getAliasedSymbol() ?? objSym
  // Try module export first (namespace imports), then object member (class / default-export objects)
  const memberSym = target.getExport(memberName) ?? target.getMember(memberName)
  return resolveDecl(memberSym)
}

/**
 * Extract call edges from a ts-morph Project.
 * Exposed separately so tests can supply an in-memory project.
 */
export function extractCallEdges(project: Project): CallGraph {
  const callGraph: CallGraph = new Map()

  for (const sourceFile of project.getSourceFiles()) {
    const filePath = sourceFile.getFilePath()
    if (filePath.includes('node_modules')) continue

    const edges: CallEdge[] = []

    sourceFile.forEachDescendant((node) => {
      if (!Node.isCallExpression(node)) return

      const expression = node.getExpression()
      const line = node.getStartLineNumber()
      let calleePackage: string | null = null
      let calleeSymbol: string | null = null
      const dynamic = false

      if (Node.isIdentifier(expression)) {
        // Direct call: dangerousFn(...)
        const decl = resolveDecl(expression.getSymbol())
        if (decl !== undefined) {
          const pkg = packageFromPath(decl.getSourceFile().getFilePath())
          if (pkg !== null) {
            calleePackage = pkg
            calleeSymbol = expression.getText()
          }
        }
      } else if (Node.isPropertyAccessExpression(expression)) {
        // Member call: ns.dangerousFn(...) or _.template(...)
        const memberName = expression.getName()
        // Try the property symbol directly first (works when TypeScript resolves the member type)
        const propDecl =
          resolveDecl(expression.getSymbol()) ??
          resolveMemberDecl(expression.getExpression().getSymbol(), memberName)
        if (propDecl !== undefined) {
          const pkg = packageFromPath(propDecl.getSourceFile().getFilePath())
          if (pkg !== null) {
            calleePackage = pkg
            calleeSymbol = memberName
          }
        }
      }

      if (calleePackage !== null && calleeSymbol !== null) {
        edges.push({
          callerFile: filePath,
          callerFunction: getEnclosingFunction(node),
          calleePackage,
          calleeSymbol,
          line,
          dynamic,
        })
      }
    })

    if (edges.length > 0) callGraph.set(filePath, edges)
  }

  return callGraph
}

/**
 * Build a call graph for a project directory.
 * Returns null when no tsconfig.json / jsconfig.json is found — callers fall back to import-level analysis.
 */
export function buildCallGraph(dir: string, opts: CallGraphOptions = {}): CallGraph | null {
  const tsConfigPath = opts.tsConfigPath ?? findTsConfig(dir)
  if (tsConfigPath === null) return null

  try {
    const projectOpts: ProjectOptions = { tsConfigFilePath: tsConfigPath }
    const project = new Project(projectOpts)
    return extractCallEdges(project)
  } catch {
    return null
  }
}
