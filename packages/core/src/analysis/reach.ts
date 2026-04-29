import type { CallEdge, EntryPoint, FileGraph } from '../types.js'

export const TEST_FILE_PATTERN = /\.(test|spec)\.[cm]?[jt]sx?$|\/__tests__\//

export function isTestFile(file: string): boolean {
  return TEST_FILE_PATTERN.test(file)
}

export interface ReachPath {
  /** Ordered file chain from entry-point file to the file containing the call site. */
  filePath: string[]
  callSite: CallEdge
  /** True when the terminal call to the package is a dynamic dispatch. */
  hasDynamicEdge: boolean
}

/**
 * BFS from `start` through `fileGraph` to any file in `targets`.
 * Returns the ordered path (inclusive of start and target), or null if unreachable.
 * Uses a parent-pointer map so the path can be reconstructed without extra storage.
 */
export function bfsPath(
  start: string,
  targets: Set<string>,
  fileGraph: FileGraph,
  depthLimit = 25,
): string[] | null {
  if (targets.has(start)) return [start]

  const parent = new Map<string, string>()
  const seen = new Set<string>([start])
  const queue: Array<{ file: string; depth: number }> = [{ file: start, depth: 0 }]

  while (queue.length > 0) {
    const item = queue.shift()
    if (item === undefined) break
    const { file, depth } = item
    if (depth >= depthLimit) continue

    const deps = fileGraph.get(file) ?? []
    for (const dep of deps) {
      if (seen.has(dep)) continue
      seen.add(dep)
      parent.set(dep, file)

      if (targets.has(dep)) {
        const path: string[] = [dep]
        let cur = dep
        let p: string | undefined
        while ((p = parent.get(cur)) !== undefined) {
          path.unshift(p)
          cur = p
        }
        return path
      }

      queue.push({ file: dep, depth: depth + 1 })
    }
  }

  return null
}

/**
 * Find the shortest call path from an entry point to any of the given call sites.
 * Returns null if no path exists or if `callSites` is empty.
 */
export function findCallPath(
  ep: EntryPoint,
  callSites: CallEdge[],
  fileGraph: FileGraph,
  depthLimit = 25,
): ReachPath | null {
  if (callSites.length === 0) return null

  const targetFiles = new Set(callSites.map((e) => e.callerFile))
  const filePath = bfsPath(ep.file, targetFiles, fileGraph, depthLimit)
  if (filePath === null) return null

  const lastFile = filePath[filePath.length - 1]
  if (lastFile === undefined) return null
  const site = callSites.find((e) => e.callerFile === lastFile)
  if (site === undefined) return null

  return { filePath, callSite: site, hasDynamicEdge: site.dynamic }
}
