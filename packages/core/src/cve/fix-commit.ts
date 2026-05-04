import type { AffectedSymbol } from '../types.js'

// ── URL parsing ───────────────────────────────────────────────────────────────

export interface CommitRef {
  owner: string
  repo: string
  sha: string
}

/**
 * Parse a GitHub commit URL into { owner, repo, sha }.
 * Handles:
 *   https://github.com/owner/repo/commit/sha
 *   https://github.com/owner/repo/pull/123/commits/sha
 */
export function parseGithubCommitUrl(url: string): CommitRef | null {
  const m = /github\.com\/([^/]+)\/([^/]+)\/(?:pull\/\d+\/)?commits?\/([0-9a-f]{7,40})\b/i.exec(url)
  if (!m) return null
  const owner = m[1]
  const repo = m[2]
  const sha = m[3]
  if (!owner || !repo || !sha) return null
  return { owner, repo, sha }
}

// ── Diff parsing ──────────────────────────────────────────────────────────────

const JS_EXT_RE = /\.[cm]?[jt]sx?$/i

// Hunk header: @@ -a,b +c,d @@ <optional git context>
const HUNK_HEADER_RE = /^@@ [^@]+ @@ (.+)$/

// Patterns that capture a symbol name in a JS/TS line (used on both hunk
// context and changed lines).
const DEF_PATTERNS: RegExp[] = [
  /(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)\s*[(<]/,
  /(?:export\s+)?(?:abstract\s+)?class\s+([A-Z][A-Za-z0-9_$]*)\b/,
  /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function|\()/,
  /([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s+)?(?:function|\()/,
]

function extractName(line: string): string | null {
  for (const re of DEF_PATTERNS) {
    const m = re.exec(line)
    if (m?.[1]) return m[1]
  }
  return null
}

/**
 * Pure: given a unified diff text, return the JS/TS symbols that were
 * modified. Inspects git hunk-context headers (the `@@ … @@ <fn>` suffix)
 * and any `+`/`-` lines that contain a function or class definition.
 */
export function parseSymbolsFromDiff(diffText: string): AffectedSymbol[] {
  const seen = new Set<string>()
  const symbols: AffectedSymbol[] = []
  let inJsFile = false

  function emit(name: string): void {
    if (seen.has(name)) return
    seen.add(name)
    symbols.push({
      name,
      type: /^[A-Z]/.test(name) ? 'class' : 'function',
      confidence: 'medium',
      source: 'fix-diff',
    })
  }

  for (const line of diffText.split('\n')) {
    if (line.startsWith('diff --git ')) {
      inJsFile = JS_EXT_RE.test(line)
      continue
    }
    if (!inJsFile) continue

    if (line.startsWith('@@')) {
      const m = HUNK_HEADER_RE.exec(line)
      if (m?.[1]) {
        const name = extractName(m[1])
        if (name) emit(name)
      }
      continue
    }

    // Changed lines only — don't emit symbols seen only in unmodified context
    if (line.startsWith('+') || line.startsWith('-')) {
      const name = extractName(line.slice(1))
      if (name) emit(name)
    }
  }

  return symbols
}

// ── Network fetch ─────────────────────────────────────────────────────────────

export interface FetchDiffOptions {
  githubToken?: string
}

/**
 * Fetch the unified diff for a single GitHub commit via the GitHub API.
 * Returns null if the request fails or returns a non-2xx status.
 */
export async function fetchCommitDiff(
  ref: CommitRef,
  opts: FetchDiffOptions = {},
): Promise<string | null> {
  const url = `https://api.github.com/repos/${ref.owner}/${ref.repo}/commits/${ref.sha}`
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.diff',
    'User-Agent': 'reachble-scanner/0.1',
  }
  if (opts.githubToken) {
    headers['Authorization'] = `Bearer ${opts.githubToken}`
  }

  try {
    const resp = await fetch(url, { headers })
    if (!resp.ok) return null
    return await resp.text()
  } catch {
    return null
  }
}

/**
 * Try each commit URL in order; return symbols from the first successful
 * diff parse. Returns [] when all fetches fail or no symbols are found.
 */
export async function resolveFixDiffSymbols(
  commitUrls: string[],
  opts: FetchDiffOptions = {},
): Promise<AffectedSymbol[]> {
  for (const url of commitUrls) {
    const ref = parseGithubCommitUrl(url)
    if (!ref) continue
    const diff = await fetchCommitDiff(ref, opts)
    if (!diff) continue
    const symbols = parseSymbolsFromDiff(diff)
    if (symbols.length > 0) return symbols
  }
  return []
}
