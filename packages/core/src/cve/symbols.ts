import type { AffectedSymbol } from '../types.js'
import type { OsvAffected, OsvVulnerability } from './schemas.js'

// ── OSV affected_functions extraction ────────────────────────────────────────

function symbolTypeFromName(name: string): AffectedSymbol['type'] {
  if (name.includes('.')) return 'method'
  if (/^[A-Z]/.test(name)) return 'class'
  if (name.endsWith('()') || name.includes('(')) return 'function'
  return 'function'
}

function cleanSymbolName(raw: string): string {
  // Strip trailing "()" and leading module prefixes like "_.template" → keep as-is
  return raw.replace(/\(\s*\)$/, '').trim()
}

function fromOsvAffected(affected: OsvAffected[]): AffectedSymbol[] {
  const symbols: AffectedSymbol[] = []
  for (const entry of affected) {
    if (entry.package.ecosystem !== 'npm') continue
    const fns = entry.ecosystem_specific?.affected_functions ?? []
    for (const fn of fns) {
      const name = cleanSymbolName(fn)
      if (!name) continue
      symbols.push({ name, type: symbolTypeFromName(name), confidence: 'high', source: 'osv' })
    }
  }
  return symbols
}

// ── NVD / GHSA description regex extraction ──────────────────────────────────

// Patterns that suggest a specific symbol in prose:
//   `foo`, `foo()`, `Foo.bar`, function foo, method foo, Class.bar, export foo
const BACKTICK_RE = /`([A-Za-z_$][\w$.]*(?:\(\))?)`/g
const FUNCTION_RE = /\b(?:function|method|class)\s+([A-Za-z_$][\w$]*)/gi
const CLASS_METHOD_RE = /\b([A-Z][A-Za-z0-9$]*\.[a-z_$][\w$]*)\b/g

function dedupe(symbols: AffectedSymbol[]): AffectedSymbol[] {
  const seen = new Set<string>()
  return symbols.filter((s) => {
    if (seen.has(s.name)) return false
    seen.add(s.name)
    return true
  })
}

function fromDescription(description: string, source: AffectedSymbol['source']): AffectedSymbol[] {
  const symbols: AffectedSymbol[] = []

  for (const match of description.matchAll(BACKTICK_RE)) {
    const name = cleanSymbolName(match[1] ?? '')
    if (name) {
      symbols.push({ name, type: symbolTypeFromName(name), confidence: 'medium', source })
    }
  }

  for (const match of description.matchAll(FUNCTION_RE)) {
    const name = match[1] ?? ''
    if (name) {
      symbols.push({ name, type: symbolTypeFromName(name), confidence: 'medium', source })
    }
  }

  for (const match of description.matchAll(CLASS_METHOD_RE)) {
    const name = match[1] ?? ''
    if (name) {
      symbols.push({ name, type: 'method', confidence: 'medium', source })
    }
  }

  return dedupe(symbols)
}

// ── Symbol override file (src/data/symbol-overrides.json) ───────────────────

export interface SymbolOverride {
  cveId: string
  packageName: string
  symbols: Array<{ name: string; type: AffectedSymbol['type'] }>
}

// ── Main entry point ─────────────────────────────────────────────────────────

export interface ExtractOptions {
  nvdDescription?: string
  overrides?: SymbolOverride[]
}

export function extractSymbols(
  vuln: OsvVulnerability,
  opts: ExtractOptions = {},
): AffectedSymbol[] {
  // 1. OSV affected_functions (highest confidence)
  const osvSymbols = fromOsvAffected(vuln.affected)
  if (osvSymbols.length > 0) return dedupe(osvSymbols)

  // 2. Manual override
  const cveId = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id
  const override = opts.overrides?.find((o) => o.cveId === cveId)
  if (override) {
    return override.symbols.map((s) => ({
      ...s,
      confidence: 'high' as const,
      source: 'override' as const,
    }))
  }

  // 3. NVD description regex
  if (opts.nvdDescription) {
    const nvdSymbols = fromDescription(opts.nvdDescription, 'nvd-desc')
    if (nvdSymbols.length > 0) return nvdSymbols
  }

  // 4. OSV/GHSA details field
  const details = vuln.details ?? vuln.summary ?? ''
  if (details) {
    const ghsaSymbols = fromDescription(details, 'ghsa-desc')
    if (ghsaSymbols.length > 0) return ghsaSymbols
  }

  // 5. Package-level fallback — no specific symbols known
  return []
}
