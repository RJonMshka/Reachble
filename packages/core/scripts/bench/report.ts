import type { BenchResult, TopFinding } from './types.js'

function fmtMs(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

function findingsTable(findings: TopFinding[]): string {
  if (findings.length === 0) return ''
  const header = '| CVE | Package | CVSS | EPSS | Reason |\n|-----|---------|------|------|--------|'
  const rows = findings
    .map(
      (f) =>
        `| ${f.cveId} | \`${f.package}@${f.version}\` | ${f.cvssScore.toFixed(1)} | ${f.epssScore.toFixed(3)} | ${f.reason.slice(0, 80)} |`,
    )
    .join('\n')
  return `${header}\n${rows}`
}

function verdictPct(count: number, total: number): string {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return `${count} (${pct}%)`
}

// ── Per-repo section ──────────────────────────────────────────────────────────

function repoSection(r: BenchResult): string {
  const lines: string[] = []
  lines.push(`### ${r.repo}  \`@ ${r.ref}\``)
  lines.push('')
  if (r.notes !== undefined) {
    lines.push(`> ${r.notes}`)
    lines.push('')
  }

  if (r.error !== undefined) {
    lines.push(`**Error:** \`${r.error}\``)
    return lines.join('\n')
  }

  const { totalCves: total, verdicts: vd } = r

  // Code stats
  lines.push('**Analysis coverage**')
  lines.push('')
  lines.push('| Metric | Value |')
  lines.push('|--------|-------|')
  lines.push(`| Packages in lockfile | ${r.packageCount} |`)
  lines.push(`| TypeScript / JS files | ${r.fileCount} |`)
  lines.push(`| CVEs from OSV | ${total} |`)
  lines.push(`| CVEs with symbol data | ${r.cvesWithSymbols} / ${total} |`)
  lines.push(
    `| Entry points | ${r.entryPointCount} total, ${r.unauthenticatedEpCount} unauthenticated |`,
  )
  if (r.callGraphEnabled) {
    lines.push(`| Call graph edges | ${r.callEdgeCount} |`)
    lines.push(`| Verdicts elevated by call graph | ${r.callGraphElevations} |`)
  } else {
    lines.push('| Call graph | disabled |')
  }
  lines.push('')

  // Verdict distribution
  lines.push('**Verdict distribution**')
  lines.push('')
  lines.push('| Verdict | Count | Share |')
  lines.push('|---------|-------|-------|')
  for (const v of ['CRITICAL', 'HIGH', 'LOW', 'SAFE'] as const) {
    lines.push(`| \`${v}\` | ${vd[v]} | ${verdictPct(vd[v], total)} |`)
  }
  lines.push('')
  lines.push(
    `**Noise reduction: ${r.noiseReduction}%** — ${vd.SAFE} of ${total} CVEs are SAFE ` +
      `(the vulnerable symbol is absent or unreachable).`,
  )
  lines.push('')

  // Findings
  if (r.topCritical.length > 0) {
    lines.push('**Top CRITICAL findings** *(reachable from unauthenticated entry point)*')
    lines.push('')
    lines.push(findingsTable(r.topCritical))
    lines.push('')
  }
  if (r.topHigh.length > 0) {
    lines.push('**Top HIGH findings** *(reachable from authenticated entry point)*')
    lines.push('')
    lines.push(findingsTable(r.topHigh))
    lines.push('')
  }

  // Phase timings
  lines.push('**Phase timings**')
  lines.push('')
  lines.push('| Phase | Time |')
  lines.push('|-------|------|')
  lines.push(`| Lockfile parse | ${fmtMs(r.timings.lockfileParse)} |`)
  lines.push(`| Import graph | ${fmtMs(r.timings.importGraph)} |`)
  lines.push(`| File graph | ${fmtMs(r.timings.fileGraph)} |`)
  lines.push(`| Entry point detection | ${fmtMs(r.timings.entryPoints)} |`)
  if (r.callGraphEnabled) {
    lines.push(`| Call graph (ts-morph) | ${fmtMs(r.timings.callGraph)} |`)
  }
  lines.push(`| CVE resolution (OSV + EPSS) | ${fmtMs(r.timings.cveResolution)} |`)
  lines.push(`| Verdict scoring | ${fmtMs(r.timings.verdictScoring)} |`)
  lines.push(`| **Total** | **${fmtMs(r.timings.total)}** |`)

  return lines.join('\n')
}

// ── Aggregate analysis section ─────────────────────────────────────────────────

function analysisSection(ok: BenchResult[], callGraph: boolean): string {
  if (ok.length === 0) return ''

  const totalCves = ok.reduce((n, r) => n + r.totalCves, 0)
  const totalCvesWithSymbols = ok.reduce((n, r) => n + r.cvesWithSymbols, 0)
  const totalCritical = ok.reduce((n, r) => n + r.verdicts.CRITICAL, 0)
  const totalHigh = ok.reduce((n, r) => n + r.verdicts.HIGH, 0)
  const totalSafe = ok.reduce((n, r) => n + r.verdicts.SAFE, 0)
  const avgNoiseReduction = Math.round(
    ok.reduce((n, r) => n + r.noiseReduction, 0) / ok.length,
  )
  const totalElevations = ok.reduce((n, r) => n + r.callGraphElevations, 0)
  const avgScanMs = Math.round(ok.reduce((n, r) => n + r.timings.total, 0) / ok.length)
  const symbolCovPct =
    totalCves > 0 ? Math.round((totalCvesWithSymbols / totalCves) * 100) : 0

  const lines: string[] = []
  lines.push('## Analysis')
  lines.push('')
  lines.push(`### Aggregate (${ok.length} repos)`)
  lines.push('')
  lines.push('| Metric | Value |')
  lines.push('|--------|-------|')
  lines.push(`| Total CVEs | ${totalCves} |`)
  lines.push(`| CRITICAL | ${totalCritical} |`)
  lines.push(`| HIGH | ${totalHigh} |`)
  lines.push(`| SAFE (eliminated noise) | ${totalSafe} |`)
  lines.push(`| Average noise reduction | ${avgNoiseReduction}% |`)
  if (callGraph) lines.push(`| Call graph elevations | ${totalElevations} |`)
  lines.push(`| Symbol coverage | ${totalCvesWithSymbols} / ${totalCves} (${symbolCovPct}%) |`)
  lines.push(`| Average scan time | ${fmtMs(avgScanMs)} |`)
  lines.push('')

  lines.push('### Key findings')
  lines.push('')
  lines.push(
    `1. **${avgNoiseReduction}% average noise reduction.** ` +
      `Naive scanners (npm audit, Snyk) report every CVE in the dependency tree. ` +
      `Reachble silences the majority that cannot be triggered because the ` +
      `vulnerable symbol is never imported or has no path from an entry point.`,
  )
  lines.push('')
  lines.push(
    `2. **${totalCritical + totalHigh} actionable findings across all repos.** ` +
      `These are traced from a real HTTP/CLI entry point to the vulnerable call site — ` +
      `not just "the package is installed."`,
  )
  if (callGraph && totalElevations > 0) {
    lines.push('')
    lines.push(
      `3. **${totalElevations} call-graph elevations.** ` +
        `The ts-morph call graph promoted these from LOW (import exists but uncalled) ` +
        `to HIGH/CRITICAL — precision that import-level analysis cannot provide.`,
    )
  }
  lines.push('')

  lines.push('### Accuracy notes')
  lines.push('')
  lines.push(
    'Reachble V1 is a **static over-approximation**: it may emit false positives ' +
      '(dynamic dispatch or conditional imports that never execute the vulnerable branch) ' +
      'but should not miss explicitly-imported symbols. Dynamic call edges are tagged ' +
      '`confidence: low` with a `caveat` so analysts can filter them separately.',
  )
  lines.push('')
  lines.push(
    `Symbol coverage is ${symbolCovPct}%: ${totalCvesWithSymbols} of ${totalCves} CVEs ` +
      'carry specific function-level data from OSV / fix-commit diffs. ' +
      'The remainder are assessed at package level (conservative LOW).',
  )

  return lines.join('\n')
}

// ── Public API ─────────────────────────────────────────────────────────────────

export interface ReportOptions {
  callGraph: boolean
}

export function generateMarkdownReport(results: BenchResult[], opts: ReportOptions): string {
  const date = new Date().toISOString().slice(0, 10)
  const ok = results.filter((r) => r.error === undefined)
  const lines: string[] = []

  // Header
  lines.push('# Reachble V1 — OSS Benchmark Report')
  lines.push('')
  lines.push(
    `**Date:** ${date}  \n` +
      `**Mode:** ${opts.callGraph ? 'Full V1 — import + call graph + entry points' : 'Import + entry points (call graph disabled)'}  \n` +
      `**Repos tested:** ${results.length}`,
  )
  lines.push('')

  // Summary table
  lines.push('## Summary')
  lines.push('')
  lines.push('| Repo | Packages | CVEs | CRITICAL | HIGH | LOW | SAFE | Noise↓ | Time |')
  lines.push('|------|----------|------|----------|------|-----|------|--------|------|')
  for (const r of results) {
    if (r.error !== undefined) {
      lines.push(`| ${r.repo} | — | — | — | — | — | — | — | **ERROR** |`)
    } else {
      lines.push(
        `| ${r.repo} | ${r.packageCount} | ${r.totalCves} | **${r.verdicts.CRITICAL}** | ${r.verdicts.HIGH} | ${r.verdicts.LOW} | ${r.verdicts.SAFE} | ${r.noiseReduction}% | ${fmtMs(r.timings.total)} |`,
      )
    }
  }
  lines.push('')
  lines.push(
    '> **Noise Reduction** = % of OSV CVEs that Reachble marks SAFE ' +
      '(absent symbol or no reachable path). A naive scanner would flag all of these.',
  )
  lines.push('')

  // Per-repo details
  lines.push('## Per-Repo Details')
  lines.push('')
  lines.push(results.map(repoSection).join('\n\n---\n\n'))
  lines.push('')

  // Aggregate analysis
  lines.push(analysisSection(ok, opts.callGraph))

  return lines.join('\n')
}
