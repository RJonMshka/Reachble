#!/usr/bin/env node
/**
 * Reachble V1 — real-world OSS benchmark runner
 *
 *   pnpm benchmark                             # all repos, full V1 pipeline
 *   pnpm benchmark --repos juice-shop          # single repo
 *   pnpm benchmark --no-callgraph              # skip call graph (faster)
 *   pnpm benchmark --reuse                     # keep existing clones
 *   pnpm benchmark --bench-dir /tmp/my-bench
 *   pnpm benchmark --out results.json
 */

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'

import { cloneRepo } from './bench/clone.js'
import { runPipeline } from './bench/pipeline.js'
import { generateMarkdownReport } from './bench/report.js'
import { REPOS } from './bench/repos.js'
import type { BenchOptions, BenchResult } from './bench/types.js'

// ── CLI args ──────────────────────────────────────────────────────────────────

function parseArgs(): BenchOptions {
  const args = process.argv.slice(2)
  const opts: BenchOptions = {
    repoFilter: [],
    callGraph: true,
    reuse: false,
    offlineCve: false,
    benchDir: join(tmpdir(), 'reachble-bench'),
    outJson: resolve('bench-results.json'),
    outMd: resolve('bench-report.md'),
    githubToken: process.env['GITHUB_TOKEN'],
  }

  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string
    const next = args[i + 1] as string | undefined
    switch (a) {
      case '--no-callgraph':
        opts.callGraph = false
        break
      case '--reuse':
        opts.reuse = true
        break
      case '--offline-cve':
        opts.offlineCve = true
        break
      case '--repos':
        if (next !== undefined) {
          opts.repoFilter = next.split(',').map((s) => s.trim())
          i++
        }
        break
      case '--bench-dir':
        if (next !== undefined) {
          opts.benchDir = resolve(next)
          i++
        }
        break
      case '--out':
        if (next !== undefined) {
          opts.outJson = resolve(next)
          i++
        }
        break
      default:
        if (!a.startsWith('-')) {
          console.warn(`Unknown argument: ${a}`)
        }
    }
  }

  return opts
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtMs(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`
}

function emptyResult(
  name: string,
  url: string,
  ref: string,
  framework: string,
  err: string,
  notes?: string,
): BenchResult {
  return {
    repo: name,
    url,
    ref,
    framework,
    ...(notes !== undefined ? { notes } : {}),
    error: err,
    packageCount: 0,
    fileCount: 0,
    totalCves: 0,
    cvesWithSymbols: 0,
    entryPointCount: 0,
    unauthenticatedEpCount: 0,
    callGraphEnabled: false,
    callEdgeCount: 0,
    verdicts: { CRITICAL: 0, HIGH: 0, LOW: 0, SAFE: 0 },
    noiseReduction: 0,
    actionableFindings: 0,
    callGraphElevations: 0,
    topCritical: [],
    topHigh: [],
    timings: {
      lockfileParse: 0,
      importGraph: 0,
      fileGraph: 0,
      entryPoints: 0,
      callGraph: 0,
      cveResolution: 0,
      verdictScoring: 0,
      total: 0,
    },
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const opts = parseArgs()

  const targets =
    opts.repoFilter.length > 0
      ? REPOS.filter((r) => opts.repoFilter.includes(r.name))
      : REPOS

  if (targets.length === 0) {
    console.error(`No repos matched. Available: ${REPOS.map((r) => r.name).join(', ')}`)
    process.exit(1)
  }

  console.log('\nReachble V1 — OSS Benchmark')
  console.log('─'.repeat(60))
  console.log(`Repos:      ${targets.map((r) => r.name).join(', ')}`)
  console.log(`Call graph: ${String(opts.callGraph)}`)
  console.log(`Offline CVE: ${String(opts.offlineCve)} (uses cached data only when true)`)
  console.log(`Reuse:      ${String(opts.reuse)}`)
  console.log(`Bench dir:  ${opts.benchDir}`)
  console.log('─'.repeat(60))

  mkdirSync(opts.benchDir, { recursive: true })

  const results: BenchResult[] = []

  for (const repo of targets) {
    console.log(`\n[ ${repo.name} @ ${repo.ref} ]`)

    let cloneDir: string
    try {
      cloneDir = cloneRepo(repo, opts.benchDir, opts.reuse)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.error(`  clone failed: ${msg}`)
      results.push(emptyResult(repo.name, repo.url, repo.ref, repo.framework, msg, repo.notes))
      continue
    }

    try {
      console.log(`  running pipeline…`)
      const result = await runPipeline(repo, cloneDir, {
        callGraph: opts.callGraph,
        githubToken: opts.githubToken,
        offlineCve: opts.offlineCve,
      })
      results.push(result)

      const { verdicts: vd, timings: t } = result
      console.log(
        `  pkgs=${result.packageCount}  files=${result.fileCount}  CVEs=${result.totalCves}` +
          `  CRIT=${vd.CRITICAL}  HIGH=${vd.HIGH}  LOW=${vd.LOW}  SAFE=${vd.SAFE}`,
      )
      console.log(
        `  noise↓=${result.noiseReduction}%  EPs=${result.entryPointCount}` +
          `  edges=${result.callEdgeCount}  total=${fmtMs(t.total)}`,
      )
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.error(`  pipeline failed: ${msg}`)
      results.push(emptyResult(repo.name, repo.url, repo.ref, repo.framework, msg, repo.notes))
    }
  }

  // ── Outputs ────────────────────────────────────────────────────────────────

  writeFileSync(opts.outJson, JSON.stringify(results, null, 2))
  console.log(`\nJSON  → ${opts.outJson}`)

  const md = generateMarkdownReport(results, { callGraph: opts.callGraph })
  writeFileSync(opts.outMd, md)
  console.log(`MD    → ${opts.outMd}`)

  // Inline summary
  console.log('\n' + '═'.repeat(70))
  console.log('RESULTS SUMMARY')
  console.log('═'.repeat(70))
  for (const r of results) {
    if (r.error !== undefined) {
      console.log(`  ${r.repo.padEnd(20)} ERROR`)
    } else {
      const { verdicts: vd } = r
      console.log(
        `  ${r.repo.padEnd(20)}` +
          `  ${String(r.packageCount).padStart(5)} pkgs` +
          `  ${String(r.totalCves).padStart(4)} CVEs` +
          `  CRIT=${String(vd.CRITICAL).padStart(3)}` +
          `  HIGH=${String(vd.HIGH).padStart(3)}` +
          `  LOW=${String(vd.LOW).padStart(3)}` +
          `  SAFE=${String(vd.SAFE).padStart(4)}` +
          `  noise↓${r.noiseReduction}%` +
          `  ${fmtMs(r.timings.total)}`,
      )
    }
  }
  console.log('═'.repeat(70))
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err)
  console.error(`\nFatal: ${msg}`)
  process.exit(1)
})
