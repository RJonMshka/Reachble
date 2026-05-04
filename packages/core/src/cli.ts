#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { cwd } from 'node:process'
import { fileURLToPath } from 'node:url'
import chalk from 'chalk'
import { Command } from 'commander'
import ora from 'ora'
import {
  buildCallGraph,
  buildFileGraph,
  buildImportGraph,
  detectEntryPoints,
} from './analysis/index.js'
import type { FailOnLevel } from './config.js'
import { loadConfig } from './config.js'
import { resolveCves } from './cve/resolver.js'
import { detectAndParse } from './lockfile/detect.js'
import type { VerdictResult } from './types.js'
import { buildCycloneDxVex, buildJsonV1, buildOpenVex, buildSarif } from './vex.js'
import { scoreVerdicts } from './verdict.js'

// ── Helpers ───────────────────────────────────────────────────────────────────

function verdictColor(verdict: VerdictResult['verdict']): string {
  switch (verdict) {
    case 'CRITICAL':
      return chalk.red.bold(verdict)
    case 'HIGH':
      return chalk.yellow.bold(verdict)
    case 'LOW':
      return chalk.blue(verdict)
    case 'SAFE':
      return chalk.green(verdict)
  }
}

export function readProjectMeta(dir: string): { name: string; version?: string } {
  const pkgPath = join(dir, 'package.json')
  if (!existsSync(pkgPath)) return { name: dir }
  try {
    const raw = JSON.parse(readFileSync(pkgPath, 'utf8')) as Record<string, unknown>
    const name = typeof raw['name'] === 'string' ? raw['name'] : dir
    if (typeof raw['version'] === 'string') return { name, version: raw['version'] }
    return { name }
  } catch {
    return { name: dir }
  }
}

export function shouldFail(results: VerdictResult[], level: FailOnLevel): boolean {
  for (const r of results) {
    if (level === 'critical' && r.verdict === 'CRITICAL') return true
    if (level === 'high' && (r.verdict === 'CRITICAL' || r.verdict === 'HIGH')) return true
    if (level === 'medium' && r.verdict !== 'SAFE') return true
  }
  return false
}

// ── Table renderer ─────────────────────────────────────────────────────────────

function renderTable(results: VerdictResult[]): void {
  if (results.length === 0) {
    console.log(chalk.green('No CVEs found.'))
    return
  }

  const COL = { pkg: 20, ver: 10, cve: 20, verdict: 10, cvss: 6, reason: 50 }
  const header = [
    'Package'.padEnd(COL.pkg),
    'Version'.padEnd(COL.ver),
    'CVE'.padEnd(COL.cve),
    'Verdict'.padEnd(COL.verdict),
    'CVSS'.padEnd(COL.cvss),
    'Reason',
  ].join('  ')

  console.log(chalk.bold(header))
  console.log('─'.repeat(header.length))

  for (const r of results) {
    const row = [
      r.package.slice(0, COL.pkg).padEnd(COL.pkg),
      r.version.slice(0, COL.ver).padEnd(COL.ver),
      r.cveId.slice(0, COL.cve).padEnd(COL.cve),
      verdictColor(r.verdict).padEnd(COL.verdict + 10), // +10 for chalk escape codes
      r.cvssScore.toFixed(1).padEnd(COL.cvss),
      r.reason.slice(0, COL.reason),
    ].join('  ')
    console.log(row)
  }
}

// ── Summary line ───────────────────────────────────────────────────────────────

function printSummary(
  pkgCount: number,
  cveCount: number,
  results: VerdictResult[],
  outPath?: string,
): void {
  const critical = results.filter((r) => r.verdict === 'CRITICAL').length
  const high = results.filter((r) => r.verdict === 'HIGH').length
  const low = results.filter((r) => r.verdict === 'LOW').length
  const safe = results.filter((r) => r.verdict === 'SAFE').length

  const parts = [
    chalk.bold(`${String(pkgCount)} packages`),
    chalk.bold(`${String(cveCount)} CVEs`),
    critical > 0 ? chalk.red.bold(`${String(critical)} CRITICAL`) : chalk.dim('0 CRITICAL'),
    high > 0 ? chalk.yellow.bold(`${String(high)} HIGH`) : chalk.dim('0 HIGH'),
    low > 0 ? chalk.blue(`${String(low)} LOW`) : chalk.dim('0 LOW'),
    chalk.green(`${String(safe)} SAFE`),
  ]

  console.log('\n' + parts.join(chalk.dim(' · ')))
  if (outPath !== undefined) {
    console.log(chalk.dim(`VEX written to ${outPath}`))
  }
}

// ── Scan command ───────────────────────────────────────────────────────────────

export interface ScanOptions {
  path: string
  format: 'vex' | 'json' | 'sarif' | 'table'
  failOn: FailOnLevel | undefined
  offline: boolean
  cacheDir: string | undefined
  ignoreDev: boolean
}

export async function runScan(opts: ScanOptions): Promise<void> {
  const projectDir = resolve(opts.path)

  // ── Config ────────────────────────────────────────────────────────────────
  const config = loadConfig(projectDir)
  const meta = readProjectMeta(projectDir)

  // CLI flags override config; config provides defaults
  const effectiveIgnoreDev = opts.ignoreDev || (config.ignoreDev ?? false)
  const effectiveFailOn: FailOnLevel | undefined = opts.failOn ?? config.failOn
  const effectiveIgnorePatterns = config.ignorePatterns ?? []

  // ── Lockfile ──────────────────────────────────────────────────────────────
  const lockSpinner = ora('Parsing lockfile…').start()
  let packages = await detectAndParse(projectDir)
  if (effectiveIgnoreDev) packages = packages.filter((p) => !p.devOnly)
  lockSpinner.succeed(`Found ${String(packages.length)} packages`)

  // ── Import graph ──────────────────────────────────────────────────────────
  const graphSpinner = ora('Analyzing imports…').start()
  const analyzeOpts =
    effectiveIgnorePatterns.length > 0 ? { ignorePatterns: effectiveIgnorePatterns } : {}
  const graph = buildImportGraph(projectDir, analyzeOpts)
  const fileCount = graph.size
  graphSpinner.succeed(`Analyzed ${String(fileCount)} file${fileCount !== 1 ? 's' : ''}`)

  // ── Entry point detection + file graph ────────────────────────────────────
  const epSpinner = ora('Detecting entry points…').start()
  const entryPoints = detectEntryPoints(projectDir, analyzeOpts)
  const fileGraph = buildFileGraph(projectDir, analyzeOpts)
  epSpinner.succeed(
    `Found ${String(entryPoints.length)} entry point${entryPoints.length !== 1 ? 's' : ''}`,
  )

  // ── Call graph ────────────────────────────────────────────────────────────
  const cgSpinner = ora('Building call graph…').start()
  const callGraph = buildCallGraph(projectDir, analyzeOpts)
  if (callGraph !== null) {
    const callFileCount = callGraph.size
    cgSpinner.succeed(
      `Call graph: ${String(callFileCount)} file${callFileCount !== 1 ? 's' : ''} with edges`,
    )
  } else {
    cgSpinner.info('Call graph skipped (no tsconfig.json found)')
  }

  // ── CVE resolution ─────────────────────────────────────────────────────────
  const cveSpinner = ora('Resolving CVEs…').start()
  const cveMap = await resolveCves(packages, {
    offline: opts.offline,
    ...(opts.cacheDir !== undefined ? { cacheDir: opts.cacheDir } : {}),
  })
  const totalCves = [...cveMap.values()].reduce((n, arr) => n + arr.length, 0)
  cveSpinner.succeed(`Resolved ${String(totalCves)} CVE${totalCves !== 1 ? 's' : ''}`)

  // ── Verdict engine ────────────────────────────────────────────────────────
  const verdictSpinner = ora('Scoring verdicts…').start()
  const results = scoreVerdicts(packages, cveMap, graph, {
    ...(config.suppressions !== undefined ? { suppressions: config.suppressions } : {}),
    entryPoints,
    fileGraph,
    ...(callGraph !== null ? { callGraph } : {}),
  })
  verdictSpinner.succeed('Verdicts computed')

  // ── Output ────────────────────────────────────────────────────────────────
  const vexOpts = {
    projectName: meta.name,
    ...(meta.version !== undefined ? { projectVersion: meta.version } : {}),
  }

  let outPath: string | undefined

  if (opts.format === 'table') {
    renderTable(results)
  } else if (opts.format === 'vex') {
    const cdx = buildCycloneDxVex(results, vexOpts)
    const openvex = buildOpenVex(results, vexOpts)
    const cdxPath = join(projectDir, 'reachble-vex.cdx.json')
    const openvexPath = join(projectDir, 'reachble-vex.openvex.json')
    writeFileSync(cdxPath, JSON.stringify(cdx, null, 2))
    writeFileSync(openvexPath, JSON.stringify(openvex, null, 2))
    outPath = cdxPath
    console.log(chalk.dim(`OpenVEX written to ${openvexPath}`))
  } else if (opts.format === 'json') {
    const doc = buildJsonV1(results, vexOpts)
    const jsonPath = join(projectDir, 'reachble-results.json')
    writeFileSync(jsonPath, JSON.stringify(doc, null, 2))
    outPath = jsonPath
  } else {
    const doc = buildSarif(results, vexOpts)
    const sarifPath = join(projectDir, 'reachble-results.sarif.json')
    writeFileSync(sarifPath, JSON.stringify(doc, null, 2))
    outPath = sarifPath
    console.log(chalk.dim(`SARIF written to ${sarifPath}`))
  }

  printSummary(packages.length, totalCves, results, outPath)

  // ── CI exit code ──────────────────────────────────────────────────────────
  if (effectiveFailOn !== undefined && shouldFail(results, effectiveFailOn)) {
    process.exit(1)
  }
}

// ── CLI wiring ─────────────────────────────────────────────────────────────────

const program = new Command()

program
  .name('reachble')
  .description('VEX generator for npm/JS/TS projects backed by reachability analysis')
  .version('0.1.0')

program
  .command('scan')
  .description('Scan a project and emit reachability-backed VEX')
  .option('--path <dir>', 'project directory to scan', cwd())
  .option('--format <fmt>', 'output format: vex|json|sarif|table', 'vex')
  .option('--fail-on <level>', 'exit 1 if any verdict at or above level: critical|high|medium')
  .option('--offline', 'use cache only; error on cache miss', false)
  .option('--cache-dir <path>', 'SQLite cache directory (default: ~/.cache/reachble/)')
  .option('--ignore-dev', 'exclude devDependencies from scan', false)
  .action(
    async (rawOpts: {
      path: string
      format: string
      failOn: string | undefined
      offline: boolean
      cacheDir: string | undefined
      ignoreDev: boolean
    }) => {
      const fmt = rawOpts.format
      if (!['vex', 'json', 'sarif', 'table'].includes(fmt)) {
        console.error(chalk.red(`Unknown format "${fmt}". Choose: vex, json, sarif, table`))
        process.exit(1)
      }

      const { failOn } = rawOpts
      if (failOn !== undefined && !['critical', 'high', 'medium'].includes(failOn)) {
        console.error(
          chalk.red(`Unknown --fail-on level "${failOn}". Choose: critical, high, medium`),
        )
        process.exit(1)
      }

      const opts: ScanOptions = {
        path: rawOpts.path,
        format: fmt as ScanOptions['format'],
        failOn: failOn !== undefined ? (failOn as FailOnLevel) : undefined,
        offline: rawOpts.offline,
        cacheDir: rawOpts.cacheDir,
        ignoreDev: rawOpts.ignoreDev,
      }

      try {
        await runScan(opts)
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        console.error(chalk.red(`\nError: ${msg}`))
        process.exit(1)
      }
    },
  )

// Guard: only parse argv when this file is run directly (not imported in tests)
const thisFile = fileURLToPath(import.meta.url)
if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(thisFile)) {
  program.parse()
}
