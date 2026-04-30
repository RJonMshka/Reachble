import { execSync, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

import type { BenchRepo } from './types.js'

const LOCKFILES = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock'] as const

function hasLockfile(dir: string): boolean {
  return LOCKFILES.some((f) => existsSync(join(dir, f)))
}

function generateNpmLockfile(dir: string): void {
  console.log('  [npm] generating lockfile (npm install --package-lock-only)…')
  const result = spawnSync(
    'npm',
    ['install', '--package-lock-only', '--ignore-scripts', '--legacy-peer-deps'],
    { cwd: dir, stdio: 'pipe', encoding: 'utf8', timeout: 180_000 },
  )
  if (result.status !== 0) {
    throw new Error(`npm install --package-lock-only failed: ${result.stderr?.trim() ?? ''}`)
  }
}

export function cloneRepo(repo: BenchRepo, benchDir: string, reuse: boolean): string {
  const dir = join(benchDir, repo.name)

  if (reuse && existsSync(dir)) {
    console.log(`  [git] reusing existing clone at ${dir}`)
    if (!hasLockfile(dir)) generateNpmLockfile(dir)
    return dir
  }

  if (existsSync(dir)) {
    console.log(`  [git] removing stale clone…`)
    execSync(`rm -rf "${dir}"`)
  }

  console.log(`  [git] shallow-cloning ${repo.url} @ ${repo.ref}…`)
  const result = spawnSync(
    'git',
    ['clone', '--depth', '1', '--branch', repo.ref, repo.url, dir],
    { stdio: 'pipe', encoding: 'utf8', timeout: 180_000 },
  )

  if (result.status !== 0) {
    const msg = result.stderr?.trim() || result.stdout?.trim() || 'unknown error'
    throw new Error(`git clone failed: ${msg}`)
  }

  if (!hasLockfile(dir)) generateNpmLockfile(dir)

  return dir
}
