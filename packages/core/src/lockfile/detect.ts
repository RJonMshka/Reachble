import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { LockfileParseError } from '../errors.js'
import type { ResolvedPackage } from '../types.js'
import { parseNpmLock } from './npm.js'
import { parsePnpmLock } from './pnpm.js'
import { RootPackageJsonSchema } from './schemas.js'
import { parseYarnLock } from './yarn.js'

async function tryRead(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf-8')
  } catch {
    return null
  }
}

export async function detectAndParse(projectDir: string): Promise<ResolvedPackage[]> {
  // pnpm > npm > yarn — if multiple coexist, prefer in this order
  const pnpm = await tryRead(join(projectDir, 'pnpm-lock.yaml'))
  if (pnpm !== null) return parsePnpmLock(pnpm)

  const npm = await tryRead(join(projectDir, 'package-lock.json'))
  if (npm !== null) return parseNpmLock(npm)

  const yarn = await tryRead(join(projectDir, 'yarn.lock'))
  if (yarn !== null) {
    const pkgJsonContent = await tryRead(join(projectDir, 'package.json'))
    if (pkgJsonContent === null) {
      throw new LockfileParseError(
        'yarn.lock',
        'yarn.lock found but package.json is missing — needed for devOnly detection'
      )
    }
    let pkgJsonRaw: unknown
    try {
      pkgJsonRaw = JSON.parse(pkgJsonContent)
    } catch (err) {
      throw new LockfileParseError('package.json', 'invalid JSON', { cause: err })
    }
    const pkgJson = RootPackageJsonSchema.parse(pkgJsonRaw)
    return parseYarnLock(yarn, pkgJson)
  }

  throw new LockfileParseError(
    'none',
    `no lockfile found in ${projectDir} — expected pnpm-lock.yaml, package-lock.json, or yarn.lock`
  )
}
