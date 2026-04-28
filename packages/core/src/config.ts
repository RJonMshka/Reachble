import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import { ConfigError } from './errors.js'

const SuppressionSchema = z.object({
  cveId: z.string().min(1),
  package: z.string().min(1),
  reason: z.string().min(1, 'Suppression reason is mandatory'),
  reviewedBy: z.string().optional(),
})

const FailOnLevelSchema = z.enum(['critical', 'high', 'medium'])

const ReachbleConfigSchema = z.object({
  entryPoints: z.array(z.string().min(1)).optional(),
  ignorePatterns: z.array(z.string().min(1)).optional(),
  ignoreDev: z.boolean().optional(),
  failOn: FailOnLevelSchema.optional(),
  suppressions: z.array(SuppressionSchema).optional(),
})

export type Suppression = z.infer<typeof SuppressionSchema>
export type FailOnLevel = z.infer<typeof FailOnLevelSchema>
export type ReachbleConfig = z.infer<typeof ReachbleConfigSchema>

export function loadConfig(dir: string): ReachbleConfig {
  const standaloneFile = join(dir, '.reachble.json')

  if (existsSync(standaloneFile)) {
    let raw: unknown
    try {
      raw = JSON.parse(readFileSync(standaloneFile, 'utf8')) as unknown
    } catch (err) {
      throw new ConfigError(`.reachble.json could not be parsed as JSON`, { cause: err })
    }
    const result = ReachbleConfigSchema.safeParse(raw)
    if (!result.success) {
      throw new ConfigError(`.reachble.json is invalid: ${result.error.message}`)
    }
    return result.data
  }

  const pkgJsonFile = join(dir, 'package.json')
  if (existsSync(pkgJsonFile)) {
    let raw: unknown
    try {
      raw = JSON.parse(readFileSync(pkgJsonFile, 'utf8')) as unknown
    } catch {
      return {}
    }
    if (raw !== null && typeof raw === 'object' && 'reachble' in raw) {
      const result = ReachbleConfigSchema.safeParse((raw as Record<string, unknown>)['reachble'])
      if (!result.success) {
        throw new ConfigError(`package.json "reachble" key is invalid: ${result.error.message}`)
      }
      return result.data
    }
  }

  return {}
}
