import { z } from 'zod'

// Zod v4 requires two arguments for z.record(): z.record(keySchema, valueSchema)
const strRecord = () => z.record(z.string(), z.string())

// ── npm package-lock.json v2/v3 ──────────────────────────────────────────────

export const NpmPackageEntrySchema = z.object({
  version: z.string().optional(),
  resolved: z.string().optional(),
  integrity: z.string().optional(),
  dev: z.boolean().optional(),
  devOptional: z.boolean().optional(),
  optional: z.boolean().optional(),
  link: z.boolean().optional(),
  dependencies: strRecord().optional(),
  devDependencies: strRecord().optional(),
  peerDependencies: strRecord().optional(),
  optionalDependencies: strRecord().optional(),
})

export const NpmLockfileSchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  lockfileVersion: z.union([z.literal(2), z.literal(3)]),
  packages: z.record(z.string(), NpmPackageEntrySchema),
})

// ── yarn v1 (classic) ────────────────────────────────────────────────────────

export const YarnV1EntrySchema = z.object({
  version: z.string(),
  resolved: z.string().optional(),
  integrity: z.string().optional(),
  dependencies: strRecord().optional(),
  optionalDependencies: strRecord().optional(),
})

export const YarnV1LockfileSchema = z.object({
  type: z.literal('success'),
  object: z.record(z.string(), YarnV1EntrySchema),
})

// ── root package.json (for yarn/pnpm devOnly cross-reference) ────────────────

export const RootPackageJsonSchema = z.object({
  name: z.string().optional(),
  version: z.string().optional(),
  dependencies: strRecord().optional(),
  devDependencies: strRecord().optional(),
  peerDependencies: strRecord().optional(),
  optionalDependencies: strRecord().optional(),
  workspaces: z
    .union([z.array(z.string()), z.object({ packages: z.array(z.string()) })])
    .optional(),
})

export type RootPackageJson = z.infer<typeof RootPackageJsonSchema>

// ── pnpm-lock.yaml v6/v9 ─────────────────────────────────────────────────────

const PnpmDepEntrySchema = z.object({
  specifier: z.string(),
  version: z.string(),
})

export const PnpmImporterSchema = z.object({
  dependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
  devDependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
  optionalDependencies: z.record(z.string(), PnpmDepEntrySchema).optional(),
})

export const PnpmPackageEntrySchema = z.object({
  resolution: z
    .object({
      integrity: z.string().optional(),
      tarball: z.string().optional(),
    })
    .optional(),
  dependencies: strRecord().optional(),
  devDependencies: strRecord().optional(),
  optionalDependencies: strRecord().optional(),
  peerDependencies: strRecord().optional(),
  dev: z.boolean().optional(),
  optional: z.boolean().optional(),
  engines: strRecord().optional(),
})

export const PnpmLockfileSchema = z.object({
  lockfileVersion: z.union([z.string(), z.number()]),
  settings: z.record(z.string(), z.unknown()).optional(),
  importers: z.record(z.string(), PnpmImporterSchema).optional(),
  packages: z.record(z.string(), PnpmPackageEntrySchema).optional(),
})
