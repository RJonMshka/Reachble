import { z } from 'zod'

// ── OSV batch request ────────────────────────────────────────────────────────

export const OsvQuerySchema = z.object({
  package: z.object({ name: z.string(), ecosystem: z.literal('npm') }),
  version: z.string(),
})

export const OsvQueryBatchRequestSchema = z.object({
  queries: z.array(OsvQuerySchema),
})

// ── OSV batch response ───────────────────────────────────────────────────────

export const OsvSeveritySchema = z.object({
  type: z.string(), // "CVSS_V3", "CVSS_V2", etc.
  score: z.string(), // CVSS vector string
})

export const OsvRangeEventSchema = z
  .object({
    introduced: z.string().optional(),
    fixed: z.string().optional(),
    last_affected: z.string().optional(),
    limit: z.string().optional(),
  })
  .loose()

export const OsvRangeSchema = z.object({
  type: z.string(), // "SEMVER" | "GIT" | "ECOSYSTEM"
  events: z.array(OsvRangeEventSchema),
  repo: z.string().optional(),
})

export const OsvAffectedSchema = z.object({
  package: z.object({
    name: z.string(),
    ecosystem: z.string(),
    purl: z.string().optional(),
  }),
  ranges: z.array(OsvRangeSchema).optional(),
  versions: z.array(z.string()).optional(),
  ecosystem_specific: z
    .object({ affected_functions: z.array(z.string()).optional() })
    .loose()
    .optional(),
  database_specific: z
    .object({
      severity: z.string().optional(),
      cvss: z.string().optional(),
    })
    .loose()
    .optional(),
})

export const OsvReferenceSchema = z.object({
  type: z.string(), // "FIX" | "WEB" | "ADVISORY" | "REPORT" | "PACKAGE" | "EVIDENCE" | "GIT"
  url: z.string(),
})

export const OsvVulnerabilitySchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  severity: z.array(OsvSeveritySchema).optional(),
  // Real API sometimes omits affected/published on withdrawn or partial entries
  affected: z.array(OsvAffectedSchema).default([]),
  references: z.array(OsvReferenceSchema).optional(),
  published: z.string().default(''),
  modified: z.string().optional(),
  database_specific: z
    .object({
      severity: z.string().optional(),
      cwe_ids: z.array(z.string()).optional(),
    })
    .loose()
    .optional(),
})

export const OsvQueryResultSchema = z.object({
  vulns: z.array(OsvVulnerabilitySchema).optional(),
})

export const OsvQueryBatchResponseSchema = z.object({
  results: z.array(OsvQueryResultSchema),
})

export type OsvVulnerability = z.infer<typeof OsvVulnerabilitySchema>
export type OsvAffected = z.infer<typeof OsvAffectedSchema>
export type OsvRange = z.infer<typeof OsvRangeSchema>
export type OsvQueryBatchResponse = z.infer<typeof OsvQueryBatchResponseSchema>

// ── NVD v2 ───────────────────────────────────────────────────────────────────

const NvdCvssMetricV3Schema = z.object({
  cvssData: z.object({
    baseScore: z.number(),
    baseSeverity: z.string(),
    vectorString: z.string().optional(),
  }),
  type: z.string().optional(),
})

const NvdCvssMetricV2Schema = z.object({
  cvssData: z.object({ baseScore: z.number(), vectorString: z.string().optional() }),
  baseSeverity: z.string().optional(),
  type: z.string().optional(),
})

export const NvdCveItemSchema = z
  .object({
    id: z.string(),
    descriptions: z.array(z.object({ lang: z.string(), value: z.string() })).optional(),
    metrics: z
      .object({
        cvssMetricV31: z.array(NvdCvssMetricV3Schema).optional(),
        cvssMetricV30: z.array(NvdCvssMetricV3Schema).optional(),
        cvssMetricV2: z.array(NvdCvssMetricV2Schema).optional(),
      })
      .optional(),
  })
  .loose()

export const NvdResponseSchema = z.object({
  resultsPerPage: z.number().optional(),
  startIndex: z.number().optional(),
  totalResults: z.number().optional(),
  vulnerabilities: z.array(z.object({ cve: NvdCveItemSchema })).optional(),
})

export type NvdResponse = z.infer<typeof NvdResponseSchema>

// ── EPSS (FIRST.org) ─────────────────────────────────────────────────────────

export const EpssDataItemSchema = z.object({
  cve: z.string(),
  epss: z.string(), // decimal string e.g. "0.00521"
  percentile: z.string(),
  date: z.string(),
})

export const EpssResponseSchema = z.object({
  status: z.string(),
  status_code: z.number().optional(),
  version: z.string().optional(),
  access: z.string().optional(),
  total: z.number().optional(),
  offset: z.number().optional(),
  limit: z.number().optional(),
  data: z.array(EpssDataItemSchema),
})

export type EpssResponse = z.infer<typeof EpssResponseSchema>
