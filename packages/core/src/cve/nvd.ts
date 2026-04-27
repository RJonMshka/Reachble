import { NetworkError } from '../errors.js'
import { NvdResponseSchema } from './schemas.js'

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const MAX_RETRIES = 3
const BASE_BACKOFF_MS = 6000 // NVD wants ~6s between requests without an API key

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export interface NvdCvssResult {
  score: number
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  description?: string
}

function mapSeverityString(s: string): NvdCvssResult['severity'] {
  const upper = s.toUpperCase()
  if (upper === 'CRITICAL') return 'CRITICAL'
  if (upper === 'HIGH') return 'HIGH'
  if (upper === 'MEDIUM' || upper === 'MODERATE') return 'MEDIUM'
  return 'LOW'
}

export async function fetchNvdCvss(
  cveId: string,
  apiKey?: string,
): Promise<NvdCvssResult | undefined> {
  const url = `${NVD_URL}?cveId=${encodeURIComponent(cveId)}`
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (apiKey) headers['apiKey'] = apiKey

  let lastErr: unknown
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(BASE_BACKOFF_MS * 2 ** (attempt - 1))
    }

    let res: Response
    try {
      res = await fetch(url, { headers })
    } catch (err) {
      lastErr = err
      continue
    }

    if (res.status === 404) return undefined // CVE not in NVD

    if (res.status === 429 || res.status === 503) {
      lastErr = new NetworkError(`NVD rate limited (HTTP ${String(res.status)})`, {
        statusCode: res.status,
      })
      continue
    }

    if (!res.ok) {
      throw new NetworkError(`NVD request failed: ${String(res.status)} ${res.statusText}`, {
        statusCode: res.status,
      })
    }

    const raw = await res.json()
    const parsed = NvdResponseSchema.safeParse(raw)
    if (!parsed.success) {
      throw new NetworkError(`Invalid NVD response: ${parsed.error.message}`)
    }

    const vuln = parsed.data.vulnerabilities?.[0]?.cve
    if (!vuln) return undefined

    const enDesc = vuln.descriptions?.find((d) => d.lang === 'en')?.value

    // Prefer V3.1 → V3.0 → V2
    const v31 = vuln.metrics?.cvssMetricV31?.[0]
    if (v31) {
      return {
        score: v31.cvssData.baseScore,
        severity: mapSeverityString(v31.cvssData.baseSeverity),
        ...(enDesc !== undefined ? { description: enDesc } : {}),
      }
    }

    const v30 = vuln.metrics?.cvssMetricV30?.[0]
    if (v30) {
      return {
        score: v30.cvssData.baseScore,
        severity: mapSeverityString(v30.cvssData.baseSeverity),
        ...(enDesc !== undefined ? { description: enDesc } : {}),
      }
    }

    const v2 = vuln.metrics?.cvssMetricV2?.[0]
    if (v2) {
      // V2 scores map differently — anything ≥7.0 is "HIGH" in V2
      const v2Severity =
        v2.baseSeverity ??
        (v2.cvssData.baseScore >= 7.0 ? 'HIGH' : v2.cvssData.baseScore >= 4.0 ? 'MEDIUM' : 'LOW')
      return {
        score: v2.cvssData.baseScore,
        severity: mapSeverityString(v2Severity),
        ...(enDesc !== undefined ? { description: enDesc } : {}),
      }
    }

    return undefined
  }

  throw new NetworkError('NVD request failed after max retries', { cause: lastErr })
}
