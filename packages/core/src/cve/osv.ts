import pLimit from 'p-limit'

import { CveResolverError, NetworkError } from '../errors.js'
import type { ResolvedPackage } from '../types.js'
import { OsvQueryBatchResponseSchema } from './schemas.js'
import type { OsvQueryBatchResponse } from './schemas.js'

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'
const CHUNK_SIZE = 1000 // OSV accepts up to 1000 queries per request
const MAX_RETRIES = 3
const BASE_BACKOFF_MS = 1000

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function postWithRetry(url: string, body: unknown): Promise<unknown> {
  let lastErr: unknown
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(BASE_BACKOFF_MS * 2 ** (attempt - 1))
    }

    let res: Response
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
    } catch (err) {
      lastErr = err
      continue
    }

    if (res.status === 429 || res.status === 503) {
      lastErr = new NetworkError(`OSV rate limited (HTTP ${String(res.status)})`, {
        statusCode: res.status,
      })
      const retryAfter = res.headers.get('retry-after')
      if (retryAfter) await sleep(Number(retryAfter) * 1000)
      continue
    }

    if (!res.ok) {
      throw new NetworkError(`OSV request failed: ${String(res.status)} ${res.statusText}`, {
        statusCode: res.status,
      })
    }

    return res.json()
  }

  throw new NetworkError('OSV request failed after max retries', { cause: lastErr })
}

export async function queryOsvBatch(packages: ResolvedPackage[]): Promise<OsvQueryBatchResponse> {
  if (packages.length === 0) return { results: [] }

  const queries = packages.map((p) => ({
    package: { name: p.name, ecosystem: 'npm' as const },
    version: p.version,
  }))

  // Chunk into batches of CHUNK_SIZE
  const chunks: (typeof queries)[] = []
  for (let i = 0; i < queries.length; i += CHUNK_SIZE) {
    chunks.push(queries.slice(i, i + CHUNK_SIZE))
  }

  const limit = pLimit(2)
  const rawChunks = await Promise.all(
    chunks.map((chunk) => limit(() => postWithRetry(OSV_BATCH_URL, { queries: chunk }))),
  )

  const allResults: OsvQueryBatchResponse['results'] = []
  for (const raw of rawChunks) {
    const parsed = OsvQueryBatchResponseSchema.safeParse(raw)
    if (!parsed.success) {
      throw new CveResolverError(`Invalid OSV response shape: ${parsed.error.message}`)
    }
    allResults.push(...parsed.data.results)
  }

  return { results: allResults }
}
