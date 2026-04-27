import { NetworkError } from '../errors.js'
import { EpssResponseSchema } from './schemas.js'

const EPSS_URL = 'https://api.first.org/data/v1/epss'
const EPSS_BATCH_SIZE = 100 // safe URL length

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function fetchEpssBatch(cveIds: string[]): Promise<Map<string, number>> {
  const query = cveIds.map((id) => encodeURIComponent(id)).join(',')
  const url = `${EPSS_URL}?cve=${query}&limit=${String(cveIds.length)}`

  let res: Response
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' } })
  } catch (err) {
    throw new NetworkError('EPSS request failed', { cause: err })
  }

  if (res.status === 429) {
    await sleep(5000)
    res = await fetch(url, { headers: { Accept: 'application/json' } })
  }

  if (!res.ok) {
    throw new NetworkError(`EPSS request failed: ${String(res.status)} ${res.statusText}`, {
      statusCode: res.status,
    })
  }

  const raw = await res.json()
  const parsed = EpssResponseSchema.safeParse(raw)
  if (!parsed.success) {
    throw new NetworkError(`Invalid EPSS response: ${parsed.error.message}`)
  }

  const result = new Map<string, number>()
  for (const item of parsed.data.data) {
    result.set(item.cve, parseFloat(item.epss))
  }
  return result
}

export async function fetchEpssScores(cveIds: string[]): Promise<Map<string, number>> {
  if (cveIds.length === 0) return new Map()

  const unique = [...new Set(cveIds)]
  const result = new Map<string, number>()

  for (let i = 0; i < unique.length; i += EPSS_BATCH_SIZE) {
    const batch = unique.slice(i, i + EPSS_BATCH_SIZE)
    const batchResult = await fetchEpssBatch(batch)
    for (const [id, score] of batchResult) {
      result.set(id, score)
    }
  }

  return result
}
