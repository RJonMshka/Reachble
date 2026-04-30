export { CveCache, DEFAULT_CACHE_DIR, DEFAULT_TTL_MS } from './cache.js'
export { fetchEpssScores } from './epss.js'
export {
  fetchCommitDiff,
  parseGithubCommitUrl,
  parseSymbolsFromDiff,
  resolveFixDiffSymbols,
} from './fix-commit.js'
export type { CommitRef, FetchDiffOptions } from './fix-commit.js'
export { fetchNvdCvss } from './nvd.js'
export { queryOsvBatch } from './osv.js'
export { resolveCves } from './resolver.js'
export type { ResolverOptions } from './resolver.js'
export * from './schemas.js'
export { extractSymbols } from './symbols.js'
export type { ExtractOptions, SymbolOverride } from './symbols.js'
