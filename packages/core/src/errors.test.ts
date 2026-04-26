import { describe, expect, it } from 'vitest'
import {
  CacheError,
  ConfigError,
  CveResolverError,
  ImportAnalysisError,
  LockfileParseError,
  NetworkError,
  ReachbleError,
  SymbolExtractionError,
} from './errors.js'

describe('ReachbleError', () => {
  it('sets code, message, and name', () => {
    const err = new ReachbleError('CONFIG_ERROR', 'bad config')
    expect(err.code).toBe('CONFIG_ERROR')
    expect(err.message).toBe('bad config')
    expect(err.name).toBe('ReachbleError')
    expect(err).toBeInstanceOf(Error)
  })

  it('chains cause', () => {
    const cause = new Error('original')
    const err = new ReachbleError('CACHE_ERROR', 'wrapped', { cause })
    expect(err.cause).toBe(cause)
  })
})

describe('LockfileParseError', () => {
  it('prefixes message with file path', () => {
    const err = new LockfileParseError('package-lock.json', 'unexpected token')
    expect(err.file).toBe('package-lock.json')
    expect(err.message).toBe('[package-lock.json] unexpected token')
    expect(err.code).toBe('LOCKFILE_PARSE_ERROR')
    expect(err.name).toBe('LockfileParseError')
    expect(err).toBeInstanceOf(ReachbleError)
  })

  it('chains cause', () => {
    const cause = new SyntaxError('bad json')
    const err = new LockfileParseError('yarn.lock', 'invalid yaml', { cause })
    expect(err.cause).toBe(cause)
  })
})

describe('CveResolverError', () => {
  it('stores cveId when provided', () => {
    const err = new CveResolverError('fetch failed', { cveId: 'CVE-2024-1234' })
    expect(err.cveId).toBe('CVE-2024-1234')
    expect(err.code).toBe('CVE_RESOLVER_ERROR')
    expect(err.name).toBe('CveResolverError')
    expect(err).toBeInstanceOf(ReachbleError)
  })

  it('cveId is undefined when not provided', () => {
    const err = new CveResolverError('rate limited')
    expect(err.cveId).toBeUndefined()
  })
})

describe('SymbolExtractionError', () => {
  it('prefixes message with cveId', () => {
    const err = new SymbolExtractionError('CVE-2024-9999', 'no diff found')
    expect(err.cveId).toBe('CVE-2024-9999')
    expect(err.message).toBe('[CVE-2024-9999] no diff found')
    expect(err.code).toBe('SYMBOL_EXTRACTION_ERROR')
    expect(err.name).toBe('SymbolExtractionError')
    expect(err).toBeInstanceOf(ReachbleError)
  })
})

describe('ImportAnalysisError', () => {
  it('stores file when provided', () => {
    const err = new ImportAnalysisError('parse failed', { file: 'src/app.ts' })
    expect(err.file).toBe('src/app.ts')
    expect(err.code).toBe('IMPORT_ANALYSIS_ERROR')
    expect(err.name).toBe('ImportAnalysisError')
    expect(err).toBeInstanceOf(ReachbleError)
  })

  it('file is undefined when not provided', () => {
    const err = new ImportAnalysisError('unknown failure')
    expect(err.file).toBeUndefined()
  })
})

describe('ConfigError', () => {
  it('has correct code and name', () => {
    const err = new ConfigError('invalid suppressions format')
    expect(err.code).toBe('CONFIG_ERROR')
    expect(err.name).toBe('ConfigError')
    expect(err).toBeInstanceOf(ReachbleError)
  })
})

describe('CacheError', () => {
  it('has correct code and name', () => {
    const err = new CacheError('sqlite write failed')
    expect(err.code).toBe('CACHE_ERROR')
    expect(err.name).toBe('CacheError')
    expect(err).toBeInstanceOf(ReachbleError)
  })
})

describe('NetworkError', () => {
  it('stores statusCode when provided', () => {
    const err = new NetworkError('too many requests', { statusCode: 429 })
    expect(err.statusCode).toBe(429)
    expect(err.code).toBe('NETWORK_ERROR')
    expect(err.name).toBe('NetworkError')
    expect(err).toBeInstanceOf(ReachbleError)
  })

  it('statusCode is undefined when not provided', () => {
    const err = new NetworkError('connection refused')
    expect(err.statusCode).toBeUndefined()
  })
})
