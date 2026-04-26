export type ErrorCode =
  | 'LOCKFILE_PARSE_ERROR'
  | 'CVE_RESOLVER_ERROR'
  | 'SYMBOL_EXTRACTION_ERROR'
  | 'IMPORT_ANALYSIS_ERROR'
  | 'CONFIG_ERROR'
  | 'CACHE_ERROR'
  | 'NETWORK_ERROR'

export class ReachbleError extends Error {
  readonly code: ErrorCode

  constructor(code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'ReachbleError'
    this.code = code
  }
}

export class LockfileParseError extends ReachbleError {
  readonly file: string

  constructor(file: string, message: string, options?: ErrorOptions) {
    super('LOCKFILE_PARSE_ERROR', `[${file}] ${message}`, options)
    this.name = 'LockfileParseError'
    this.file = file
  }
}

export class CveResolverError extends ReachbleError {
  readonly cveId?: string

  constructor(message: string, options?: ErrorOptions & { cveId?: string }) {
    super('CVE_RESOLVER_ERROR', message, options)
    this.name = 'CveResolverError'
    if (options?.cveId !== undefined) {
      this.cveId = options.cveId
    }
  }
}

export class SymbolExtractionError extends ReachbleError {
  readonly cveId: string

  constructor(cveId: string, message: string, options?: ErrorOptions) {
    super('SYMBOL_EXTRACTION_ERROR', `[${cveId}] ${message}`, options)
    this.name = 'SymbolExtractionError'
    this.cveId = cveId
  }
}

export class ImportAnalysisError extends ReachbleError {
  readonly file?: string

  constructor(message: string, options?: ErrorOptions & { file?: string }) {
    super('IMPORT_ANALYSIS_ERROR', message, options)
    this.name = 'ImportAnalysisError'
    if (options?.file !== undefined) {
      this.file = options.file
    }
  }
}

export class ConfigError extends ReachbleError {
  constructor(message: string, options?: ErrorOptions) {
    super('CONFIG_ERROR', message, options)
    this.name = 'ConfigError'
  }
}

export class CacheError extends ReachbleError {
  constructor(message: string, options?: ErrorOptions) {
    super('CACHE_ERROR', message, options)
    this.name = 'CacheError'
  }
}

export class NetworkError extends ReachbleError {
  readonly statusCode?: number

  constructor(message: string, options?: ErrorOptions & { statusCode?: number }) {
    super('NETWORK_ERROR', message, options)
    this.name = 'NetworkError'
    if (options?.statusCode !== undefined) {
      this.statusCode = options.statusCode
    }
  }
}
