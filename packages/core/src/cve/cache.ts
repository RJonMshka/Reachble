import Database from 'better-sqlite3'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { CacheError } from '../errors.js'

export const DEFAULT_CACHE_DIR = path.join(os.homedir(), '.cache', 'reachble')
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000 // 24 hours

interface CacheRow {
  value: string
  expires_at: number
}

export class CveCache {
  private readonly db: Database.Database

  constructor(cacheDir = DEFAULT_CACHE_DIR) {
    fs.mkdirSync(cacheDir, { recursive: true })
    const dbPath = path.join(cacheDir, 'cve-cache.db')
    try {
      this.db = new Database(dbPath)
      this.db.pragma('journal_mode = WAL')
      this.init()
    } catch (err) {
      throw new CacheError(`Failed to open cache database at ${dbPath}`, { cause: err })
    }
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cache (
        key        TEXT    PRIMARY KEY,
        value      TEXT    NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `)
    // Prune expired entries on startup
    this.db.prepare('DELETE FROM cache WHERE expires_at < ?').run(Date.now())
  }

  get(key: string): unknown {
    const row = this.db
      .prepare<[string], CacheRow>('SELECT value, expires_at FROM cache WHERE key = ?')
      .get(key)

    if (!row) return undefined

    if (row.expires_at < Date.now()) {
      this.db.prepare('DELETE FROM cache WHERE key = ?').run(key)
      return undefined
    }

    return JSON.parse(row.value) as unknown
  }

  set(key: string, value: unknown, ttlMs = DEFAULT_TTL_MS): void {
    this.db
      .prepare('INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)')
      .run(key, JSON.stringify(value), Date.now() + ttlMs)
  }

  invalidate(key: string): void {
    this.db.prepare('DELETE FROM cache WHERE key = ?').run(key)
  }

  invalidatePrefix(prefix: string): void {
    this.db.prepare("DELETE FROM cache WHERE key LIKE ? ESCAPE '\\'").run(`${prefix}%`)
  }

  close(): void {
    this.db.close()
  }
}
