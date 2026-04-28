import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { EntryPoint } from '../types.js'
import { detectEntryPoints } from './entrypoints.js'

const FIXTURES = join(import.meta.dirname, '../../fixtures/entrypoints')

// ─── helpers ─────────────────────────────────────────────────────────────────

function byDescription(eps: EntryPoint[]): Map<string, EntryPoint> {
  return new Map(eps.map((ep) => [ep.description, ep]))
}

// ─── Express ─────────────────────────────────────────────────────────────────

describe('Express entry point detection', () => {
  const dir = join(FIXTURES, 'express')

  it('detects GET route without auth middleware', () => {
    const eps = detectEntryPoints(dir)
    const map = byDescription(eps)
    const ep = map.get('Express GET /users')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('http')
    expect(ep?.framework).toBe('express')
    expect(ep?.authenticated).toBe(false)
  })

  it('detects POST route with requireAuth middleware → authenticated', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Express POST /users')
    expect(ep?.authenticated).toBe(true)
  })

  it('detects DELETE route with verifyAdmin middleware → authenticated', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Express DELETE /users/:id')
    expect(ep?.authenticated).toBe(true)
  })

  it('detects routes registered on express.Router()', () => {
    const eps = detectEntryPoints(dir)
    const map = byDescription(eps)
    expect(map.has('Express GET /items')).toBe(true)
    expect(map.has('Express PUT /items/:id')).toBe(true)
  })

  it('marks router PUT with checkPermission → authenticated', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Express PUT /items/:id')
    expect(ep?.authenticated).toBe(true)
  })

  it('detects app.use() middleware mount', () => {
    const eps = detectEntryPoints(dir)
    expect(byDescription(eps).has('Express USE /api')).toBe(true)
  })

  it('all http entry points have correct kind and framework', () => {
    const eps = detectEntryPoints(dir)
    for (const ep of eps) {
      expect(ep.kind).toBe('http')
      expect(ep.framework).toBe('express')
    }
  })

  it('does not produce duplicates', () => {
    const eps = detectEntryPoints(dir)
    const descriptions = eps.map((ep) => ep.description)
    expect(descriptions.length).toBe(new Set(descriptions).size)
  })
})

// ─── Fastify ──────────────────────────────────────────────────────────────────

describe('Fastify entry point detection', () => {
  const dir = join(FIXTURES, 'fastify')

  it('detects GET route', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Fastify GET /health')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('http')
    expect(ep?.framework).toBe('fastify')
    expect(ep?.authenticated).toBe(false)
  })

  it('detects POST route', () => {
    const ep = byDescription(detectEntryPoints(dir)).get('Fastify POST /login')
    expect(ep).toBeDefined()
    expect(ep?.authenticated).toBe(false)
  })

  it('detects fastify.route() with method and url', () => {
    const ep = byDescription(detectEntryPoints(dir)).get('Fastify GET /items')
    expect(ep).toBeDefined()
    expect(ep?.framework).toBe('fastify')
  })

  it('detects addHook preHandler as authenticated http entry point', () => {
    const ep = byDescription(detectEntryPoints(dir)).get('Fastify preHandler hook')
    expect(ep).toBeDefined()
    expect(ep?.authenticated).toBe(true)
    expect(ep?.kind).toBe('http')
  })
})

// ─── Next.js ──────────────────────────────────────────────────────────────────

describe('Next.js pages/api detection', () => {
  const dir = join(FIXTURES, 'nextjs-pages')

  it('detects default export in pages/api/ as nextjs http entry point', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Next.js pages/api default handler')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('http')
    expect(ep?.framework).toBe('nextjs')
    expect(ep?.authenticated).toBe(false)
  })
})

describe('Next.js app/api route detection', () => {
  const dir = join(FIXTURES, 'nextjs-app')

  it('detects exported GET handler in app/api/**/route.ts', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('Next.js GET handler')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('http')
    expect(ep?.framework).toBe('nextjs')
  })

  it('detects exported POST handler in app/api/**/route.ts', () => {
    const ep = byDescription(detectEntryPoints(dir)).get('Next.js POST handler')
    expect(ep).toBeDefined()
    expect(ep?.framework).toBe('nextjs')
  })
})

// ─── CLI ─────────────────────────────────────────────────────────────────────

describe('CLI entry point detection', () => {
  const dir = join(FIXTURES, 'cli')

  it('detects commander program.parse(process.argv)', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('CLI parse(process.argv)')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('cli')
    expect(ep?.authenticated).toBe(false)
  })
})

// ─── Env / file-input ────────────────────────────────────────────────────────

describe('process.env detection', () => {
  const dir = join(FIXTURES, 'env-fs')

  it('detects each unique env var as a separate entry point', () => {
    const eps = detectEntryPoints(dir)
    const map = byDescription(eps)
    expect(map.has('process.env.DATABASE_URL')).toBe(true)
    expect(map.has('process.env.PORT')).toBe(true)
    expect(map.has('process.env.JWT_SECRET')).toBe(true)
  })

  it('deduplicates repeated access to the same env var', () => {
    const eps = detectEntryPoints(dir)
    const envEps = eps.filter((ep) => ep.description === 'process.env.DATABASE_URL')
    expect(envEps.length).toBe(1)
  })

  it('env entry points have kind env and authenticated false', () => {
    const eps = detectEntryPoints(dir)
    for (const ep of eps.filter((e) => e.kind === 'env')) {
      expect(ep.authenticated).toBe(false)
    }
  })
})

describe('file-input detection', () => {
  const dir = join(FIXTURES, 'env-fs')

  it('detects fs.readFileSync with dynamic path', () => {
    const eps = detectEntryPoints(dir)
    const ep = byDescription(eps).get('fs.readFileSync with dynamic path')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('file-input')
    expect(ep?.authenticated).toBe(false)
  })

  it('detects fs.createReadStream with dynamic path', () => {
    const ep = byDescription(detectEntryPoints(dir)).get('fs.createReadStream with dynamic path')
    expect(ep).toBeDefined()
    expect(ep?.kind).toBe('file-input')
  })

  it('does NOT flag fs.readFileSync with literal path', () => {
    const eps = detectEntryPoints(dir)
    const ep = eps.find(
      (e) => e.kind === 'file-input' && e.description === 'fs.readFileSync with dynamic path',
    )
    // Only one readFileSync entry (the dynamic one), not the literal one
    const allReadFileSync = eps.filter(
      (e) => e.kind === 'file-input' && e.description.includes('readFileSync'),
    )
    expect(allReadFileSync.length).toBe(1)
    expect(ep).toBeDefined()
  })
})

// ─── Custom entry points ──────────────────────────────────────────────────────

describe('custom entry points from config', () => {
  it('appends custom entry points with kind custom', () => {
    const eps = detectEntryPoints(join(FIXTURES, 'express'), {
      customEntryPoints: ['src/server.ts', 'src/worker.ts'],
    })
    const customs = eps.filter((e) => e.kind === 'custom')
    expect(customs).toHaveLength(2)
    expect(customs[0]?.file).toBe('src/server.ts')
    expect(customs[0]?.description).toBe('custom entry point: src/server.ts')
    expect(customs[1]?.file).toBe('src/worker.ts')
  })
})

// ─── Empty directory ─────────────────────────────────────────────────────────

describe('no entry points', () => {
  it('returns empty array for directory with no matching patterns', () => {
    // nextjs-pages/pages/api has no express/fastify/cli/env — but it has a Next.js file
    // Use express dir but override to a dir we know has no patterns...
    // Instead test that the function handles gracefully
    const eps = detectEntryPoints(join(FIXTURES, 'nextjs-pages'), {
      ignorePatterns: ['pages/**'],
    })
    expect(eps).toEqual([])
  })
})
