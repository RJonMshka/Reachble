import { describe, expect, it } from 'vitest'
import { parseGithubCommitUrl, parseSymbolsFromDiff } from './fix-commit.js'

// ── parseGithubCommitUrl ──────────────────────────────────────────────────────

describe('parseGithubCommitUrl', () => {
  it('parses a standard commit URL', () => {
    const r = parseGithubCommitUrl('https://github.com/lodash/lodash/commit/abc1234567890')
    expect(r).toEqual({ owner: 'lodash', repo: 'lodash', sha: 'abc1234567890' })
  })

  it('parses a pull-request commit URL', () => {
    const r = parseGithubCommitUrl('https://github.com/owner/repo/pull/42/commits/deadbeefdeadbeef')
    expect(r).toEqual({ owner: 'owner', repo: 'repo', sha: 'deadbeefdeadbeef' })
  })

  it('parses a short (7-char) SHA', () => {
    const r = parseGithubCommitUrl('https://github.com/a/b/commit/abc1234')
    expect(r).not.toBeNull()
    expect(r?.sha).toBe('abc1234')
  })

  it('parses a full 40-char SHA', () => {
    const sha = 'a'.repeat(40)
    const r = parseGithubCommitUrl(`https://github.com/a/b/commit/${sha}`)
    expect(r?.sha).toBe(sha)
  })

  it('returns null for a non-GitHub URL', () => {
    expect(parseGithubCommitUrl('https://gitlab.com/owner/repo/commit/abc123')).toBeNull()
  })

  it('returns null for a GitHub URL that is not a commit', () => {
    expect(parseGithubCommitUrl('https://github.com/owner/repo/issues/1')).toBeNull()
  })

  it('returns null for a SHA that is too short (< 7 chars)', () => {
    expect(parseGithubCommitUrl('https://github.com/a/b/commit/abc12')).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(parseGithubCommitUrl('')).toBeNull()
  })
})

// ── parseSymbolsFromDiff ──────────────────────────────────────────────────────

// Helper to build a minimal unified diff string
function makeDiff(files: Array<{ path: string; hunks: string[] }>): string {
  return files
    .map(({ path, hunks }) =>
      [`diff --git a/${path} b/${path}`, `--- a/${path}`, `+++ b/${path}`, ...hunks].join('\n'),
    )
    .join('\n')
}

describe('parseSymbolsFromDiff', () => {
  it('extracts a function name from a git hunk-context header', () => {
    const diff = makeDiff([
      {
        path: 'src/template.ts',
        hunks: [
          '@@ -42,7 +42,8 @@ export function template(string, options) {',
          '-  return unsafe(string)',
          '+  return safe(string)',
        ],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    expect(symbols.map((s) => s.name)).toContain('template')
  })

  it('extracts a function name from a changed (+) line', () => {
    const diff = makeDiff([
      {
        path: 'src/utils.js',
        hunks: [
          '@@ -1,3 +1,5 @@',
          '+export function merge(target, source) {',
          '+  return Object.assign(target, source)',
          '+}',
        ],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    expect(symbols.map((s) => s.name)).toContain('merge')
  })

  it('extracts a function name from a removed (-) line', () => {
    const diff = makeDiff([
      {
        path: 'lib/foo.ts',
        hunks: ['@@ -1,3 +0,0 @@', '-export function oldHelper() {', '-}'],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    expect(symbols.map((s) => s.name)).toContain('oldHelper')
  })

  it('extracts a class name and marks type as class', () => {
    const diff = makeDiff([
      {
        path: 'src/Parser.ts',
        hunks: ['@@ -1,4 +1,5 @@ export class Parser {', '+  // new method', ' }'],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    const cls = symbols.find((s) => s.name === 'Parser')
    expect(cls).toBeDefined()
    expect(cls?.type).toBe('class')
  })

  it('extracts a const-arrow-function definition', () => {
    const diff = makeDiff([
      {
        path: 'src/helpers.ts',
        hunks: ['@@ -5,4 +5,5 @@', '+export const sanitize = (input: string) => input.trim()'],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    expect(symbols.map((s) => s.name)).toContain('sanitize')
  })

  it('deduplicates when hunk header and changed line both name the same symbol', () => {
    const diff = makeDiff([
      {
        path: 'src/render.ts',
        hunks: ['@@ -10,6 +10,7 @@ function render(tpl) {', '+export function render(tpl) {'],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    const names = symbols.map((s) => s.name)
    expect(names.filter((n) => n === 'render')).toHaveLength(1)
  })

  it('ignores non-JS/TS files', () => {
    const diff = [
      'diff --git a/README.md b/README.md',
      '--- a/README.md',
      '+++ b/README.md',
      '@@ -1,2 +1,3 @@',
      '+export function notAJsSymbol() {}',
    ].join('\n')
    expect(parseSymbolsFromDiff(diff)).toHaveLength(0)
  })

  it('handles multiple files — collects symbols from all JS/TS files', () => {
    const diff = makeDiff([
      {
        path: 'src/a.ts',
        hunks: ['@@ -1,2 +1,3 @@', '+export function alpha() {}'],
      },
      {
        path: 'src/b.ts',
        hunks: ['@@ -1,2 +1,3 @@', '+export function beta() {}'],
      },
    ])
    const names = parseSymbolsFromDiff(diff).map((s) => s.name)
    expect(names).toContain('alpha')
    expect(names).toContain('beta')
  })

  it('returns [] for an empty diff', () => {
    expect(parseSymbolsFromDiff('')).toHaveLength(0)
  })

  it('returns [] when no symbol definitions appear in changed lines', () => {
    const diff = makeDiff([
      {
        path: 'src/config.ts',
        hunks: ['@@ -3,4 +3,4 @@', '-  timeout: 5000,', '+  timeout: 10000,'],
      },
    ])
    expect(parseSymbolsFromDiff(diff)).toHaveLength(0)
  })

  it('emits source: fix-diff and confidence: medium for every symbol', () => {
    const diff = makeDiff([
      {
        path: 'src/x.ts',
        hunks: ['@@ -1,2 +1,3 @@', '+export function foo() {}'],
      },
    ])
    const symbols = parseSymbolsFromDiff(diff)
    expect(symbols.length).toBeGreaterThan(0)
    for (const s of symbols) {
      expect(s.source).toBe('fix-diff')
      expect(s.confidence).toBe('medium')
    }
  })
})
