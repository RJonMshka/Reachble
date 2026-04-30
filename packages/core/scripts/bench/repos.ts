import type { BenchRepo } from './types.js'

/**
 * Curated OSS repos for V1 benchmarking.
 *
 * Selection criteria:
 *  - npm/yarn/pnpm lockfile present (or generatable with npm install --package-lock-only)
 *  - TypeScript source (enables call graph analysis)
 *  - Has or likely has transitive CVEs (pinned to older tags)
 *  - Mix of sizes and frameworks
 *
 * To add a new target: append an entry here — no other files need changing.
 */
export const REPOS: BenchRepo[] = [
  {
    name: 'juice-shop',
    url: 'https://github.com/juice-shop/juice-shop',
    ref: 'v15.0.0',
    framework: 'express',
    notes:
      'OWASP intentionally-vulnerable TypeScript+Express app — canonical benchmark target. ' +
      'Lockfile is gitignored; benchmark generates it via npm install --package-lock-only.',
  },
  {
    name: 'directus-9',
    url: 'https://github.com/directus/directus',
    ref: 'v9.23.3',
    framework: 'express',
    notes:
      'Headless CMS — TypeScript REST+GraphQL API, large npm dependency tree, root package-lock.json.',
  },
  {
    name: 'payload-1',
    url: 'https://github.com/payloadcms/payload',
    ref: 'v1.13.5',
    framework: 'express',
    notes:
      'TypeScript headless CMS built on Express — single-package repo with committed lockfile.',
  },
]
