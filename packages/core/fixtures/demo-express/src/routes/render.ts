import type { Request, Response } from 'express'
import { template } from 'lodash'

// CVE-2021-23337: lodash.template() is vulnerable to command injection.
// This app DOES import and call template — making this CVE reachable.
// Verdict: LOW (import-level analysis) → CRITICAL once V1 call graph traces
// the unauthenticated HTTP route through to this call site.
const compiled = template('Hello, <%= user %>!')

export function renderPage(req: Request, res: Response): void {
  const user = String(req.query['user'] ?? 'World')
  res.send(compiled({ user }))
}
