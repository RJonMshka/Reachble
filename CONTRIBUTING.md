# Contributing to Reachble

Thanks for taking a look. The project is early (MVP), so the highest-value contributions right now are bug reports, real-world scan results, and fixes — not new features.

## Before you start

Read [`CLAUDE.md`](CLAUDE.md) for the hard rules and current focus. If you're about to touch something that feels out of scope, open an issue first.

## Setup

```bash
node --version    # 20+
pnpm --version    # 9+
pnpm install
pnpm test
pnpm build
```

## What's useful right now

- **Bug reports** — scan your project and share what came out wrong. Include the lockfile format (npm/yarn/pnpm), whether it was a false SAFE or false LOW/CRITICAL, and the CVE ID.
- **Real-world scan results** — even just "I ran it on X and got Y" is useful signal. File an issue.
- **OSV symbol-extraction gaps** — if a CVE you care about has no `affectedSymbols`, that's the V1 fix-commit extraction problem. The ADR and spec are in `docs/GUIDE.md §11`.
- **Lockfile edge cases** — berry yarn lockfiles, pnpm catalogs, non-standard workspace shapes.

## What to avoid

Don't add features, abstractions, or multi-language support — see `CLAUDE.md` non-goals. A PR that adds a feature not on the MVP/V1 milestone will be closed, not out of rudeness but because scope creep is the primary risk.

## Code standards

- TypeScript strict (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`)
- Zod schema on every external API response — no exceptions
- Tests required for every new module (vitest, fixture-driven)
- Pure functions in the verdict engine — same inputs, byte-identical output
- No comments unless the WHY is non-obvious

Run `pnpm lint` and `pnpm test` before submitting. The CI gate is lint + test + build.

## Commit style

Short imperative subject line. No ticket references in the message body.

## PR size

Small, focused PRs. One logical change per PR. If a fix requires understanding a lot of context, add a sentence in the PR description explaining it.
