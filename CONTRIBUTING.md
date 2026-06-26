# Contributing to mcp-auth-kit

Thanks for your interest in improving the kit. This project aims to be a small,
auditable, production-grade foundation for OAuth-protected MCP servers — contributions
that keep it that way are very welcome.

## Getting started

```bash
npm install
npm run build        # tsc → dist/
npm test             # vitest (run mode)
npm run typecheck    # tsc --noEmit
npm run lint         # eslint
npm run format:check # prettier --check
```

Node **22+** is required (see `package.json` `engines`). CI runs the suite on Node 22, 24, and 26.

## Before opening a pull request

Run the full local gate — this mirrors CI, which must be green to merge:

```bash
npm run typecheck && npm run lint && npm run format:check && npm run build && npm test
```

- **Format** your changes: `npm run format`.
- **Add or update tests** for any behavior change. Security-relevant changes (OAuth,
  PKCE, tokens, rate limiting, two-phase confirm) require tests that demonstrate both the
  intended behavior and the failure being prevented.
- **Keep the public API documented.** If you add or change an export, update `README.md`
  (the API and config reference tables) accordingly.
- **Preserve the security model.** Don't weaken PKCE enforcement, token hashing-at-rest,
  redirect-URI exact matching, scope normalization, or the confirm-token ownership check
  without discussion in an issue first.

## Reporting bugs and security issues

- Functional bugs: open a GitHub issue using the bug template.
- **Security vulnerabilities: do NOT open a public issue.** Follow
  [SECURITY.md](SECURITY.md).

## Commit messages

Conventional-commit style is used in history (`feat:`, `fix:`, `docs:`, `chore:`,
`refactor:`). Keep messages focused and explain the _why_ for non-obvious changes.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
