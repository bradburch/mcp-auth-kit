# CLAUDE.md

`mcp-oauth-kit`: a library that builds an OAuth-protected MCP server as a Hono app
(`createMcpServer`). Published to npm from `dist/`; examples in `examples/`.

## Commands

```bash
npm run typecheck && npm run lint && npm run format:check && npm run build && npm test
```

That is the full CI gate (Node 22/24/26). `npm run format` fixes formatting. Lint
`no-explicit-any` warnings in tests are pre-existing and accepted.

## Protocol and SDK

- Targets MCP spec **2026-07-28** on the v2 TypeScript SDK (`@modelcontextprotocol/server`).
  Don't reintroduce `@modelcontextprotocol/sdk` (v1).
- `POST /mcp` (`src/transport.ts`) runs on `createMcpHandler`: modern requests carry a
  `_meta` envelope + `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name` headers; claim-less
  2025-era requests hit the SDK's stateless legacy fallback, which answers as one-event SSE.
- The SDK owns header validation, the body cap (`maxRequestBodySize`), and per-tool
  `insufficient_scope` 403s (`scopeChallenge`). The kit owns Origin exact-match, Bearer
  verification against its own authorization server (`src/oauth/`), and rate limiting.
  Don't re-implement SDK-owned checks.
- Every tool is listed in `tools/list` regardless of granted scopes (step-up discovery);
  scope gating happens at dispatch via `scopeChallengeFor` in `src/two-phase.ts`.

## Tests

- Use `test/helpers.ts`: `getToken` (full OAuth flow), `mcpRequest` (modern request),
  `readRpc` (parses JSON or SSE bodies), `callTool` (strips wire-only `_meta`/`resultType`).
- Security-relevant changes (OAuth, PKCE, tokens, rate limiting, two-phase confirm) need tests
  for both the intended behavior and the failure being prevented.

## Conventions

- Zod 4 only (`^4.2`); tool `inputSchema` must be a `z.object`.
- Raw tool errors never reach clients — only `ToolError` messages pass through (`two-phase.ts`).
- Public API changes: update the README reference tables and `CHANGELOG.md` (Unreleased).
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`); `DEFAULT_SERVER_VERSION` in
  `src/server.ts` must match `package.json` on release.
- `docs/superpowers/plans/` holds historical implementation plans; don't treat them as current.
