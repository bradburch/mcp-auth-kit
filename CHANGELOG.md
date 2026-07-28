# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-28

### Added

- **MCP 2026-07-28 authorization compliance:**
  - `iss` parameter on the authorization-code redirect (RFC 9207), and the corresponding
    `authorization_response_iss_parameter_supported: true` flag on the authorization
    server metadata (RFC 9207 §2.3 requires advertising it).
  - Optional support for [OAuth Client ID Metadata Documents](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) as an alternative to Dynamic Client Registration, via the new `allowClientIdMetadataDocuments` config option (off by default). DCR remains fully supported — the spec deprecates it with a 12-month minimum window, it does not remove it.
  - The CIMD fetch cache now respects the document's `Cache-Control: max-age` (clamped to
    a sane range) instead of a fixed TTL.
  - `application_type` (`"web" | "native"`) accepted and echoed on `POST /register` (SEP-837).
  - `scope` attribute on the 401 `WWW-Authenticate` challenge, hinting the default scopes.
  - `Origin` header validation on the MCP transport (via a new `allowedOrigins` config
    option), rejecting cross-origin requests to guard against DNS rebinding attacks.
  - `Mcp-Method`/`Mcp-Name` request headers, when present, are now validated against the
    JSON-RPC request body and rejected on mismatch — guards against an edge proxy
    routing or authorizing on the header while the server executes on the body.
- The Protected Resource Metadata document now also advertises `scopes_supported`, and is
  now served both at the root well-known path and at its `/mcp` sub-path (so it resolves
  correctly when the server is mounted under a sub-path).
- The login page now displays the redirect URI's hostname ("Signing in to: ...") so users
  can verify where they're about to be redirected, with an additional warning banner when
  the redirect target is `localhost`/`127.0.0.1`.
- A `frame-ancestors 'none'` directive on the login page's Content-Security-Policy,
  preventing the login form from being framed (clickjacking hardening).
- `baseUrl` is now validated to be `https://` (except for `localhost`/`127.0.0.1`, allowed
  for local development) when the server is constructed.
- Not yet adopted: the MCP TypeScript SDK v2 beta (`@modelcontextprotocol/server`/`@modelcontextprotocol/client`) implementing the non-authorization parts of the 2026-07-28 spec (stateless handshake, `resultType`, `server/discover`, etc.) — see the plan doc for rationale.

### Changed

- **Breaking:** Scope-gated tools are no longer hidden from `tools/list` — every
  registered tool is now listed regardless of the caller's granted scopes. Calling a tool
  the caller lacks scope for now returns an `isError` tool result naming the missing
  scope, and for a single (non-batch) `tools/call` request the transport additionally
  returns an HTTP 403 with a `WWW-Authenticate: insufficient_scope` challenge, enabling
  step-up authorization instead of silently hiding capabilities.
- Token validation now re-checks the token's audience against the server's `baseUrl` as a
  defense-in-depth measure (RFC 8707 §2), guarding against a KV namespace ever being
  shared across two servers built with this kit.
- The `@modelcontextprotocol/sdk` peer dependency is now pinned to `^1` (was an
  open-ended `>=1`), so a hypothetical future major SDK release can't silently break
  consumers.

### Fixed

- The authorization server metadata no longer includes a non-standard `resource` field
  (RFC 8414 doesn't define one; RFC 9728's Protected Resource Metadata is the correct
  place for it).
- `ToolContext.env` now carries the real Hono `c.env` passed through from the request; it
  was previously always `undefined`. Its doc comment now accurately describes `env`
  across runtimes (Cloudflare Workers, Node, Lambda, Vercel), not just Cloudflare.
- The bundled `appointments` example's `baseUrl` now matches where it actually runs, and
  the Cloudflare Workers deploy guide's environment-variable access example was corrected.

### Documentation

- Numerous corrections across `README.md`, `deploy.md`, `how-to-use.md`, and
  `CONTRIBUTING.md`: peer-dependency versions, an ESM-only note, API signatures, a
  sub-path mounting contradiction, a transport-version caveat, the new scope-gating
  behavior, missing `identity` config in deploy examples, a Vercel origin-root routing
  mistake, an inaccurate in-memory-adapter claim, runnable code samples, the two-phase
  confirmation wire contract, the mandatory `Accept` header, and a corrected
  custom-identity example.
- Added `repository`/`homepage`/`bugs`/`keywords` package metadata so npm's package page
  links back to GitHub, and softened `CONTRIBUTING.md`'s "production-grade" claim, which
  contradicted the README's own pre-1.0 status banner.
- Documented that storage keys aren't namespaced by `baseUrl` — a shared KV namespace
  across two deployments would make tokens/clients/codes cross-resolvable — and
  recommended a separate namespace per deployment (`SECURITY.md`).

[0.2.0]: https://github.com/bradburch/mcp-auth-kit/releases/tag/v0.2.0

## [0.1.0] - 2026-06-25

First publishable release. Establishes the public API and hardens the OAuth/auth surface
for production use.

### Added

- **Refresh-token reuse detection (RFC 9700).** Tokens rotated from one authorization
  share a family; replaying a rotated-out refresh token now revokes the entire family.
- **Configurable trusted client-IP source** via `ipExtractor` on `McpServerConfig` /
  `OAuthRouteDeps`, so non-Cloudflare deployments can avoid spoofable rate-limit buckets.
- **Per-IP rate limiting on `/register` and `/revoke`** (previously only `/authorize` and
  `/token`), guarding against unauthenticated storage-exhaustion abuse.
- Defense-in-depth, storage-independent expiry checks for access tokens and authorization
  codes.
- Confirmation tokens in the two-phase flow are now bound to the previewing user.
- Project hygiene: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR
  templates, `engines` field, and a CI build step.
- Minimum supported Node is **22** (Node 20 reached end-of-life); CI runs the suite on a
  Node 22 / 24 / 26 matrix, and `@types/node` tracks the support floor.

### Changed

- Access, refresh, authorization-code, and confirmation tokens now use 256-bit
  (`crypto.getRandomValues`) entropy instead of `crypto.randomUUID()` (~122 bits).
- `POST /authorize` validates the client **before** invoking `identity.verify` and returns
  a uniform error for a bad client or bad credentials — closing a credential-validity /
  user-enumeration oracle.
- The 1 MB body cap is now enforced **while streaming** on all OAuth routes and the MCP
  transport (bytes are capped as they arrive, not just via the `Content-Length` header), so
  a chunked/length-omitting request can neither bypass the cap nor buffer an unbounded body
  into memory before rejection.
- `branding.accentColor` is validated against a strict hex pattern before being
  interpolated into the login page's `<style>` block (CSS-injection hardening).

### Fixed

- `npm run build` failed under TypeScript 6 (`TS5011`): `rootDir` is now set explicitly,
  so `dist/` builds and ships correctly.
- `package.json` `exports` now declares a `types` condition so consumers resolve the
  bundled `.d.ts` under `node16`/`nodenext`/`bundler` module resolution.
- Added a `prepublishOnly` build hook so a publish can't ship a stale or empty `dist/`.

[0.1.0]: https://github.com/bradburch/mcp-auth-kit/releases/tag/v0.1.0
