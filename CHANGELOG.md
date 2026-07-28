# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **MCP 2026-07-28 authorization compliance:**
  - `iss` parameter on the authorization-code redirect (RFC 9207).
  - Optional support for [OAuth Client ID Metadata Documents](https://modelcontextprotocol.io/specification/draft/basic/authorization) as an alternative to Dynamic Client Registration, via the new `allowClientIdMetadataDocuments` config option (off by default). DCR remains fully supported — the spec deprecates it with a 12-month minimum window, it does not remove it.
  - `application_type` (`"web" | "native"`) accepted and echoed on `POST /register` (SEP-837).
  - `scope` attribute on the 401 `WWW-Authenticate` challenge, hinting the default scopes.
- Not yet adopted: the MCP TypeScript SDK v2 beta (`@modelcontextprotocol/server`/`@modelcontextprotocol/client`) implementing the non-authorization parts of the 2026-07-28 spec (stateless handshake, `resultType`, `server/discover`, etc.) — see the plan doc for rationale.

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
