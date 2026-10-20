# Security Policy

`mcp-oauth-kit` implements OAuth 2.1 / PKCE, token issuance, and rate limiting —
security is the point of the library. Please report vulnerabilities responsibly.

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Preferred: use GitHub's private vulnerability reporting — open the repository's
**Security** tab → **Report a vulnerability**. This keeps the report private until a
fix is released.

Alternatively, email **bradburch@duck.com** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof-of-concept if possible),
- the affected version(s) / commit.

You can expect an acknowledgement within **5 business days**. We aim to ship a fix or
mitigation for confirmed high-severity issues within **30 days**, and will credit
reporters who wish to be named once a fix is published.

## Supported versions

This project is pre-1.0. Security fixes land on the latest published `0.x` release.
Pin a version and watch releases for security updates.

| Version      | Supported |
| ------------ | --------- |
| latest `0.x` | ✅        |
| older        | ❌        |

## Scope and known limitations

The following are **documented design limitations**, not vulnerabilities. They follow
from the default Cloudflare-KV-style storage backend, which has no compare-and-swap:

- **Idempotency / single-use is best-effort under concurrency.** Authorization-code
  redemption, refresh-token rotation, and the two-phase confirm flow narrow but do not
  fully close double-execute windows. True exactly-once requires a strongly-consistent
  store (e.g. a Durable Object). See the README's two-phase and OAuth sections.
  Within that limit: refresh-token reuse, `/revoke`, and replay of an already-redeemed
  authorization code each revoke the whole token family — every access token in the
  lineage, older generations still inside their TTL included — and a failed code
  redemption consumes the code.
- **Workers KV is eventually consistent.** Changes take up to ~60s to reach other
  locations, so a rotated refresh token, used code, or revoked family can still look valid
  elsewhere in that window, and rate limits are effectively per location. KV also limits
  writes to ~1/sec per key (the rate-limit counter is written every request) and to
  1,000/day on the free plan. Use a Durable Object-backed `KvLike` for strict guarantees —
  see [docs/storage-adapters.md](docs/storage-adapters.md#cloudflare-kv-caveats).
- **Per-IP rate limiting trusts the configured client-IP source.** The default reads
  `CF-Connecting-IP` (authoritative on Cloudflare). Off-Cloudflare deployments **must**
  pass a custom `ipExtractor` that derives the IP from a trusted source, or the
  brute-force guards can be bypassed with a spoofed header. On bare `@hono/node-server`,
  use the socket peer address (`ipExtractor`'s second argument).
- **Per-account lockout is the consumer's job.** The kit limits `/authorize` attempts per
  IP only. If your identity credential is guessable (e.g. a 6-digit code), count failures
  per account in `identity.verify` — its second argument carries the request and the
  trusted client IP.
- **Rate-limit windows are fixed clock hours**, so a client can spend up to twice a limit
  across an hour boundary.
- **In-memory storage is for tests only.** `createMemoryStorage()` is not persistent or
  shared across isolates; never use it in production.
- **Storage keys are not namespaced by `baseUrl`.** If two servers built with this kit
  share one KV namespace, a token/client/code issued by one is resolvable by the other
  (all keys are `mcp:<kind>:<id-or-hash>`, with no per-deployment prefix). Use a separate KV
  namespace/database per deployment, or don't share storage across distinct `baseUrl`s.
- **The CIMD redirect-URI cache lifetime is attacker-influenced within a bounded range.**
  When `allowClientIdMetadataDocuments` is enabled, the cache TTL for a fetched document
  honors that document's own `Cache-Control: max-age` (clamped to 60s–24h) instead of a
  fixed 1-hour TTL. This is a deliberate spec-compliant tradeoff, not a bug — but it means
  the party publishing the CIMD document (also the party whose `redirect_uris` you'd want
  to revoke quickly after a compromise) can elect a cache lifetime up to 24x longer than
  the previous fixed default.

Reports that depend on misconfiguring these (e.g. using memory storage in production,
running off-Cloudflare without an `ipExtractor`, or a guessable credential without
per-account lockout) are out of scope.
