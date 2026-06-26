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
- **Per-IP rate limiting trusts the configured client-IP source.** The default reads
  `CF-Connecting-IP` (authoritative on Cloudflare). Off-Cloudflare deployments **must**
  pass a custom `ipExtractor` that derives the IP from a trusted source, or the
  brute-force guards can be bypassed with a spoofed header.
- **In-memory storage is for tests only.** `createMemoryStorage()` is not persistent or
  shared across isolates; never use it in production.

Reports that depend on misconfiguring these (e.g. using memory storage in production, or
running off-Cloudflare without an `ipExtractor`) are out of scope.
