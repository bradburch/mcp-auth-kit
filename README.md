# mcp-oauth-kit

A production-minded MCP server kit: OAuth 2.1/PKCE, rate limiting, scope-gated tools, and two-phase confirm — bring your own tools, identity, and storage.

> **⚠️ Status: pre-1.0 (`0.1.0`).** The OAuth core is independently reviewed and tested, but the API may still change and there are **deliberate design limitations** to understand before production use — most importantly: single-use code redemption, refresh-token rotation, and confirm idempotency are **best-effort, not exactly-once** on a storage backend without compare-and-swap; and per-IP rate limiting needs a correct `ipExtractor` when you're not behind Cloudflare. Read [SECURITY.md](SECURITY.md#scope-and-known-limitations) before deploying, and pin a version.

**New here?** Start with the [How-to-use guide](docs/how-to-use.md) for a step-by-step walkthrough (including an end-to-end OAuth flow you can run with `curl`). This README is the full config/API reference.

## Install

```bash
npm install mcp-oauth-kit
```

Peer dependencies (not bundled):

```bash
npm install hono @modelcontextprotocol/sdk
```

## Quick start

```ts
import { z } from "zod";
import { createMcpServer, createMemoryStorage } from "mcp-oauth-kit";

const app = createMcpServer({
  baseUrl: "https://mcp.example.com",
  storage: createMemoryStorage(), // swap for createCloudflareKvStorage in production
  scopes: [
    { name: "account:read", default: true },
    { name: "write", default: true },
  ],
  identity: {
    fields: [
      { name: "email", label: "Email", type: "email", required: true },
      {
        name: "code",
        label: "Verification Code",
        type: "text",
        required: true,
      },
    ],
    verify: async (fields) => {
      // Return a stable userId string on success, null to reject.
      const user = await db.lookupUser(fields.email, fields.code);
      return user ? user.id : null;
    },
  },
  tools: [
    {
      name: "list_slots",
      description: "List available appointment slots for today.",
      inputSchema: z.object({}),
      handler: async (_input, _ctx) => ({
        content: [{ type: "text", text: "09:00, 10:00, 11:00" }],
      }),
    },
    {
      name: "book_slot",
      description: "Book an appointment slot.",
      scope: "write",
      inputSchema: z.object({ slot: z.string() }),
      mutating: {
        preview: async (input) => {
          const { slot } = input as { slot: string };
          return { summary: `book ${slot}`, data: { slot } };
        },
        execute: async (data) => {
          const { slot } = data as { slot: string };
          return { content: [{ type: "text", text: `Booked ${slot}.` }] };
        },
      },
    },
  ],
});

// app is a Hono instance — export it for your runtime adapter.
export default app;
```

See `examples/appointments/server.ts` for a complete working server.

## Config reference

`createMcpServer(config: McpServerConfig)` accepts:

| Field                            | Type                                | Required | Description                                                                                                                                                                                                                                                         |
| -------------------------------- | ----------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `baseUrl`                        | `string`                            | Yes      | Public base URL of this server (used in OAuth discovery and redirect URIs).                                                                                                                                                                                         |
| `storage`                        | `KvLike`                            | Yes      | Key-value store for tokens, rate-limit counters, and idempotency records.                                                                                                                                                                                           |
| `scopes`                         | `ScopeConfig[]`                     | Yes      | OAuth scopes the server advertises.                                                                                                                                                                                                                                 |
| `identity`                       | `IdentityConfig`                    | No       | Built-in login-form identity provider. Omit to use a custom provider.                                                                                                                                                                                               |
| `tools`                          | `Array<ToolDef \| MutatingToolDef>` | Yes      | Tool definitions registered on the MCP server.                                                                                                                                                                                                                      |
| `rateLimits`                     | `RateLimitConfig`                   | No       | Per-hour thresholds for tool calls and OAuth endpoints.                                                                                                                                                                                                             |
| `hooks`                          | `ObservabilityHooks`                | No       | Async callbacks for tool calls, OAuth lifecycle events, and mutation audit.                                                                                                                                                                                         |
| `ipExtractor`                    | `(req: Request) => string`          | No       | Override how the trusted client IP is derived for per-IP rate limiting (see below).                                                                                                                                                                                 |
| `allowClientIdMetadataDocuments` | `boolean`                           | No       | Resolve unregistered `https://` client_ids as [Client ID Metadata Documents](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) instead of requiring Dynamic Client Registration. Off by default (see "OAuth / PKCE client flow" below). |

### `ScopeConfig`

| Field         | Type       | Description                                          |
| ------------- | ---------- | ---------------------------------------------------- |
| `name`        | `string`   | Scope name (e.g. `"account:read"`).                  |
| `description` | `string?`  | Human-readable description.                          |
| `default`     | `boolean?` | Granted when the client requests no specific scopes. |

### `IdentityConfig`

| Field      | Type                                  | Description                                                              |
| ---------- | ------------------------------------- | ------------------------------------------------------------------------ |
| `fields`   | `IdentityField[]`                     | Fields rendered on the built-in login form.                              |
| `branding` | `Branding?`                           | App name, logo URL, and accent colour for the form.                      |
| `verify`   | `(fields) => Promise<string \| null>` | Validate credentials. Return a stable userId string or `null` to reject. |

### `IdentityField`

| Field      | Type       | Description                                             |
| ---------- | ---------- | ------------------------------------------------------- |
| `name`     | `string`   | HTML input name and key in the submitted record.        |
| `label`    | `string`   | Human-readable label.                                   |
| `type`     | `string?`  | HTML input type (`"text"`, `"password"`, `"email"`, …). |
| `required` | `boolean?` | Whether the field is required.                          |

### `Branding`

| Field         | Type      | Description                           |
| ------------- | --------- | ------------------------------------- |
| `appName`     | `string`  | App name shown in the UI heading.     |
| `logoUrl`     | `string?` | URL to a logo image.                  |
| `accentColor` | `string?` | Hex accent colour (e.g. `"#3b82f6"`). |

### `RateLimitConfig`

All limits are per-hour. Omit a field to use the default.

| Field                | Type      | Default | Description                                                           |
| -------------------- | --------- | ------- | --------------------------------------------------------------------- |
| `userPerHour`        | `number?` | 50      | Max MCP tool calls per user per hour.                                 |
| `ipAuthorizePerHour` | `number?` | 10      | Max OAuth authorize attempts per IP per hour (brute-force guard).     |
| `ipTokenPerHour`     | `number?` | 30      | Max requests per IP per hour to `/token`, `/register`, and `/revoke`. |

The `/register` and `/revoke` endpoints share the per-IP `ipTokenPerHour` bucket so that unauthenticated requests can't be used for storage-exhaustion abuse.

Rate-limit counters use a non-atomic read-modify-write (KV has no atomic increment) — counts may under-count under high concurrency. For strict enforcement, wrap `createRateLimiter` with a Durable Object counter or equivalent.

**Trusted client IP.** By default the per-IP source is `CF-Connecting-IP` (authoritative on Cloudflare) falling back to the first hop of `X-Forwarded-For`. `X-Forwarded-For` is client-spoofable unless a trusted proxy overwrites it, so **off-Cloudflare deployments must pass a custom `ipExtractor`** that derives the IP from a source you control — otherwise the brute-force guards can be bypassed by rotating the header:

```ts
createMcpServer({
  // ...
  ipExtractor: (req) => req.headers.get("True-Client-IP") ?? "unknown",
});
```

### `ObservabilityHooks`

All callbacks are fire-and-forget except `onMutation` (which is awaited). Errors are swallowed so a throwing hook never fails the request.

| Field        | Type                       | Description                                                                                                 |
| ------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `onToolCall` | `(event) => Promise<void>` | Called after every tool invocation.                                                                         |
| `onAudit`    | `(event) => Promise<void>` | Called on OAuth lifecycle events (`client_registered`, `token_issued`, `token_refreshed`, `token_revoked`). |
| `onMutation` | `(event) => Promise<void>` | Called (awaited) after a mutating tool's execute phase succeeds.                                            |

## Tool definitions

Each tool in the `tools` array is either a `ToolDef` (has a `handler` — called directly) or a `MutatingToolDef` (has a `mutating.preview` and `mutating.execute` — uses the two-phase confirm flow). The two shapes are mutually exclusive.

### Standard tool (`ToolDef`)

```ts
{
  name: "list_slots",
  description: "List available slots.",
  inputSchema: z.object({}),
  scope: "account:read",   // optional — omit for no scope check
  handler: async (input, ctx) => ({
    content: [{ type: "text", text: "..." }],
  }),
}
```

`ctx` is a `ToolContext`:

```ts
interface ToolContext {
  userId: string;
  scopes: string[];
  storage: KvLike;
  env: unknown; // Cloudflare Worker env bindings — cast to your own type
  hooks: ObservabilityHooks;
}
```

### Scope gating

If a tool specifies `scope`, the kit checks the caller's token at dispatch time. A caller whose token lacks the required scope receives an error without the handler running — the tool is also hidden from the `tools/list` response for that caller. Scopes flagged `default: true` in the server config are automatically granted when the client requests no explicit scopes. `ctx.scopes` inside a handler reflects the token's full granted scope list.

### Mutating tool (`MutatingToolDef`) — two-phase preview → confirm

Mutating tools never execute their side effect on the first call. The flow is:

1. **Preview phase** — the MCP client calls the tool. `mutating.preview(input, ctx)` runs, returns a `{ summary, data }` preview. The kit stores it under a single-use confirmation token (5-minute TTL) and returns the token to the client.
2. **Confirm phase** — the MCP client calls the built-in `confirm_request` tool with the `confirmationToken` from step 1 and a unique `idempotencyKey`. `mutating.execute(data, ctx)` runs, and the result is returned (and cached for 10 minutes under the idempotency key). The confirmation token is bound to the user who previewed it: a confirm from a different user is rejected and does not consume the token.

> **Idempotency — best-effort, not exactly-once:** The kit writes a `"pending"` sentinel before
> executing, so a concurrent retry that sees it backs off and asks the caller to retry. A retry
> that sees a cached result replays it without re-executing. **Limitation:** The underlying KV
> store has no compare-and-swap. The pending sentinel narrows — but does not fully close — the
> double-execute window. True exactly-once delivery requires a strongly consistent store (a
> Durable Object or equivalent). On execute failure the sentinel is deleted so a legitimate retry
> can re-run.

```ts
{
  name: "book_slot",
  description: "Book an appointment slot.",
  scope: "write",
  inputSchema: z.object({ slot: z.string() }),
  mutating: {
    preview: async (input) => {
      const { slot } = input as { slot: string };
      return { summary: `book ${slot}`, data: { slot } };
    },
    execute: async (data, ctx) => {
      const { slot } = data as { slot: string };
      // carry out the side effect here
      return { content: [{ type: "text", text: `Booked ${slot}.` }] };
    },
  },
}
```

#### `confirm_request` tool

The kit registers one shared `confirm_request` tool automatically. Its input schema:

```ts
z.object({
  confirmationToken: z.string(), // from the preview response
  idempotencyKey: z.string(), // caller-generated, unique per logical operation
});
```

## Endpoints mounted by `createMcpServer`

The Hono app returned by `createMcpServer` must be served at the **origin root** (i.e. `https://mcp.example.com/`). RFC 8414 requires `/.well-known/oauth-authorization-server` to resolve at the domain root, and the protected resource is advertised as `${baseUrl}/mcp` — mounting under a path prefix would break discovery and token validation for spec-compliant clients.

| Method   | Path                                      | Description                                             |
| -------- | ----------------------------------------- | ------------------------------------------------------- |
| `GET`    | `/.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata                  |
| `GET`    | `/.well-known/oauth-protected-resource`   | RFC 9728 protected resource metadata                    |
| `POST`   | `/register`                               | Dynamic Client Registration (RFC 7591)                  |
| `GET`    | `/authorize`                              | Render built-in login form                              |
| `POST`   | `/authorize`                              | Process login, issue auth code, 302 redirect            |
| `POST`   | `/token`                                  | Token exchange (`authorization_code` + `refresh_token`) |
| `POST`   | `/revoke`                                 | Token revocation (RFC 7009)                             |
| `POST`   | `/mcp`                                    | MCP transport (stateless streamable-HTTP)               |
| `GET`    | `/mcp`                                    | 405 — stateless mode, no SSE                            |
| `DELETE` | `/mcp`                                    | 405 — stateless mode, no sessions                       |

### Request body limit

All request bodies — OAuth endpoints and `POST /mcp` — are capped at **1 MB** (HTTP 413 if exceeded). If your tools accept large inputs (e.g. document contents), pre-process or chunk them before sending.

## OAuth / PKCE client flow

The kit implements OAuth 2.1 with PKCE (S256). A standards-compliant MCP client discovers and authenticates as follows:

1. **Discovery** — `GET /.well-known/oauth-authorization-server` (RFC 8414) returns server metadata including `authorization_endpoint`, `token_endpoint`, and `registration_endpoint`.
2. **Client registration** — either **Dynamic Client Registration**: `POST /register` with `{ "redirect_uris": ["https://your-client/callback"] }` returns a `client_id`; or, if `allowClientIdMetadataDocuments` is enabled, a **Client ID Metadata Document**: use an `https://` URL hosting a `{ client_id, redirect_uris, ... }` JSON document as the `client_id` directly, with no registration call (MCP 2026-07-28 deprecates DCR in favor of this — DCR remains fully supported here).
3. **Authorization** — redirect the user to `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `code_challenge` (S256 PKCE), and optionally `scope`. The built-in identity form collects credentials and calls your `identity.verify`. On success, the server 302-redirects to `redirect_uri?code=<auth_code>&iss=<baseUrl>` (the `iss` parameter, RFC 9207, lets a compliant client detect an authorization-server mix-up before redeeming the code).
4. **Token exchange** — `POST /token` with `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, and `code_verifier`. Returns `{ access_token, refresh_token, expires_in, token_type: "Bearer" }`.
5. **Call tools** — send MCP JSON-RPC to `POST /mcp` with `Authorization: Bearer <access_token>`.
6. **Token refresh** — `POST /token` with `grant_type=refresh_token` and `refresh_token`. Issues a new access + refresh token pair (rotation). Note: the prior access token remains valid until its TTL (~1 hour) expires naturally. **Reuse detection (RFC 9700):** all tokens rotated from one authorization share a family; presenting a refresh token that has already been rotated out revokes the entire family (its active access + refresh tokens), containing a stolen token. Detection is eventually-consistent — like single-use code redemption, a concurrent race isn't fully closed without a strongly-consistent store. **Client implication:** always refresh with the newest refresh token and never retry a refresh using a previously-rotated token — doing so is indistinguishable from theft and will revoke the whole session.
7. **Revocation** — `POST /revoke` with the access or refresh token to invalidate it immediately (paired token is also revoked).

## Bring your own storage

The default `createMemoryStorage()` is suitable for tests only — it is not persistent and is not shared across isolates or instances; never use it in production. `createCloudflareKvStorage(kv)` wraps a Cloudflare KV namespace for production. For any other backend, implement `KvLike` (three methods: `get`, `put`, `delete`) and pass it as `storage`.

See [docs/storage-adapters.md](docs/storage-adapters.md) for the interface definition and adapter examples (Redis, DynamoDB, Postgres).

## Deploy

See [docs/deploy.md](docs/deploy.md) for runtime-specific entry-point wrappers (Cloudflare Workers, Node, AWS Lambda, Vercel).

## Public API

### Primary API (start here)

- `createMcpServer(config)` — factory; returns a Hono app
- `createMemoryStorage()` — in-memory `KvLike` for tests
- `createCloudflareKvStorage(kv)` — wraps a Cloudflare KV namespace
- `registerMutatingTool(server, tool, ctx)` — low-level registration helper
- `registerConfirmTool(server, ctx, mutatingTools)` — low-level confirm registration
- `isMutating(t)` — type guard: `true` when `t` is a `MutatingToolDef`

Types: `McpServerConfig`, `ScopeConfig`, `IdentityField`, `IdentityConfig`, `Branding`, `ObservabilityHooks`, `ToolContext`, `ToolDef`, `MutatingToolDef`, `RateLimitConfig`, `KvLike`, `KVNamespaceLike`, `AuthorizePageParams`

### Advanced / low-level API

Reach for these when you need to compose your own Hono app — custom middleware, sub-path mounting, or a custom OAuth UI — rather than using `createMcpServer` directly.

- `createOAuthProvider(config)` — build the OAuth provider independently. `OAuthProviderConfig` fields: `storage`, `scopes`, `baseUrl`, and optional `now?: () => number` (injectable clock for deterministic testing).
- `mountOAuthRoutes(app, deps)` — mount `/register`, `/authorize`, `/token`, `/revoke` onto an existing Hono app.
- `mountDiscovery(app, deps)` — mount `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`.
- `createRateLimiter({ storage, config? })` — build the rate limiter independently.
- `handleMcpRequest(req, deps)` — handle a single `POST /mcp` request; returns a `Promise<Response>`.
- `renderAuthorizePage(params)` — render the built-in login form HTML (use when building a custom `/authorize` handler).

Types: `OAuthProvider`, `OAuthProviderConfig`, `TokenPair`, `OAuthRouteDeps`, `DiscoveryDeps`, `RateLimiter`, `McpRequestDeps`

## License

MIT
