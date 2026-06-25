# mcp-server-kit

Production-ready MCP server kit: OAuth 2.1/PKCE, rate limiting, scope-gated tools, and two-phase confirm — bring your own tools, identity, and storage.

## Install

```bash
npm install mcp-server-kit
```

Peer dependencies (not bundled):

```bash
npm install hono @modelcontextprotocol/sdk
```

## Quick start

```ts
import { z } from "zod";
import { createMcpServer, createMemoryStorage } from "mcp-server-kit";

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

| Field        | Type                                | Required | Description                                                                 |
| ------------ | ----------------------------------- | -------- | --------------------------------------------------------------------------- |
| `baseUrl`    | `string`                            | Yes      | Public base URL of this server (used in OAuth discovery and redirect URIs). |
| `storage`    | `KvLike`                            | Yes      | Key-value store for tokens, rate-limit counters, and idempotency records.   |
| `scopes`     | `ScopeConfig[]`                     | Yes      | OAuth scopes the server advertises.                                         |
| `identity`   | `IdentityConfig`                    | No       | Built-in login-form identity provider. Omit to use a custom provider.       |
| `tools`      | `Array<ToolDef \| MutatingToolDef>` | Yes      | Tool definitions registered on the MCP server.                              |
| `rateLimits` | `RateLimitConfig`                   | No       | Per-hour thresholds for tool calls and OAuth endpoints.                     |
| `hooks`      | `ObservabilityHooks`                | No       | Async callbacks for tool calls, OAuth lifecycle events, and mutation audit. |

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

| Field                | Type      | Default | Description                                                       |
| -------------------- | --------- | ------- | ----------------------------------------------------------------- |
| `userPerHour`        | `number?` | 50      | Max MCP tool calls per user per hour.                             |
| `ipAuthorizePerHour` | `number?` | 10      | Max OAuth authorize attempts per IP per hour (brute-force guard). |
| `ipTokenPerHour`     | `number?` | 30      | Max token-endpoint requests per IP per hour.                      |

### `ObservabilityHooks`

All callbacks are fire-and-forget except `onMutation` (which is awaited). Errors are swallowed so a throwing hook never fails the request.

| Field        | Type                       | Description                                                                                                 |
| ------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `onToolCall` | `(event) => Promise<void>` | Called after every tool invocation.                                                                         |
| `onAudit`    | `(event) => Promise<void>` | Called on OAuth lifecycle events (`client_registered`, `token_issued`, `token_refreshed`, `token_revoked`). |
| `onMutation` | `(event) => Promise<void>` | Called (awaited) after a mutating tool's execute phase succeeds.                                            |

## Tool definitions

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

### Mutating tool (`MutatingToolDef`) — two-phase preview → confirm

Mutating tools never execute their side effect on the first call. The flow is:

1. **Preview phase** — the MCP client calls the tool. `mutating.preview(input, ctx)` runs, returns a `{ summary, data }` preview. The kit stores it under a single-use confirmation token (5-minute TTL) and returns the token to the client.
2. **Confirm phase** — the MCP client calls the built-in `confirm_request` tool with the `confirmationToken` from step 1 and a unique `idempotencyKey`. `mutating.execute(data, ctx)` runs, and the result is returned (and cached for 10 minutes under the idempotency key).

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

The kit registers one shared `confirm_request` tool automatically. Its input:

```ts
{
  confirmationToken: string; // from the preview response
  idempotencyKey: string; // caller-generated, unique per logical operation
}
```

#### Idempotency — best-effort, not exactly-once

The kit writes a `"pending"` sentinel before executing, so a concurrent retry that sees it backs off and asks the caller to retry. A retry that sees a cached result replays it without re-executing.

**Limitation:** The underlying KV store has no compare-and-swap. The pending sentinel narrows — but does not fully close — the double-execute window. True exactly-once delivery requires a strongly consistent store (a Durable Object or equivalent). On execute failure the sentinel is deleted so a legitimate retry can re-run.

## Endpoints mounted by `createMcpServer`

| Method   | Path                                      | Description                                             |
| -------- | ----------------------------------------- | ------------------------------------------------------- |
| `GET`    | `/.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata                  |
| `GET`    | `/.well-known/oauth-protected-resource`   | RFC 9728 protected resource metadata                    |
| `POST`   | `/register`                               | Dynamic Client Registration (RFC 7591)                  |
| `GET`    | `/authorize`                              | Render built-in login form                              |
| `POST`   | `/authorize`                              | Process login, issue auth code, 302 redirect            |
| `POST`   | `/token`                                  | Token exchange (`authorization_code` + `refresh_token`) |
| `POST`   | `/revoke`                                 | Token revocation (RFC 7009)                             |
| `POST`   | `/`                                       | MCP transport (stateless streamable-HTTP)               |
| `GET`    | `/`                                       | 405 — stateless mode, no SSE                            |
| `DELETE` | `/`                                       | 405 — stateless mode, no sessions                       |

## Bring your own storage

The default `createMemoryStorage()` is suitable for tests. `createCloudflareKvStorage(kv)` wraps a Cloudflare KV namespace for production. For any other backend, implement `KvLike` (three methods: `get`, `put`, `delete`) and pass it as `storage`.

See [docs/storage-adapters.md](docs/storage-adapters.md) for the interface definition and adapter examples (Redis, DynamoDB, Postgres).

## Deploy

See [docs/deploy.md](docs/deploy.md) for runtime-specific entry-point wrappers (Cloudflare Workers, Node, AWS Lambda, Vercel).

## Public API

Exported from `mcp-server-kit`:

- `createMcpServer(config)` — factory; returns a Hono app
- `createMemoryStorage()` — in-memory `KvLike` for tests
- `createCloudflareKvStorage(kv)` — wraps a Cloudflare KV namespace
- `registerMutatingTool(server, tool, ctx)` — low-level registration helper
- `registerConfirmTool(server, ctx, mutatingTools)` — low-level confirm registration
- `renderAuthorizePage(identity, params)` — renders the built-in login form HTML
- `isMutating(t)` — type guard: `true` when `t` is a `MutatingToolDef`
- `version` — package version string

Types: `McpServerConfig`, `ScopeConfig`, `IdentityField`, `IdentityConfig`, `Branding`, `ObservabilityHooks`, `ToolContext`, `ToolDef`, `MutatingToolDef`, `RateLimitConfig`, `KvLike`, `KVNamespaceLike`, `AuthorizePageParams`

## License

MIT
