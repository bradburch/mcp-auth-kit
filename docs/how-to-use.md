# How to use mcp-oauth-kit

A practical, step-by-step guide to building and running an OAuth-protected MCP server with
the kit. For the exhaustive config/API reference, see the [README](../README.md); for
runtime wrappers see [deploy.md](deploy.md); for storage backends see
[storage-adapters.md](storage-adapters.md).

## Mental model

`createMcpServer(config)` returns a [Hono](https://hono.dev/) app that bundles four things
behind one origin:

1. **OAuth 2.1 / PKCE authorization server** — discovery, dynamic client registration,
   `/authorize`, `/token`, `/revoke`.
2. **A built-in login form** (the "identity provider") that collects credentials and calls
   _your_ `verify` function.
3. **The MCP transport** at `POST /mcp` (stateless streamable-HTTP), authenticated per
   request by a Bearer token.
4. **Cross-cutting policy** — per-user and per-IP rate limiting, scope gating, a two-phase
   confirm flow for mutating tools, and observability hooks.

You bring three things: **tools**, an **identity `verify`** function, and a **storage**
backend. Everything else is wired for you.

```
MCP client ──discovery──▶ /.well-known/*
           ──register──▶  POST /register        ──▶ client_id
           ──login─────▶  GET/POST /authorize   ──▶ auth code (after your verify() passes)
           ──exchange──▶  POST /token           ──▶ access + refresh token
           ──call──────▶  POST /mcp (Bearer)    ──▶ your tool handlers
```

## 1. Install

```bash
npm install mcp-oauth-kit
# peer dependencies (not bundled):
npm install hono @modelcontextprotocol/sdk zod
```

Node **22+** is required.

## 2. A minimal server

Start with a single read-only tool and no auth-backend of your own — the in-memory store is
fine for local development.

```ts
// server.ts
import { z } from "zod";
import { createMcpServer, createMemoryStorage } from "mcp-oauth-kit";

export const app = createMcpServer({
  baseUrl: "http://localhost:3000", // MUST match where the server is actually reachable
  storage: createMemoryStorage(), // dev/tests only — never in production
  scopes: [{ name: "account:read", default: true }],
  identity: {
    fields: [{ name: "email", label: "Email", type: "email", required: true }],
    // Return a STABLE user id string on success, or null to reject.
    verify: async (fields) => (fields.email.endsWith("@example.com") ? fields.email : null),
  },
  tools: [
    {
      name: "whoami",
      description: "Return the caller's user id.",
      inputSchema: z.object({}),
      handler: async (_input, ctx) => ({
        content: [{ type: "text", text: `You are ${ctx.userId}` }],
      }),
    },
  ],
});
```

> **`baseUrl` must be exact.** It is advertised in OAuth discovery, used to build redirect
> URIs, and is the audience (`resource`) tokens are bound to. A mismatch breaks discovery and
> token validation for spec-compliant clients. Serve the app at the **origin root** — not
> under a path prefix.

## 3. Run it locally

```bash
npm install --save-dev @hono/node-server tsx
```

```ts
// run.ts
import { serve } from "@hono/node-server";
import { app } from "./server.js";

serve({ fetch: app.fetch, port: 3000 }, () => console.log("MCP server on http://localhost:3000"));
```

```bash
npx tsx run.ts
# sanity check discovery:
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq
```

A complete runnable example lives in [`examples/appointments/`](../examples/appointments/).

## 4. Define your identity provider

`identity.verify(fields)` is the single integration point for authentication. The kit renders
a login form from `identity.fields`, collects the values, and hands them to `verify`. Return a
**stable user id** (the same string every time for a given user — it keys rate limits and
shows up as `ctx.userId`) or `null` to reject.

```ts
identity: {
  branding: { appName: "Acme", accentColor: "#3b82f6" }, // optional
  fields: [
    { name: "email", label: "Email", type: "email", required: true },
    { name: "code", label: "One-time code", type: "text", required: true },
  ],
  verify: async (fields) => {
    const user = await db.verifyLoginCode(fields.email, fields.code);
    return user ? user.id : null;
  },
}
```

The kit never stores credentials — it only stores the issued tokens (hashed) keyed to the
user id you return. If you already run your own OAuth UI, omit `identity` and compose the
lower-level pieces (see the README's "Advanced / low-level API").

## 5. Scopes and scope gating

Declare the scopes your server understands. Mark the ones granted when a client requests none
as `default: true`.

```ts
scopes: [
  { name: "account:read", default: true },
  { name: "write", description: "Make changes on the user's behalf" },
],
```

Attach `scope` to a tool to gate it. A caller whose token lacks the scope can't call the tool
**and won't even see it** in `tools/list`:

```ts
{
  name: "delete_thing",
  description: "Delete a thing.",
  scope: "write",          // hidden + blocked unless the token has "write"
  inputSchema: z.object({ id: z.string() }),
  handler: async (input, ctx) => { /* ctx.scopes lists everything granted */ },
}
```

## 6. Tools: read vs. mutating (two-phase confirm)

A **read tool** has a `handler` and runs immediately.

A **mutating tool** has `mutating.preview` + `mutating.execute` and never performs its side
effect on the first call. Instead the kit returns a single-use `confirmationToken`; the client
then calls the built-in `confirm_request` tool with that token and a unique `idempotencyKey` to
actually execute. This gives the human/agent a chance to review the action first.

```ts
{
  name: "book_slot",
  description: "Book an appointment slot.",
  scope: "write",
  inputSchema: z.object({ slot: z.string() }),
  mutating: {
    // Phase 1 — validate + describe. NO side effect here.
    preview: async (input) => {
      const { slot } = input as { slot: string };
      return { summary: `Book ${slot}`, data: { slot } };
    },
    // Phase 2 — runs only after confirm_request with the token from phase 1.
    execute: async (data, ctx) => {
      const { slot } = data as { slot: string };
      await db.book(ctx.userId, slot);
      return { content: [{ type: "text", text: `Booked ${slot}.` }] };
    },
  },
}
```

The confirmation token is bound to the user who previewed it, expires after 5 minutes, and is
single-use. Results are cached under the idempotency key for 10 minutes so a retried confirm
replays rather than re-executes. (Exactly-once is best-effort on a store without
compare-and-swap — see the README for the precise guarantee.)

## 7. Drive the full OAuth + MCP flow (end to end)

This is what a spec-compliant MCP client does under the hood. You can reproduce it with `curl`
to verify your server. It uses PKCE (S256).

```bash
BASE=http://localhost:3000

# (a) Generate a PKCE verifier + challenge
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')

# (b) Register a client (Dynamic Client Registration)
CLIENT_ID=$(curl -s -X POST $BASE/register \
  -H 'content-type: application/json' \
  -d '{"redirect_uris":["http://localhost:9999/cb"]}' | jq -r .client_id)

# (c) Log in — submit the identity form. On success the server 302-redirects with ?code=...
CODE=$(curl -s -i -X POST $BASE/authorize \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$BASE/mcp" \
  --data-urlencode "email=you@example.com" \
  | grep -i '^location:' | sed -E 's/.*[?&]code=([^&[:space:]]+).*/\1/')

# (d) Exchange the code for tokens
ACCESS=$(curl -s -X POST $BASE/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$BASE/mcp" | jq -r .access_token)

# (e) Call a tool over MCP
curl -s -X POST $BASE/mcp \
  -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}' | jq
```

In a real MCP client (Claude, an IDE plugin, etc.) you just point it at `http://localhost:3000`
and it performs steps (a)–(e) for you.

## 8. Observe what happens (hooks)

All hooks are optional and fire-and-forget except `onMutation`, which is awaited.

```ts
hooks: {
  onToolCall: async (e) => log.info("tool", e.toolName, "by", e.userId),
  onAudit: async (e) => log.info("oauth", e.event, e.clientId), // registered / issued / refreshed / revoked
  onMutation: async (e) => auditLedger.write(e), // awaited — durable side effect
}
```

A throwing hook never fails the request.

## 9. Going to production — checklist

- [ ] **Swap storage.** Replace `createMemoryStorage()` with `createCloudflareKvStorage(kv)`
      or another `KvLike` ([storage-adapters.md](storage-adapters.md)). Memory storage is not
      persistent or shared across instances.
- [ ] **Serve at the origin root** over HTTPS, with `baseUrl` set to that exact public URL.
- [ ] **Set the trusted client-IP source if you're _not_ behind Cloudflare.** Pass
      `ipExtractor` so per-IP rate limits can't be bypassed with a spoofed header (see the
      README's RateLimitConfig section).
- [ ] **Tune `rateLimits`** for your traffic (defaults: 50 tool calls/user/hr, 10
      authorize/IP/hr, 30 token+register+revoke/IP/hr).
- [ ] **Pick your deployment adapter** ([deploy.md](deploy.md): Workers, Node, Lambda, Vercel).
- [ ] **Wire `hooks`** to your logging/audit pipeline.
- [ ] Review the security model and documented limitations in [SECURITY.md](../SECURITY.md).

## Where to go next

- [README](../README.md) — full config reference, endpoint table, and OAuth/PKCE details.
- [deploy.md](deploy.md) — runtime-specific entry points.
- [storage-adapters.md](storage-adapters.md) — implementing `KvLike` for Redis/DynamoDB/Postgres.
- [`examples/appointments/`](../examples/appointments/) — a complete working server.
