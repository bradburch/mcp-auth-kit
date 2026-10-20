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
npm install hono @modelcontextprotocol/server zod
# Node adapter (a runtime dependency, not a dev one):
npm install @hono/node-server
```

Node **22+** is required, and your project must be ESM (`"type": "module"`).

> **TypeScript is optional.** The snippets below are TypeScript, but everything except the
> type annotations (`type` imports, `: Foo` annotations) is plain ESM JavaScript: name the file
> `server.js` and run `node server.js`. `defineTool` is only a typing helper — in JS you can
> pass the tool objects directly. Node 22.18+ / 23.6+ can also run `.ts` files directly via
> built-in type stripping (`node run.ts`) — relative imports must then name the real `.ts`
> file (`./server.ts`, as in §3), not `./server.js`.

## 2. A minimal server

Start with a single read-only tool and no auth-backend of your own — the in-memory store is
fine for local development.

```ts
// server.ts
import { z } from "zod";
import { createMcpServer, createMemoryStorage, defineTool } from "mcp-oauth-kit";

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
    defineTool({
      name: "whoami",
      description: "Return the caller's user id.",
      inputSchema: z.object({}),
      handler: async (_input, ctx) => `You are ${ctx.userId}`, // strings become text content
    }),
  ],
});
```

> **`baseUrl` must be exact.** It is advertised in OAuth discovery, used to build redirect
> URIs, and is the audience (`resource`) tokens are bound to. A mismatch breaks discovery and
> token validation for spec-compliant clients. Serve the app at the **origin root** — not
> under a path prefix.

## 3. Run it locally

```bash
npm install @hono/node-server   # runtime dependency
```

```ts
// run.ts
import { serve } from "@hono/node-server";
import { app } from "./server.ts"; // the .ts extension is what lets plain `node` resolve it

serve({ fetch: app.fetch, port: 3000 }, () => console.log("MCP server on http://localhost:3000"));
```

```bash
node run.ts   # Node 22.18+ / 23.6+ (built-in type stripping); older Node: npm i -D tsx && npx tsx run.ts
# sanity check discovery:
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq
```

If you type-check with `tsc`, importing `./server.ts` needs `"allowImportingTsExtensions": true`
with `"noEmit": true` (or `"rewriteRelativeImportExtensions": true` if `tsc` emits JS). In plain
JS, name the files `.js` and import `./server.js`.

A complete runnable example lives in [`examples/appointments/`](../examples/appointments/).

### Alongside your own routes

The returned app is plain Hono, so you can mount it inside your own app at the root:

```ts
import { Hono } from "hono";
import { createMcpServer } from "mcp-oauth-kit";

const app = new Hono();
app.get("/", (c) => c.text("Hello"));
app.route("/", createMcpServer({/* ... */}));
```

The kit owns `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`
(and `/.well-known/oauth-protected-resource/mcp`), `/register`, `/authorize`, `/token`,
`/revoke`, and `/mcp` — keep your routes off those. The kit's login creates **no browser
session or cookie** (it only hands an OAuth code to the MCP client), so a web UI of your own
needs its own authentication.

## 4. Define your identity provider

`identity.verify(fields, { request, ip })` is the single integration point for
authentication. The kit renders a login form from `identity.fields`, collects the values, and
hands them to `verify`. Return a **stable user id** (the same string every time for a given
user — it keys rate limits and shows up as `ctx.userId`) or `null` to reject. Values are
strings (missing fields are `""`); non-password fields are trimmed, password fields are passed
verbatim and never refilled on a failed attempt. The form also lists the scopes being granted,
using each scope's `description`.

```ts
identity: {
  branding: { appName: "Acme", accentColor: "#3b82f6" }, // optional
  fields: [
    { name: "email", label: "Email", type: "email", required: true },
    { name: "code", label: "One-time code", type: "text", required: true },
  ],
  verify: async (fields) => {
    // Illustrative in-memory check — replace with your real user store/lookup.
    const validCodes = new Map([["you@example.com", "123456"]]);
    return validCodes.get(fields.email) === fields.code ? fields.email : null;
  },
}
```

The kit never stores credentials — it only stores the issued tokens (hashed) keyed to the
user id you return.

> **Add per-account lockout for short codes.** The kit rate-limits `/authorize` per IP only
> (`ipAuthorizePerHour`); an attacker rotating IPs can still guess a 6-digit code. Count
> failures per account inside `verify` — the second argument gives you the raw `request` and
> the trusted client `ip` (from `ipExtractor`) to key on.

### Bringing your own OAuth UI / SSO instead of `identity`

If you already run your own OAuth UI or SSO flow (SAML, OIDC, an existing login page),
`createMcpServer`'s built-in `identity` form isn't your integration point — it's a credential
form, not a redirect-based federation client. Compose the lower-level pieces instead, and
call `provider.issueAuthCode` yourself from wherever your own login flow lands:

> **The route must be `/authorize`, and it must be registered before `mountOAuthRoutes`.**
> `mountDiscovery` publishes `authorization_endpoint: "<baseUrl>/authorize"` in the AS metadata
> — that exact path is what every spec-compliant client will request, so your override has to
> live there, not at some other path. `mountOAuthRoutes` also registers its own
> `GET /authorize` (which 400s with "No identity provider configured" when `identity` is
> omitted). Hono dispatches to the **first** matching handler registered for a given method +
> path, so register yours first to shadow the kit's. (Its `POST /authorize` is still registered
> after yours but is simply never hit, since your flow never submits to it — harmless, unused.)

```ts
import { Hono, type Context } from "hono";
import { z } from "zod";
import {
  createOAuthProvider,
  createRateLimiter,
  createMemoryStorage,
  defineTool,
  handleMcpRequest,
  mountDiscovery,
  mountOAuthRoutes,
  OAuthError,
} from "mcp-oauth-kit";

const baseUrl = "https://mcp.example.com";
const storage = createMemoryStorage(); // swap for production storage
const scopes = [{ name: "account:read", default: true }];
const tools = [
  defineTool({
    name: "whoami",
    description: "Return the caller's user id.",
    inputSchema: z.object({}),
    handler: async (_input, ctx) => `You are ${ctx.userId}`,
  }),
];

// Stand-in for your existing SSO/SAML/OIDC session check — return the user's stable id.
const authenticateUser = async (_c: Context): Promise<string> => "user-123";

const provider = createOAuthProvider({ storage, scopes, baseUrl });
const rateLimiter = createRateLimiter({ storage }); // optional `config: RateLimitConfig`
export const app = new Hono();

mountDiscovery(app, { baseUrl, scopes });

// Register YOUR /authorize BEFORE mountOAuthRoutes — Hono dispatches to the first handler
// registered for a given method + path, so this shadows the kit's bundled GET /authorize.
app.get("/authorize", async (c) => {
  const q = (name: string) => c.req.query(name) ?? "";
  if (
    q("response_type") !== "code" ||
    !q("code_challenge") ||
    q("code_challenge_method") !== "S256"
  ) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const userId = await authenticateUser(c);
  try {
    // Throws OAuthError on an unknown client_id, unregistered redirect_uri, or wrong resource.
    const { code } = await provider.issueAuthCode({
      clientId: q("client_id"),
      redirectUri: q("redirect_uri"),
      codeChallenge: q("code_challenge"),
      scope: provider.normalizeScopes(q("scope").split(" ")),
      userId,
      resource: q("resource"),
    });
    const location = new URL(q("redirect_uri")); // validated by issueAuthCode
    location.searchParams.set("code", code);
    if (q("state")) location.searchParams.set("state", q("state"));
    // RFC 9207: discovery advertises authorization_response_iss_parameter_supported, so a
    // compliant client rejects a redirect without `iss`.
    location.searchParams.set("iss", baseUrl);
    return c.redirect(location.toString(), 302);
  } catch (e) {
    // Never redirect to an unvalidated redirect_uri — answer the error directly.
    if (e instanceof OAuthError)
      return c.json({ error: e.code, error_description: e.message }, 400);
    throw e;
  }
});

// No `identity`: the kit's GET /authorize is shadowed above (its POST /authorize is never hit).
// /register, /token and /revoke work as usual, rate-limited per IP by `rateLimiter` — pass
// `ipExtractor` too when you're not behind Cloudflare.
mountOAuthRoutes(app, { provider, baseUrl, rateLimiter, scopes });

// The MCP transport, with the same deps createMcpServer passes it.
app.post("/mcp", (c) =>
  handleMcpRequest(c.req.raw, {
    provider,
    rateLimiter,
    storage,
    tools,
    baseUrl,
    serverName: "my-server",
    serverVersion: "1.0.0",
    env: c.env, // becomes ctx.env
    hooks: {},
    defaultScopes: scopes.filter((s) => s.default).map((s) => s.name),
    allowedOrigins: [], // browser Origins allowed to call /mcp
    // waitUntil: on Workers, (p) => c.executionCtx.waitUntil(p)
  }),
);
```

Serve `app` exactly as in §3. `createMcpServer` additionally answers `GET`/`DELETE /mcp` with
`405`; add those routes if you want the same behavior.

## 5. Scopes and scope gating

Declare the scopes your server understands. Mark the ones granted when a client requests none
as `default: true`.

```ts
scopes: [
  { name: "account:read", default: true },
  { name: "write", description: "Make changes on the user's behalf" },
],
```

Attach `scope` to a tool to gate it. The tool is always listed in `tools/list` regardless
of the caller's granted scopes — a client can discover it exists and ask for the scope via
step-up authorization. A `tools/call` from a caller whose token lacks the scope is answered
with HTTP `403` and a `WWW-Authenticate: Bearer error="insufficient_scope", scope="write", ...`
challenge before the handler runs — a compliant client uses it to request the scope:

```ts
{
  name: "delete_thing",
  description: "Delete a thing.",
  scope: "write",          // always listed; blocked unless the token has "write"
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
defineTool({
  name: "book_slot",
  description: "Book an appointment slot.",
  scope: "write",
  inputSchema: z.object({ slot: z.string() }),
  mutating: {
    // Phase 1 — validate + describe. NO side effect here. `slot` is typed from inputSchema.
    // `summary` is shown before confirming and passed to onMutation after — keep it
    // tense-neutral ("Book 09:00", not "Booked 09:00").
    preview: async ({ slot }) => ({ summary: `Book ${slot}`, data: { slot } }),
    // Phase 2 — runs only after confirm_request with the token from phase 1, up to 5 minutes
    // later. `data` is typed from preview's return value but arrives JSON round-tripped (no
    // Date/Map/BigInt) — and re-check anything preview checked (is the slot still free?).
    execute: async ({ slot }, ctx) => {
      // Replace with your real persistence — this illustrates where the side effect goes.
      console.log(`booking ${slot} for ${ctx.userId}`);
      return `Booked ${slot}.`;
    },
  },
});
```

The confirmation token is bound to the user who previewed it, expires after 5 minutes, and is
single-use. Results are cached under the idempotency key for 10 minutes so a retried confirm
replays rather than re-executes. (Exactly-once is best-effort on a store without
compare-and-swap — see the README for the precise guarantee.)

### The exact preview → confirm wire shapes

The preview call's result carries both `content[0].text` (JSON-encoded, for clients that
only read `content`) and `structuredContent` (for clients that read it directly):

```json
{
  "status": "preview",
  "summary": "Book 09:00",
  "confirmationToken": "<opaque single-use token>"
}
```

Call `confirm_request` with that token:

```json
{
  "confirmationToken": "<token from the preview>",
  "idempotencyKey": "<your own unique string per logical operation — e.g. a UUID you generate once per attempt, reused only on retry of the SAME attempt>"
}
```

What `confirm_request` returns:

- **Success** — whatever `execute` returned, shaped like a handler result (a string becomes one
  text block, other values become JSON text; a value that can't be serialized becomes
  `{"success":true}` since the side effect already happened).
- **Replay** (same `idempotencyKey` and same `confirmationToken`, within 10 minutes) — the
  identical cached result; `execute` does not run again and `onMutation` doesn't fire.
- **Refusal** — `isError: true` with text `{"success":false,"error":"..."}`: the token expired
  or was already used, the request is still being processed (retry shortly), or the
  `idempotencyKey` was already used for a different confirmation (use a new key).
- **Thrown error in `execute`** — `isError: true` with the `ToolError` message, or a generic
  "Tool execution failed" for anything else.

`confirm_request` is registered only when the caller is granted at least one mutating tool's
scope; the mutating tools themselves are always listed regardless of grant (for step-up
discovery, §5). A caller with no mutating tool granted can never get a preview token, so
`confirm_request` would have nothing to confirm and doesn't appear in their `tools/list`.

## 7. Drive the full OAuth + MCP flow (end to end)

This is what a spec-compliant MCP client does under the hood. You can reproduce it with `curl`
to verify your server. It uses PKCE (S256), and assumes the §2 server with §5's `scopes`
and §6's `book_slot` tool added.

> **MCP request shape (2026-07-28).** `POST /mcp` speaks the 2026-07-28 revision: every
> request carries the `MCP-Protocol-Version`, `Mcp-Method` (and for `tools/call`, `Mcp-Name`)
> headers matching the body, plus a `_meta` envelope in `params`. Send
> `accept: application/json, text/event-stream`. A client that instead opens with a 2025-era
> `initialize` still works via the SDK's stateless fallback (answered as a one-event SSE stream).
> `Mcp-Name` is only needed for `tools/call` — a `tools/list` request sends just
> `Mcp-Method: tools/list`.

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
#     `scope` asks for the non-default "write" scope (§5) so book_slot can run below.
CODE=$(curl -s -i -X POST $BASE/authorize \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$BASE/mcp" \
  --data-urlencode "scope=account:read write" \
  --data-urlencode "email=you@example.com" \
  | grep -i '^location:' | sed -E 's/.*[?&]code=([^&[:space:]]+).*/\1/')
echo "$CODE"   # empty = login rejected (verify returned null or a form field is missing)

# (d) Exchange the code for tokens
ACCESS=$(curl -s -X POST $BASE/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$BASE/mcp" | jq -r .access_token)

# (e) Call a tool over MCP (2026-07-28 request: headers + _meta envelope)
curl -s -X POST $BASE/mcp \
  -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H 'mcp-protocol-version: 2026-07-28' \
  -H 'mcp-method: tools/call' \
  -H 'mcp-name: whoami' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{},
       "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":{"name":"curl","version":"1"},
                "io.modelcontextprotocol/clientCapabilities":{}}}}' | jq
# → {"result":{"content":[{"type":"text","text":"You are you@example.com"}],"resultType":"complete",
#    "_meta":{"io.modelcontextprotocol/serverInfo":{...}}},"jsonrpc":"2.0","id":1}

# The same _meta envelope for the next two calls:
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
  "io.modelcontextprotocol/clientInfo":{"name":"curl","version":"1"},
  "io.modelcontextprotocol/clientCapabilities":{}}'

# (f) Preview a mutating tool (book_slot from §6) — nothing is booked yet
TOKEN=$(curl -s -X POST $BASE/mcp \
  -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H 'mcp-protocol-version: 2026-07-28' \
  -H 'mcp-method: tools/call' \
  -H 'mcp-name: book_slot' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"book_slot",
       "arguments":{"slot":"09:00"},'"$META"'}}' \
  | jq -r .result.structuredContent.confirmationToken)
# structuredContent is {"status":"preview","summary":"Book 09:00","confirmationToken":"..."}
echo "$TOKEN"

# (g) Confirm it — execute runs now
curl -s -X POST $BASE/mcp \
  -H "authorization: Bearer $ACCESS" \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H 'mcp-protocol-version: 2026-07-28' \
  -H 'mcp-method: tools/call' \
  -H 'mcp-name: confirm_request' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"confirm_request",
       "arguments":{"confirmationToken":"'"$TOKEN"'","idempotencyKey":"'"$(openssl rand -hex 16)"'"},
       '"$META"'}}' | jq
# → {"result":{"content":[{"type":"text","text":"Booked 09:00."}],"resultType":"complete",...}, ...}
```

> **Using §4's email + code identity?** Step (c) must submit every `identity.fields` entry —
> add `--data-urlencode "code=123456"` — or `verify` rejects the login, the response has no
> `location:` header, and `CODE` comes back empty (which then fails every later step).

> **`iss` on the redirect.** Step (c)'s 302 now also carries `&iss=<baseUrl>` (RFC 9207) —
> a compliant client checks this matches the issuer it expects before proceeding, to catch
> an authorization-server mix-up. The `sed` extraction above only pulls `code`, so it's
> unaffected; a real client parses the full redirect URL.

> **Client ID Metadata Documents.** Step (b) shows Dynamic Client Registration. If the
> server has `allowClientIdMetadataDocuments: true`, you can skip registration entirely and
> use an `https://` URL (hosting a `{ client_id, redirect_uris, ... }` JSON document) as
> `CLIENT_ID` directly — see the Config reference in the README.

In a real MCP client (Claude, an IDE plugin, etc.) you just point it at
`http://localhost:3000/mcp` and it performs steps (a)–(d) for you, then makes MCP calls like
(e)–(g).

### Connect with the TypeScript SDK client

`@modelcontextprotocol/client` runs discovery, registration, PKCE, token exchange and
scope step-up itself; you supply an `OAuthClientProvider` that stores state and sends the
user to the login page. A minimal in-memory provider (a real app opens `url` in a browser and
receives the redirect on `redirectUrl`):

```ts
import {
  Client,
  StreamableHTTPClientTransport,
  UnauthorizedError,
  type OAuthClientProvider,
} from "@modelcontextprotocol/client";

const redirectUrl = "http://localhost:9999/cb";
let state: Record<string, any> = {};
let callback: URLSearchParams | undefined;

const authProvider: OAuthClientProvider = {
  redirectUrl,
  clientMetadata: { client_name: "my-client", redirect_uris: [redirectUrl] },
  clientInformation: () => state.client,
  saveClientInformation: (c) => void (state.client = c),
  tokens: () => state.tokens,
  saveTokens: (t) => void (state.tokens = t),
  codeVerifier: () => state.verifier,
  saveCodeVerifier: (v) => void (state.verifier = v),
  discoveryState: () => state.discovery,
  saveDiscoveryState: (d) => void (state.discovery = d),
  redirectToAuthorization: async (url) => {
    // Open `url` for the user; when the browser lands on redirectUrl, keep its query params.
    callback = await openBrowserAndWaitForRedirect(url); // your UI
  },
};

const connect = async () => {
  const transport = new StreamableHTTPClientTransport(new URL("http://localhost:3000/mcp"), {
    authProvider,
  });
  // "auto" negotiates 2026-07-28 via server/discover; omit for the 2025 handshake.
  const client = new Client(
    { name: "my-client", version: "1.0.0" },
    {
      versionNegotiation: { mode: "auto" },
    },
  );
  try {
    await client.connect(transport);
  } catch (e) {
    if (!(e instanceof UnauthorizedError)) throw e;
    await transport.finishAuth(callback!); // redeem the code, then reconnect
    return connect();
  }
  return client;
};

const client = await connect();
console.log(await client.listTools());
```

A `callTool` for a tool whose scope you don't hold throws `UnauthorizedError` after the SDK
has started a step-up authorization for that scope — finish it the same way
(`finishAuth`, reconnect) and retry the call.

Things the minimal provider above glosses over:

- **`state`.** Generate an unguessable `state` per authorization, and check the value on the
  redirect matches before calling `finishAuth` (CSRF protection on your callback).
- **Requesting scopes up front.** The 401 challenge only advertises default scopes. To get a
  non-default scope on the first login, start the flow yourself with
  `auth(authProvider, { serverUrl, scope: "account:read write" })`.
- **Step-up isn't additive.** The new token carries only the scopes requested in that round,
  so request the **union** of every scope you need, not just the missing one.
- **`redirectToAuthorization` can fire mid tool-call**, on a 403 step-up — not only during
  `connect`. Your UI must handle it at any point.
- **Persist discovery state.** If the callback leg runs in a different process from the one
  that started the flow, persist what `saveDiscoveryState` receives and return it from
  `discoveryState()` — otherwise `finishAuth` throws `AuthorizationServerMismatchError`.

## 8. Observe what happens (hooks)

All hooks are optional and fire-and-forget except `onMutation`, which is awaited.

```ts
hooks: {
  onToolCall: async (e) => log.info("tool", e.toolName, "by", e.userId),
  onAudit: async (e) => log.info("oauth", e.event, e.clientId, e.userId), // registered / issued / refreshed / revoked
  onMutation: async (e) => auditLedger.write(e), // awaited — { summary, data, result, idempotencyKey, ... }
  onToolError: async (e) => { if (!e.expected) alert(e.error); }, // expected = a ToolError rejection
}
```

A throwing hook never fails the request. `onMutation` fires only for two-phase (mutating)
tools, and not when a confirm is replayed — log plain tools' side effects in their handler. On
Cloudflare Workers, pass the execution context (`app.fetch(req, env, ctx)`) so the
fire-and-forget hooks are kept alive with `waitUntil` after the response is sent.

## 9. Going to production — checklist

- [ ] **Swap storage.** Replace `createMemoryStorage()` with `createCloudflareKvStorage(kv)`
      or another `KvLike` ([storage-adapters.md](storage-adapters.md)). Memory storage is not
      persistent or shared across instances.
- [ ] **Serve at the origin root** over HTTPS, with `baseUrl` set to that exact public URL.
- [ ] **Set the trusted client-IP source if you're _not_ behind Cloudflare.** Pass
      `ipExtractor` so per-IP rate limits can't be bypassed with a spoofed header (see the
      README's RateLimitConfig section; on bare Node use the socket peer address).
- [ ] **Add per-account lockout in `verify`** if your credential is short or guessable — the
      kit only limits per IP.
- [ ] **List browser origins in `allowedOrigins`** if a browser-based client calls `/mcp`
      (`localhost` and `127.0.0.1` are different origins).
- [ ] **Decide on `allowClientIdMetadataDocuments`.** Off by default. Turning it on lets
      unregistered HTTPS `client_id`s authorize by hosting a metadata document — an
      outbound-fetch surface at authorization time. Leave it off unless you have clients
      that need it.
- [ ] **Tune `rateLimits`** for your traffic (defaults: 50 `/mcp` requests/user/hr, 10
      authorize/IP/hr, 30 token+register+revoke/IP/hr). During local client development raise
      `ipAuthorizePerHour` — every OAuth round trip, including a step-up, costs one attempt.
- [ ] **Pick your deployment adapter** ([deploy.md](deploy.md): Workers, Node, Lambda, Vercel).
- [ ] **Wire `hooks`** to your logging/audit pipeline.
- [ ] Review the security model and documented limitations in [SECURITY.md](../SECURITY.md).

## Where to go next

- [README](../README.md) — full config reference, endpoint table, and OAuth/PKCE details.
- [deploy.md](deploy.md) — runtime-specific entry points.
- [storage-adapters.md](storage-adapters.md) — implementing `KvLike` for Redis/DynamoDB/Postgres.
- [`examples/appointments/`](../examples/appointments/) — a complete working server.
