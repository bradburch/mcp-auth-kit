# Full Review Fixes (spec compliance + onboarding) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every finding from two independent fresh-eyes audits of `main` — one auditing MCP 2026-07-28 spec compliance, one role-playing a developer starting a greenfield project — then cut a new release.

**Architecture:** No new subsystems. Each task is a small, additive change to existing files (`src/oauth/*`, `src/transport.ts`, `src/server.ts`, `src/tools/registry.ts`) or a documentation correction (`README.md`, `docs/*.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `package.json`, `examples/appointments/*`).

**Tech Stack:** TypeScript, Hono, vitest — all already in use, no new dependencies.

## Global Constraints

- Node >=22 (existing `engines` floor), ESM (`"type": "module"`), strict TypeScript (`tsconfig.json`).
- Every new/changed source file follows existing conventions: file-header comment block, `KvLike` for persistence, errors surfaced as `Error` with a message `routes.ts` pattern-matches on, existing RFC-citation-plus-rationale comment style.
- Run `npm run typecheck && npm run lint && npm run format:check && npm test` before every commit (matches CI — `format:check` was missed by the prior plan and caused a late fix wave; do not repeat that).
- Docs must stay internally consistent: a claim in one doc file must not contradict another (this was the single biggest class of finding — cross-check `README.md`, `docs/how-to-use.md`, `docs/deploy.md`, `CONTRIBUTING.md`, `CHANGELOG.md` against each other and against the actual code, not just against themselves).
- **Explicitly out of scope for this plan** (deliberate, not overlooked):
  - Full TypeScript SDK v2 migration — still a separate, larger effort (unchanged from the prior plan's reasoning); this plan only tightens the `^1` peer-dependency pin and adds an explicit README caveat about the transport-version gap.
  - Per-client scope allowlisting, DCR authentication (client secrets), and consent cookies / CSRF tokens on `POST /authorize` — the spec's proxy-scoped MUSTs for these don't bind a first-party AS (see the prior plan's audit for the reasoning); not revisited here.
  - Storage key namespacing by `baseUrl` (multi-tenant KV-sharing hardening) — narrow risk, real fix is a breaking key-format change; documented as a known limitation in `SECURITY.md` instead (Task 4).
  - A generic `Env` type parameter on `createMcpServer`'s returned `Hono` instance — Task 8 fixes the actual runtime bug (env was always `undefined`); adding full generic type plumbing is a separate API-design question, not a bug fix.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/server.ts` | *Modify.* `allowedOrigins` config wiring (Task 1); `env: c.env` instead of hardcoded `undefined` (Task 8); baseUrl HTTPS validation (Task 4). |
| `src/transport.ts` | *Modify.* Origin header validation (Task 1); `Mcp-Method`/`Mcp-Name` header validation (Task 6); `insufficient_scope` 403 support (Task 7). |
| `src/oauth/discovery.ts` | *Modify.* `authorization_response_iss_parameter_supported`, PRM `scopes_supported`, drop non-standard `resource` from AS metadata, mount PRM at the `/mcp` sub-path too (Task 2). |
| `src/identity/page.ts` | *Modify.* Display the redirect URI hostname (+ localhost warning); `frame-ancestors` CSP (Task 3). |
| `src/oauth/routes.ts` | *Modify.* Wire the redirect-URI-hostname display into `authorizePageParams`/CSP (Task 3). |
| `src/oauth/provider.ts` | *Modify.* Defense-in-depth audience re-check in `verifyAccessToken` (Task 4); CIMD cache respects `Cache-Control` (Task 5). |
| `src/oauth/cimd.ts` | *Modify.* Parse and return the response's cache-control max-age (Task 5). |
| `src/tools/registry.ts` | *Modify.* Register all tools regardless of scope; return an `insufficient_scope`-shaped error instead of executing when ungranted (Task 7). |
| `src/config.ts` | *Modify.* `allowedOrigins` on `McpServerConfig` (Task 1); doc comment update on `ToolContext.env` (Task 8). |
| `package.json` | *Modify.* SDK peer pin `>=1` → `^1` (Task 4); repository/homepage/bugs/keywords/author metadata (Task 13); version bump (Task 14). |
| `examples/appointments/server.ts`, `run.ts`, `README.md` | *Modify.* `baseUrl` param defaulting to the test value but overridable; `run.ts` passes the real local URL (Task 9). |
| `docs/deploy.md` | *Modify.* Fix the Cloudflare Workers env-access pattern; add `identity` to all 4 examples; fix the Vercel origin-root violation; fix the in-memory-adapter contradiction (Task 9, 11). |
| `README.md` | *Modify.* Peer-dep list, Node/ESM note, `renderAuthorizePage` arg count, `OAuthProviderConfig` field list, sub-path-mounting contradiction, transport-version caveat, `allowedOrigins` doc (Task 10). |
| `docs/how-to-use.md` | *Modify.* Runnable code samples, two-phase confirm wire contract, mandatory `Accept` header, real custom-identity composition example (Task 12). |
| `CONTRIBUTING.md`, `CHANGELOG.md` | *Modify.* Overclaim wording, repo link (Task 13). |
| `SECURITY.md` | *Modify.* Document the multi-tenant KV-sharing limitation (Task 4). |

---

### Task 1: `Origin` header validation (DNS rebinding protection)

**Files:**
- Modify: `src/config.ts` (add `allowedOrigins` to `McpServerConfig`)
- Modify: `src/transport.ts` (add `allowedOrigins` to `McpRequestDeps`, validate `Origin`)
- Modify: `src/server.ts` (thread `config.allowedOrigins` through)
- Test: `test/transport.test.ts`

**Interfaces:**
- Produces: `McpServerConfig.allowedOrigins?: string[]`, `McpRequestDeps.allowedOrigins: string[]`.

**Design decision (read before implementing):** the streamable-http spec's `Origin` MUST is scoped to the MCP transport endpoint (`POST /mcp`), which is where a malicious webpage could otherwise drive a DNS-rebinding attack against a locally-running server. It does not apply to the OAuth routes (`/authorize`, `/token`, `/register`, `/revoke`), which have their own CSRF-adjacent protections (exact redirect-URI matching, PKCE, single-use codes) and are not the spec's target here. Default behavior: **non-browser clients (no `Origin` header) are always allowed** — most MCP clients (Claude desktop, IDE plugins, server-to-server) never send `Origin`. **If `Origin` is present and `allowedOrigins` is not configured, reject with 403** — secure-by-default, since an unconfigured server has no way to know which origins are legitimate. If `Origin` is present and configured, allow only exact matches.

- [ ] **Step 1: Write the failing tests**

Add to `test/transport.test.ts`:

```typescript
describe("POST /mcp — Origin validation", () => {
  it("rejects a request with an Origin header when allowedOrigins is not configured", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example.com" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(403);
  });

  it("allows a request with no Origin header regardless of configuration", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    // No Origin header — falls through to the normal 401 (missing auth), not 403.
    expect(res.status).toBe(401);
  });

  it("allows a request whose Origin is in the configured allowlist", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
      allowedOrigins: ["https://claude.ai"],
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://claude.ai" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401); // past the Origin check, falls through to normal auth
  });

  it("rejects an Origin not in the configured allowlist", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
      allowedOrigins: ["https://claude.ai"],
    });
    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example.com" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(403);
  });
});
```

(This extends the existing `test/transport.test.ts` created in the prior plan — reuse its `baseUrl` constant and imports; don't redeclare them.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/transport.test.ts`
Expected: FAIL — no Origin check exists yet, all four new assertions fail (no 403 ever returned; the "allowed" cases may already pass by coincidence, but write and run all four together).

- [ ] **Step 3: Write the implementation**

In `src/config.ts`, add to `McpServerConfig` (near `ipExtractor`):

```typescript
  /**
   * Origins allowed to send `POST /mcp` requests carrying a browser `Origin` header
   * (DNS-rebinding protection, MCP 2026-07-28 streamable-http spec). Requests with NO
   * Origin header (the common case — most MCP clients aren't browsers) are always
   * allowed. A request WITH an Origin header is rejected with 403 unless it exactly
   * matches an entry here — including when this option is omitted entirely, since an
   * unconfigured server has no way to know which origins are legitimate.
   */
  allowedOrigins?: string[];
```

In `src/transport.ts`, add to `McpRequestDeps` (near `defaultScopes`):

```typescript
  /** Exact-match allowlist for the `Origin` header — see `McpServerConfig.allowedOrigins`. */
  allowedOrigins: string[];
```

At the very top of `handleMcpRequest`, before reading the body:

```typescript
export async function handleMcpRequest(req: Request, deps: McpRequestDeps): Promise<Response> {
  // MCP 2026-07-28 streamable-http spec: validate Origin to prevent DNS-rebinding attacks
  // from a malicious webpage against a locally-running server. No Origin header means a
  // non-browser client (the common case) — always allowed. An Origin header present but
  // not in the configured allowlist (default: nothing allowed) is rejected outright.
  const origin = req.headers.get("Origin");
  if (origin !== null && !deps.allowedOrigins.includes(origin)) {
    return Response.json(jsonRpcError(JSON_RPC_ERROR.ORIGIN_NOT_ALLOWED, "Origin not allowed"), {
      status: 403,
    });
  }

  // Read the body up front (before anything else could consume the stream), with the
  ...
```

Add the new error code to the `JSON_RPC_ERROR` const (implementation-defined range, next unused slot):

```typescript
export const JSON_RPC_ERROR = {
  METHOD_NOT_ALLOWED: -32000,
  AUTH_REQUIRED: -32001,
  RATE_LIMITED: -32002,
  ORIGIN_NOT_ALLOWED: -32003,
  INTERNAL: -32603,
} as const;
```

In `src/server.ts`, thread it through the `/mcp` handler:

```typescript
  app.post("/mcp", (c) =>
    handleMcpRequest(c.req.raw, {
      provider,
      rateLimiter,
      storage: config.storage,
      tools: config.tools,
      baseUrl: config.baseUrl,
      serverName: DEFAULT_SERVER_NAME,
      serverVersion: DEFAULT_SERVER_VERSION,
      env: c.env,
      hooks,
      defaultScopes: config.scopes.filter((s) => s.default).map((s) => s.name),
      allowedOrigins: config.allowedOrigins ?? [],
    }),
  );
```

(The `env: c.env` here is Task 8's fix — apply it in this same edit since you're touching this exact call site anyway; it avoids a second pass over the same six lines. Task 8's own step will confirm/test it.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/transport.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/transport.ts src/server.ts test/transport.test.ts
git commit -m "feat(transport): validate Origin header to prevent DNS rebinding (MCP 2026-07-28)"
```

---

### Task 2: Discovery metadata fixes bundle

**Files:**
- Modify: `src/oauth/discovery.ts`
- Test: `test/oauth/routes.test.ts`

**Interfaces:** None new — response-body changes only.

Four independent, small fixes to the same file, reviewed together:

1. Add `authorization_response_iss_parameter_supported: true` to AS metadata — RFC 9207 requires advertising this since we unconditionally emit `iss` on the redirect (`routes.ts`). Without it, a spec-compliant client's own decision table treats "flag absent" as "proceed without validating `iss`," which silently neuters the mix-up defense.
2. Add `scopes_supported` to the Protected Resource Metadata (PRM) response — the spec's client-side scope-selection fallback reads `scopes_supported` from the **PRM** document specifically, not the AS metadata (which already has it). Without it, a client following the documented fallback can never discover non-default scopes.
3. Remove the non-standard `resource` field from AS metadata — RFC 8414 defines no such member; it belongs only in the PRM document (where it already correctly appears).
4. Mount the PRM handler at `/.well-known/oauth-protected-resource/mcp` in addition to the existing root path — RFC 9728 ties the `resource` value to the URI the document is served at; the spec's own client discovery diagram probes the sub-path form first. Both paths serve the identical document so either probe order succeeds.

- [ ] **Step 1: Write the failing tests**

Add to `test/oauth/routes.test.ts`:

```typescript
describe("discovery metadata — 2026-07-28 fixes", () => {
  it("advertises authorization_response_iss_parameter_supported", async () => {
    const res = await appUnderTest().request("/.well-known/oauth-authorization-server");
    const body = await res.json();
    expect(body.authorization_response_iss_parameter_supported).toBe(true);
  });

  it("does not include a non-standard resource field in AS metadata", async () => {
    const res = await appUnderTest().request("/.well-known/oauth-authorization-server");
    const body = await res.json();
    expect(body.resource).toBeUndefined();
  });

  it("includes scopes_supported in Protected Resource Metadata", async () => {
    const res = await appUnderTest().request("/.well-known/oauth-protected-resource");
    const body = await res.json();
    expect(body.scopes_supported).toEqual(["account:read"]);
  });

  it("serves identical Protected Resource Metadata at the /mcp sub-path", async () => {
    const root = await (
      await appUnderTest().request("/.well-known/oauth-protected-resource")
    ).json();
    const subPath = await (
      await appUnderTest().request("/.well-known/oauth-protected-resource/mcp")
    ).json();
    expect(subPath).toEqual(root);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/routes.test.ts -t "discovery metadata"`
Expected: FAIL — none of the four fields/routes exist yet.

- [ ] **Step 3: Write the implementation**

Replace the body of `src/oauth/discovery.ts`'s `mountDiscovery`:

```typescript
export function mountDiscovery(
  app: Hono,
  { baseUrl, scopes, clientIdMetadataDocumentsSupported = false }: DiscoveryDeps,
): void {
  const scopeNames = scopes.map((s) => s.name);

  // RFC 8414 — Authorization Server Metadata
  app.get("/.well-known/oauth-authorization-server", (c) => {
    return c.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      revocation_endpoint: `${baseUrl}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: scopeNames,
      // RFC 9207 §2.3: MUST advertise this since we unconditionally emit `iss` on the
      // authorization redirect (see routes.ts) — otherwise a compliant client's own
      // decision table treats "flag absent" as "proceed without validating iss."
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: clientIdMetadataDocumentsSupported,
    });
  });

  // RFC 9728 — Protected Resource Metadata. Served at both the root well-known path and
  // the /mcp sub-path: RFC 9728 ties `resource` to the URI the document is served at, and
  // the MCP spec's client discovery flow probes the sub-path form first.
  const protectedResourceMetadata = (c: Context) =>
    c.json({
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: scopeNames,
    });
  app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);
  app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadata);
}
```

Add `import type { Context, Hono } from "hono";` (currently only `Hono` is imported — add `Context` alongside it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/routes.test.ts && npm run typecheck`
Expected: PASS (including all pre-existing discovery tests — `client_id_metadata_document_supported` behavior is unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/oauth/discovery.ts test/oauth/routes.test.ts
git commit -m "fix(oauth): discovery metadata gaps (iss flag, PRM scopes_supported, sub-path mount)"
```

---

### Task 3: Authorize page shows redirect URI + `frame-ancestors` CSP

**Files:**
- Modify: `src/identity/page.ts`
- Modify: `src/oauth/routes.ts` (CSP constant only)
- Test: `test/oauth/routes.test.ts`

**Interfaces:** No signature changes — `renderAuthorizePage(identity, params)` already receives `params.redirect_uri`; this task only changes what's rendered from data already flowing through.

**Design decision:** the spec's security-considerations page requires the AS to "clearly display the redirect URI hostname during authorization" and "display additional warnings for localhost-only redirect URIs" — this defends against a client impersonating a legitimate one by supplying its own `client_id`/`redirect_uri` with a copied `client_name`/branding. Surfacing `client_name` itself (DCR- or CIMD-supplied) is a larger follow-up (`OAuthProvider.validateClientRedirect` deliberately returns only a boolean to prevent a credential-validity oracle — see its doc comment — so exposing a display name requires a second, non-oracle-risking lookup path, which is not part of this task; note it in the CHANGELOG as a known follow-up rather than silently dropping it).

- [ ] **Step 1: Write the failing tests**

Add to `test/oauth/routes.test.ts`:

```typescript
describe("GET /authorize — redirect URI display", () => {
  it("shows the redirect URI hostname on the login page", async () => {
    const app = new Hono();
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });
    mountOAuthRoutes(app, {
      provider,
      baseUrl,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
    });
    const { client_id } = await (
      await app.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://app.example.com/cb"] }),
      })
    ).json();

    const res = await app.request(
      `/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent("https://app.example.com/cb")}&code_challenge=x&code_challenge_method=S256`,
    );
    const html = await res.text();
    expect(html).toContain("app.example.com");
  });

  it("warns when the redirect URI is localhost", async () => {
    const app = new Hono();
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });
    mountOAuthRoutes(app, {
      provider,
      baseUrl,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
    });
    const { client_id } = await (
      await app.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://localhost:9999/cb"] }),
      })
    ).json();

    const res = await app.request(
      `/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent("http://localhost:9999/cb")}&code_challenge=x&code_challenge_method=S256`,
    );
    const html = await res.text();
    expect(html.toLowerCase()).toContain("localhost");
    expect(html.toLowerCase()).toMatch(/warn|caution|note/);
  });

  it("sets frame-ancestors none on the authorize CSP", async () => {
    const res = await appUnderTest().request("/authorize");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/routes.test.ts -t "redirect URI display"`
Expected: FAIL — the hostname isn't rendered anywhere yet, and the CSP has no `frame-ancestors`.

- [ ] **Step 3: Write the implementation**

In `src/identity/page.ts`, add a helper and use it in the template. After `safeAccent`:

```typescript
/**
 * Extract the redirect URI's hostname for display, and whether it's a localhost target
 * (security-considerations: "MUST clearly display the redirect URI hostname" and "SHOULD
 * display additional warnings for localhost-only redirect URIs").
 */
function redirectUriDisplay(redirectUri: string): { hostname: string; isLocalhost: boolean } {
  try {
    const url = new URL(redirectUri);
    const isLocalhost = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    return { hostname: url.hostname, isLocalhost };
  } catch {
    return { hostname: "(invalid redirect URI)", isLocalhost: false };
  }
}
```

In `renderAuthorizePage`, after the `errorHtml` line:

```typescript
  const errorHtml = params.error ? `<div class="error">${escapeHtml(params.error)}</div>` : "";

  const { hostname: redirectHostname, isLocalhost } = redirectUriDisplay(params.redirect_uri);
  const redirectNoticeHtml = isLocalhost
    ? `<div class="redirect-notice warn">⚠ Signing in to a request from <strong>${escapeHtml(redirectHostname)}</strong> (localhost) — only continue if you started this yourself.</div>`
    : `<div class="redirect-notice">Signing in to: <strong>${escapeHtml(redirectHostname)}</strong></div>`;
```

Add it to the rendered body, right after `${errorHtml}`:

```typescript
    ${errorHtml}
    ${redirectNoticeHtml}
    <form method="POST" action="/authorize">
```

Add matching CSS to the `<style>` block, alongside `.error`:

```css
    .redirect-notice { font-size: 0.85rem; color: #555; margin-bottom: 1rem; }
    .redirect-notice.warn { background: #fffbeb; color: #92400e; padding: 0.75rem; border-radius: 8px; }
```

In `src/oauth/routes.ts`, update `AUTHORIZE_CSP`:

```typescript
const AUTHORIZE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; img-src https:; frame-ancestors 'none'";
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/routes.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/identity/page.ts src/oauth/routes.ts test/oauth/routes.test.ts
git commit -m "fix(oauth): display redirect URI + localhost warning on login page, add frame-ancestors CSP"
```

---

### Task 4: Security hardening bundle (baseUrl HTTPS check, audience re-check, SDK peer pin)

**Files:**
- Modify: `src/server.ts` (baseUrl validation)
- Modify: `src/oauth/provider.ts` (audience re-check)
- Modify: `package.json` (peer dep pin)
- Modify: `SECURITY.md` (document the KV-sharing limitation)
- Test: `test/server.read-tools.test.ts` or a new focused test file, `test/oauth/provider.test.ts`

**Interfaces:** None new. `createMcpServer` throws synchronously on an invalid `baseUrl` instead of silently accepting it.

Three independent, small fixes:

1. **`baseUrl` HTTPS validation.** Security-considerations: "All authorization server endpoints MUST be served over HTTPS." Currently unvalidated — an `http://` `baseUrl` (other than localhost, for dev) silently produces a non-compliant discovery document. Fail fast at `createMcpServer` construction time.
2. **Defense-in-depth audience re-check.** `verifyAccessToken` reads `tokenData.resource` but never compares it to the server's own expected resource — harmless today (tokens are opaque randoms resolved only against this server's own KV keyspace) but fragile if two kit-built servers ever share one KV namespace. One-line check closes it regardless.
3. **SDK peer dependency pin.** `package.json`'s `"@modelcontextprotocol/sdk": ">=1"` peer range permits `2.x`, which is a *different package* (`@modelcontextprotocol/server`) that this kit does not support — the range advertises compatibility that can't exist. Pin to `^1`, matching the devDependency.

- [ ] **Step 1: Write the failing tests**

Add to `test/server.read-tools.test.ts` (or create `test/server.baseurl.test.ts` if that file's existing `describe` structure doesn't fit — your call, keep it in whichever existing file most naturally covers `createMcpServer`'s construction-time behavior):

```typescript
describe("createMcpServer — baseUrl validation", () => {
  it("throws when baseUrl is not https and not localhost", () => {
    expect(() =>
      createMcpServer({
        baseUrl: "http://example.com",
        storage: createMemoryStorage(),
        scopes: [{ name: "account:read", default: true }],
        tools: [],
      }),
    ).toThrow(/https/i);
  });

  it("allows http for localhost (dev)", () => {
    expect(() =>
      createMcpServer({
        baseUrl: "http://localhost:3000",
        storage: createMemoryStorage(),
        scopes: [{ name: "account:read", default: true }],
        tools: [],
      }),
    ).not.toThrow();
  });

  it("allows http for 127.0.0.1 (dev)", () => {
    expect(() =>
      createMcpServer({
        baseUrl: "http://127.0.0.1:3000",
        storage: createMemoryStorage(),
        scopes: [{ name: "account:read", default: true }],
        tools: [],
      }),
    ).not.toThrow();
  });

  it("allows https always", () => {
    expect(() =>
      createMcpServer({
        baseUrl: "https://mcp.example.com",
        storage: createMemoryStorage(),
        scopes: [{ name: "account:read", default: true }],
        tools: [],
      }),
    ).not.toThrow();
  });
});
```

Add to `test/oauth/provider.test.ts`:

```typescript
describe("verifyAccessToken — audience re-check", () => {
  it("rejects a token record whose resource doesn't match this server's expected resource", async () => {
    const storage = createMemoryStorage();
    const provider = createOAuthProvider({ storage, scopes, baseUrl });
    // Simulate a token that was somehow stored with a foreign resource (defense in depth —
    // this shouldn't happen via the normal issue/exchange path, which is exactly why it's
    // worth a redundant check here rather than relying solely on that path being correct).
    const token = "test-foreign-token";
    const tokenHash = await sha256Hex(token);
    await storage.put(
      `mcp:token:${tokenHash}`,
      JSON.stringify({
        userId: "u1",
        clientId: "c1",
        resource: "https://other-server.example.test/mcp",
        scope: ["account:read"],
        createdAt: Date.now(),
      }),
    );
    expect(await provider.verifyAccessToken(token)).toBeNull();
  });
});
```

(This test needs `sha256Hex` imported from `../../src/crypto.js` — add that import to `test/oauth/provider.test.ts` if not already present. Hardcoding the `mcp:token:` prefix matches `src/storage/keys.ts`'s `accessTokenKey` — if that changes, this test breaks loudly, which is fine for a defense-in-depth check like this.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/server.read-tools.test.ts test/oauth/provider.test.ts -t "baseUrl validation|audience re-check"`
Expected: FAIL — no validation exists, and the foreign-resource token currently resolves successfully.

- [ ] **Step 3: Write the implementation**

In `src/server.ts`, add a validator and call it first thing inside `createMcpServer`:

```typescript
/** Security-considerations: "All authorization server endpoints MUST be served over HTTPS." */
function assertHttpsBaseUrl(baseUrl: string): void {
  const url = new URL(baseUrl);
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !isLocal) {
    throw new Error(
      `baseUrl must be https:// (got "${baseUrl}") — http is only allowed for localhost/127.0.0.1 during local development.`,
    );
  }
}

export function createMcpServer(config: McpServerConfig): Hono {
  assertHttpsBaseUrl(config.baseUrl);

  const app = new Hono();
  ...
```

In `src/oauth/provider.ts`, in `verifyAccessToken`:

```typescript
    async verifyAccessToken(token) {
      const tokenHash = await sha256Hex(token);
      const raw = await storage.get(accessTokenKey(tokenHash));
      if (!raw) {
        return null;
      }
      const tokenData = JSON.parse(raw) as TokenData;
      // Defense-in-depth expiry — never honour a token past its TTL even if KV did.
      if (isExpired(tokenData.createdAt, TTL.ACCESS_TOKEN)) {
        return null;
      }
      // Defense-in-depth audience check (RFC 8707 §2) — redundant with issue-time binding
      // under normal operation, but guards against a KV namespace ever being shared across
      // two servers built with this kit.
      if (tokenData.resource && tokenData.resource !== expectedResource) {
        return null;
      }
      return { userId: tokenData.userId, scopes: tokenData.scope };
    },
```

In `package.json`, change the peer dependency:

```json
  "peerDependencies": {
    "@modelcontextprotocol/sdk": "^1",
    "hono": ">=4",
    "zod": "^3.25 || ^4"
  },
```

In `SECURITY.md`, add a line to the known-limitations section (find the existing limitations list — likely near "Scope and Known Limitations" per the README's cross-reference — and add):

```markdown
- **Storage keys are not namespaced by `baseUrl`.** If two servers built with this kit
  share one KV namespace, a token/client/code issued by one is resolvable by the other
  (all keys are `mcp:<kind>:<hash>`, with no per-deployment prefix). Use a separate KV
  namespace/database per deployment, or don't share storage across distinct `baseUrl`s.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/server.read-tools.test.ts test/oauth/provider.test.ts && npm test && npm run typecheck`
Expected: PASS — including the FULL suite, since `assertHttpsBaseUrl` runs on every `createMcpServer` call and could break any existing test that uses a non-https, non-localhost `baseUrl` (check `test/helpers.ts` and every test file's `baseUrl` constant before this step; the established convention across the test suite is `https://example.test`, which is already `https:`, so this should be a non-issue — but verify, don't assume).

- [ ] **Step 5: Commit**

```bash
git add src/server.ts src/oauth/provider.ts package.json SECURITY.md test/server.read-tools.test.ts test/oauth/provider.test.ts
git commit -m "fix(security): baseUrl HTTPS validation, token audience re-check, pin SDK peer to ^1"
```

---

### Task 5: CIMD cache respects `Cache-Control`

**Files:**
- Modify: `src/oauth/cimd.ts` (parse and return cache lifetime)
- Modify: `src/oauth/provider.ts` (use it instead of the fixed TTL)
- Test: `test/oauth/cimd.test.ts`, `test/oauth/provider.test.ts`

**Interfaces:**
- `ClientIdMetadata` gains `maxAgeSeconds?: number`.
- `resolveClientRedirectUris` uses it to set the cache TTL, clamped to a sane range so a document can't force an unbounded cache lifetime or force a cache-defeating `max-age=0` that reopens the repeated-outbound-fetch concern the fixed TTL existed to bound.

- [ ] **Step 1: Write the failing tests**

Add to `test/oauth/cimd.test.ts`:

```typescript
describe("fetchClientIdMetadata — Cache-Control", () => {
  it("returns the response's max-age when present", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ client_id: clientId, redirect_uris: ["https://app.example.com/cb"] }),
            { status: 200, headers: { "cache-control": "max-age=120" } },
          ),
      ),
    );
    const result = await fetchClientIdMetadata(clientId);
    expect(result?.maxAgeSeconds).toBe(120);
  });

  it("clamps an excessive max-age to the upper bound", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ client_id: clientId, redirect_uris: ["https://app.example.com/cb"] }),
            { status: 200, headers: { "cache-control": "max-age=999999999" } },
          ),
      ),
    );
    const result = await fetchClientIdMetadata(clientId);
    expect(result?.maxAgeSeconds).toBeLessThanOrEqual(24 * 60 * 60);
  });

  it("clamps a tiny/zero max-age to the lower bound", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ client_id: clientId, redirect_uris: ["https://app.example.com/cb"] }),
            { status: 200, headers: { "cache-control": "max-age=0" } },
          ),
      ),
    );
    const result = await fetchClientIdMetadata(clientId);
    expect(result?.maxAgeSeconds).toBeGreaterThanOrEqual(60);
  });

  it("defaults to undefined (caller uses its own default) when no Cache-Control is sent", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ client_id: clientId, redirect_uris: ["https://app.example.com/cb"] }),
            { status: 200 },
          ),
      ),
    );
    const result = await fetchClientIdMetadata(clientId);
    expect(result?.maxAgeSeconds).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/cimd.test.ts -t "Cache-Control"`
Expected: FAIL — `maxAgeSeconds` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

In `src/oauth/cimd.ts`, add bounds constants near the top:

```typescript
/** Bounds for a CIMD document's own Cache-Control max-age, so a document can't force an
 *  unbounded cache lifetime (stale redirect_uris survive too long) or an effectively-zero
 *  one (reopening the repeated-outbound-fetch/SSRF-adjacent concern the cache exists to bound). */
const MIN_CACHE_SECONDS = 60;
const MAX_CACHE_SECONDS = 24 * 60 * 60;
```

Extend `ClientIdMetadata`:

```typescript
export interface ClientIdMetadata {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  /** Clamped `max-age` from the response's Cache-Control header, if present. */
  maxAgeSeconds?: number;
}
```

Add a small parser near `readCappedText`:

```typescript
/** Parse and clamp `max-age` from a Cache-Control header, if present and well-formed. */
function parseMaxAge(cacheControl: string | null): number | undefined {
  if (!cacheControl) return undefined;
  const match = /max-age=(\d+)/i.exec(cacheControl);
  if (!match) return undefined;
  const raw = Number.parseInt(match[1], 10);
  return Math.min(Math.max(raw, MIN_CACHE_SECONDS), MAX_CACHE_SECONDS);
}
```

In `fetchClientIdMetadata`, capture the header before returning and include it in the result:

```typescript
    if (!res.ok) return null;

    const maxAgeSeconds = parseMaxAge(res.headers.get("cache-control"));

    const text = await readCappedText(res, MAX_DOCUMENT_BYTES, controller.signal);
    ...
    return {
      clientId: clientIdUrl,
      clientName: typeof d.client_name === "string" ? d.client_name : undefined,
      redirectUris,
      maxAgeSeconds,
    };
```

In `src/oauth/provider.ts`'s `resolveClientRedirectUris`, use it:

```typescript
    const doc = await fetchClientIdMetadata(clientId);
    // "[]" is the cached "fetched but invalid/unreachable" sentinel — JSON.parse("[]") is
    // naturally an empty array, and [].includes(anything) is false, so no special-case
    // branch is needed to read it back.
    await storage.put(cacheKey, doc ? JSON.stringify(doc.redirectUris) : "[]", {
      ttlSeconds: doc?.maxAgeSeconds ?? TTL.CIMD_CACHE,
    });
    return doc?.redirectUris ?? null;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/cimd.test.ts test/oauth/provider.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oauth/cimd.ts src/oauth/provider.ts test/oauth/cimd.test.ts test/oauth/provider.test.ts
git commit -m "feat(oauth): CIMD cache respects Cache-Control max-age (clamped)"
```

---

### Task 6: `Mcp-Method` / `Mcp-Name` header validation

**Files:**
- Modify: `src/transport.ts`
- Test: `test/transport.test.ts`

**Interfaces:** None new — internal validation only.

**Design decision:** the 2026-07-28 spec requires `Mcp-Method` and `Mcp-Name` headers on Streamable HTTP POST requests, and that servers reject a request where the header values don't match the JSON-RPC body — the exact scenario named in the spec is an edge proxy/load-balancer routing or authorizing on the header while the server executes on the body. `Mcp-Method` is the JSON-RPC `method` field; `Mcp-Name` applies specifically to `tools/call` (the tool name from `params.name`) — for any other method, `Mcp-Name` is not expected and should be ignored if present. Validate AFTER parsing the JSON-RPC body (you already read it as `requestBody` — parse it here for validation, then still hand the raw string to the SDK transport unchanged). Malformed/unparseable JSON-RPC bodies should NOT be rejected by this check — let the SDK transport's own JSON-RPC error handling take over for a body it can't parse; only compare when both a header and a matching body field are present and parseable.

- [ ] **Step 1: Write the failing tests**

Add to `test/transport.test.ts`:

```typescript
describe("POST /mcp — Mcp-Method / Mcp-Name header validation", () => {
  it("rejects a request whose Mcp-Method header doesn't match the JSON-RPC method", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-method": "resources/list",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe(-32020);
  });

  it("rejects a tools/call whose Mcp-Name header doesn't match params.name", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [
        {
          name: "list_slots",
          description: "list",
          inputSchema: z.object({}),
          handler: async () => ({ content: [{ type: "text", text: "ok" }] }),
        },
      ],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-method": "tools/call",
        "mcp-name": "book_slot",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "list_slots", arguments: {} },
      }),
    });
    expect(res.status).toBe(400);
  });

  it("allows a matching Mcp-Method/Mcp-Name pair through", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [
        {
          name: "list_slots",
          description: "list",
          inputSchema: z.object({}),
          handler: async () => ({ content: [{ type: "text", text: "ok" }] }),
        },
      ],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-method": "tools/call",
        "mcp-name": "list_slots",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "list_slots", arguments: {} },
      }),
    });
    expect(res.status).toBe(200);
  });

  it("allows a request with no Mcp-Method/Mcp-Name headers at all (older clients)", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      tools: [],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(200);
  });
});
```

(These tests need `getToken` from `../helpers.js` and `z` from `"zod"` — add those imports to `test/transport.test.ts` if not already present.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/transport.test.ts -t "Mcp-Method"`
Expected: FAIL — no header validation exists; the mismatched-header tests currently return 200/401 instead of 400, and the matching/absent-header tests may already pass (run all five together to confirm the mismatch cases are the ones failing).

- [ ] **Step 3: Write the implementation**

In `src/transport.ts`, add the error code:

```typescript
export const JSON_RPC_ERROR = {
  METHOD_NOT_ALLOWED: -32000,
  AUTH_REQUIRED: -32001,
  RATE_LIMITED: -32002,
  ORIGIN_NOT_ALLOWED: -32003,
  HEADER_MISMATCH: -32020, // matches the MCP 2026-07-28 error-code allocation policy
  INTERNAL: -32603,
} as const;
```

Add a validation helper and call it after `requestBody` is available (right after the body-cap check, before the auth check — malformed headers are cheap to reject before doing any auth work):

```typescript
/**
 * MCP 2026-07-28 streamable-http spec: reject a request where `Mcp-Method` (and, for
 * `tools/call`, `Mcp-Name`) don't match the JSON-RPC body — guards against an edge proxy
 * routing/authorizing on the header while the server executes on the body. A request with
 * NO such headers (older clients) is unaffected; only a present-but-mismatched header is
 * rejected. An unparseable body is not rejected here — the SDK transport handles that.
 */
function headerMismatch(req: Request, requestBody: string): boolean {
  const mcpMethod = req.headers.get("Mcp-Method");
  const mcpName = req.headers.get("Mcp-Name");
  if (mcpMethod === null && mcpName === null) return false;

  let parsed: { method?: unknown; params?: { name?: unknown } };
  try {
    parsed = JSON.parse(requestBody);
  } catch {
    return false; // let the SDK's own JSON-RPC parse-error handling take over
  }

  if (mcpMethod !== null && parsed.method !== mcpMethod) return true;
  if (mcpName !== null && parsed.method === "tools/call" && parsed.params?.name !== mcpName) {
    return true;
  }
  return false;
}
```

Call it right after `requestBody` is set:

```typescript
  const capped = await readCappedBody(req);
  if (capped instanceof Response) return capped;
  const requestBody = capped;

  if (headerMismatch(req, requestBody)) {
    return Response.json(
      jsonRpcError(JSON_RPC_ERROR.HEADER_MISMATCH, "Mcp-Method/Mcp-Name header does not match request body"),
      { status: 400 },
    );
  }

  // RFC 9728: tell clients where to discover OAuth endpoints on a 401.
  ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/transport.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/transport.ts test/transport.test.ts
git commit -m "feat(transport): validate Mcp-Method/Mcp-Name headers against the request body"
```

---

### Task 7: `insufficient_scope` 403 step-up flow

**Files:**
- Modify: `src/tools/registry.ts` (register all tools; gate execution, not registration)
- Modify: `src/transport.ts` (surface `WWW-Authenticate: insufficient_scope` on the resulting error — actually surfaced via the tool result itself, see below)
- Test: `test/scope-gating.test.ts`

**Interfaces:** `registerTools`'s behavior changes — this is a deliberate design reversal from the prior plan (confirmed with the repo owner): tools are no longer hidden from `tools/list` based on scope. **Read this whole task before starting — it changes tested, working behavior; don't guess at the intended shape.**

**Design decision:** the spec's runtime insufficient-scope flow is an HTTP-level `403` with a `WWW-Authenticate: Bearer error="insufficient_scope", scope="...", resource_metadata="..."` challenge — but a single `POST /mcp` request can be a JSON-RPC batch or a single `tools/call`, and the *transport* only sees one HTTP response for the whole request. The practical shape that fits this architecture: **register every tool regardless of scope** (so `tools/list` shows the client what exists — this is the part that actually enables discovery, which is the whole point of the spec's step-up flow) **and reject the call at dispatch time with an `isError` tool result whose text names the missing scope**, AND **additionally send the HTTP-level 403 with the `insufficient_scope` `WWW-Authenticate` challenge when the ENTIRE request was a single `tools/call` for an ungranted tool** (the common case — a batch containing a mix of granted/ungranted calls can't cleanly map to one HTTP status, so that case falls back to the JSON-RPC-level `isError` result only, which is still spec-legal — the 403 challenge is a "SHOULD," not interpreted here as applying to every element of a batch).

This means: `handleMcpRequest` needs to peek at the parsed body to detect "is this a single non-batch `tools/call` for an ungranted tool" BEFORE dispatching to the SDK transport, since the SDK transport itself has no concept of scopes. Do this check the same way Task 6 already parses the body once — don't parse it a third time; if Task 6 already exists on this branch when you start, extend its checkpoint rather than adding a separate parse.

- [ ] **Step 1: Write the failing tests**

Add to `test/scope-gating.test.ts` (or extend its existing structure — read the file first, it already tests `registerTools`'s current hide-from-`tools/list` behavior; those specific assertions will need to change since this task changes what they're asserting, per the design decision above — update them in place rather than leaving contradictory tests in the suite):

```typescript
describe("insufficient_scope — 403 step-up flow", () => {
  const scopes = [
    { name: "account:read", default: true },
    { name: "write" },
  ];
  const writeTool = {
    name: "delete_thing",
    description: "delete",
    scope: "write",
    inputSchema: z.object({}),
    handler: async () => ({ content: [{ type: "text" as const, text: "deleted" }] }),
  };

  it("lists a scope-gated tool in tools/list even when the caller lacks the scope", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "u1" },
      tools: [writeTool],
    });
    const token = await getToken(app); // defaults to account:read only
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const body = await res.json();
    expect(body.result.tools.map((t: { name: string }) => t.name)).toContain("delete_thing");
  });

  it("returns HTTP 403 with an insufficient_scope WWW-Authenticate challenge on a single ungranted tools/call", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "u1" },
      tools: [writeTool],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "delete_thing", arguments: {} },
      }),
    });
    expect(res.status).toBe(403);
    const wwwAuth = res.headers.get("WWW-Authenticate")!;
    expect(wwwAuth).toContain('error="insufficient_scope"');
    expect(wwwAuth).toContain('scope="write"');
    expect(wwwAuth).toContain("resource_metadata=");
  });

  it("still executes a granted tool call normally", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "u1" },
      tools: [
        {
          name: "list_slots",
          description: "list",
          inputSchema: z.object({}),
          handler: async () => ({ content: [{ type: "text" as const, text: "ok" }] }),
        },
      ],
    });
    const token = await getToken(app);
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "list_slots", arguments: {} },
      }),
    });
    expect(res.status).toBe(200);
  });
});
```

Now open `test/scope-gating.test.ts` and find every existing assertion of the form "tool X is NOT in the tools/list for a caller without scope Y" (this is the behavior being deliberately reversed) — change those specific assertions to expect the tool IS listed, and if there's a companion assertion that calling it fails, change that to expect the specific 403/insufficient_scope shape from above rather than the old "method not found." Do not delete test coverage — convert it to assert the new behavior.

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/scope-gating.test.ts`
Expected: FAIL — tools are still hidden from `tools/list`, and calls fail with the old "method not found" shape, not a 403.

- [ ] **Step 3: Write the implementation**

In `src/tools/registry.ts`, remove the `isGranted` skip and instead wrap ungranted tool handlers with a rejection:

```typescript
/** Generic client-facing message when a tool handler throws. */
const TOOL_ERROR_MESSAGE = "Tool execution failed. Please try again.";

/** True when a scoped tool is permitted given the caller's granted scopes. */
function isGranted(tool: AnyTool, grantedScopes: string[]): boolean {
  return tool.scope === undefined || grantedScopes.includes(tool.scope);
}

/** Result returned (as an isError tool result, not a thrown exception) when a caller's
 *  token lacks the scope a tool requires. The tool is still listed in tools/list — see
 *  registerTools's file header — so this path is reachable by a caller who saw the tool. */
function insufficientScopeResult(requiredScope: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: `This tool requires the "${requiredScope}" scope, which your current token does not have.`,
      },
    ],
    isError: true,
  };
}
```

Update the main loop — every tool registers now, but an ungranted one's handler short-circuits:

```typescript
export function registerTools(
  server: McpServer,
  tools: AnyTool[],
  ctx: ToolContext,
  grantedScopes: string[],
): void {
  const grantedMutating: MutatingToolDef[] = [];

  for (const tool of tools) {
    const granted = isGranted(tool, grantedScopes);

    if (isMutating(tool)) {
      if (granted) {
        registerMutatingTool(server, tool, ctx);
        grantedMutating.push(tool);
      } else {
        registerUngrantedMutatingTool(server, tool);
      }
      continue;
    }

    const readTool = tool as ToolDef;
    const shape = toShape(tool.inputSchema);

    const cb = async (input: unknown) => {
      if (!granted) {
        // tool.scope is guaranteed defined here — isGranted only returns false when it is.
        return insufficientScopeResult(tool.scope!);
      }
      let result: unknown;
      try {
        result = await readTool.handler(input, ctx);
      } catch {
        void fireToolCall(ctx, tool.name, input);
        return {
          content: [{ type: "text" as const, text: TOOL_ERROR_MESSAGE }],
          isError: true,
        };
      }
      void fireToolCall(ctx, tool.name, input);
      return result as { content: Array<{ type: "text"; text: string }> };
    };

    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: shape, annotations: tool.annotations },
      cb,
    );
  }

  // Register the shared confirm_request tool whenever any mutating tool is GRANTED — an
  // ungranted mutating tool never reaches the preview phase that would create a token for
  // confirm_request to act on, so there's nothing for it to do for a caller with none granted.
  if (grantedMutating.length > 0) {
    registerConfirmTool(server, ctx, grantedMutating);
  }
}

/** Register an ungranted mutating tool with a preview handler that immediately rejects —
 *  it never reaches two-phase.ts's real preview/confirm machinery. */
function registerUngrantedMutatingTool(server: McpServer, tool: MutatingToolDef): void {
  const shape = toShape(tool.inputSchema);
  server.registerTool(
    tool.name,
    { description: tool.description, inputSchema: shape, annotations: tool.annotations },
    async () => insufficientScopeResult(tool.scope!),
  );
}
```

Now, `src/transport.ts` — detect the "single non-batch `tools/call` for an ungranted tool" case and return the HTTP 403 directly, BEFORE dispatching to the SDK transport (since the SDK has no scope concept and would otherwise return 200 with the `isError` body from above — which is still correct MCP-JSON-RPC-wise, but doesn't satisfy the spec's HTTP-level 403 SHOULD for the common single-call case). Add this check after the `ctx`/`auth` are established, reusing Task 6's parsed body if that task landed first on this branch — otherwise parse once here:

```typescript
  // Spec SHOULD: a single (non-batch) tools/call for a tool the caller's scopes don't
  // grant gets the HTTP-level 403 insufficient_scope challenge, in addition to (not
  // instead of) the isError tool result registry.ts already returns — a batch request or
  // any other method falls through to the normal 200 JSON-RPC dispatch, where per-call
  // scope handling in registry.ts still applies.
  let parsedForScopeCheck: { method?: unknown; params?: { name?: unknown } } | null = null;
  try {
    parsedForScopeCheck = JSON.parse(requestBody);
  } catch {
    parsedForScopeCheck = null;
  }
  if (
    parsedForScopeCheck &&
    !Array.isArray(parsedForScopeCheck) &&
    parsedForScopeCheck.method === "tools/call" &&
    typeof parsedForScopeCheck.params?.name === "string"
  ) {
    const calledTool = deps.tools.find((t) => t.name === parsedForScopeCheck!.params!.name);
    if (calledTool?.scope && !auth.scopes.includes(calledTool.scope)) {
      return Response.json(
        jsonRpcError(JSON_RPC_ERROR.INSUFFICIENT_SCOPE, "Insufficient scope"),
        {
          status: 403,
          headers: {
            "WWW-Authenticate": `Bearer error="insufficient_scope", scope="${calledTool.scope}", resource_metadata="${resourceMetadataUrl}"`,
          },
        },
      );
    }
  }
```

Place this block after `ctx` is built (so `auth.scopes` is available) but before the `McpServer`/transport are constructed. Add `INSUFFICIENT_SCOPE: -32021` to `JSON_RPC_ERROR` (next slot after `HEADER_MISMATCH: -32020`, matching the spec's allocation policy).

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/scope-gating.test.ts test/transport.test.ts && npm test && npm run typecheck`
Expected: PASS — run the FULL suite here, not just the two touched files: this task changes `registerTools`'s core dispatch behavior, and `test/two-phase.test.ts`, `test/two-phase-failures.test.ts`, and `test/server.read-tools.test.ts` all exercise tool registration and may have assertions coupled to the old hide-from-list behavior. Fix any that break in the same way you fixed `scope-gating.test.ts` — convert, don't delete.

- [ ] **Step 5: Commit**

```bash
git add src/tools/registry.ts src/transport.ts test/scope-gating.test.ts
# add any other test files touched in Step 4's full-suite fixup
git commit -m "feat(mcp): insufficient_scope 403 step-up flow — list all tools, gate execution"
```

---

### Task 8: Fix `ctx.env` — real bug, currently always `undefined`

**Files:**
- Modify: `src/server.ts` (if not already done as part of Task 1's Step 3 — confirm before duplicating)
- Modify: `src/config.ts` (doc comment)
- Test: `test/server.read-tools.test.ts`

**Interfaces:** `ToolContext.env` now carries Hono's real `c.env` instead of always being `undefined`.

**Note:** Task 1's implementation step already changes the `/mcp` handler's `env: undefined` to `env: c.env` as a drive-by (both tasks touch the exact same six-line call site — doing it twice would just be a wasted second diff on the same lines). **Before starting this task, check whether Task 1 already landed and whether that line is already `env: c.env`.** If so, this task is just: write the test proving it, fix the doc comment, and confirm. If Task 1 hasn't run yet or this task runs first, make the change yourself here.

- [ ] **Step 1: Write the failing test**

Add to `test/server.read-tools.test.ts`:

```typescript
describe("ToolContext.env", () => {
  it("passes the Hono request's c.env through to tool handlers, not always undefined", async () => {
    let capturedEnv: unknown;
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "u1" },
      tools: [
        {
          name: "check_env",
          description: "capture ctx.env",
          inputSchema: z.object({}),
          handler: async (_input, ctx) => {
            capturedEnv = ctx.env;
            return { content: [{ type: "text" as const, text: "ok" }] };
          },
        },
      ],
    });
    const token = await getToken(app);
    // Hono's `app.request` accepts a third argument that becomes `c.env` — this is exactly
    // how a Cloudflare Workers adapter supplies bindings in production.
    const fakeEnv = { SOME_BINDING: "present" };
    await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "check_env", arguments: {} },
        }),
      },
      fakeEnv,
    );
    expect(capturedEnv).toEqual(fakeEnv);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/server.read-tools.test.ts -t "ToolContext.env"`
Expected: FAIL (unless Task 1 already landed the fix, in which case this passes immediately — that's fine, it means Step 3 is a no-op here and you just move to Step 4).

- [ ] **Step 3: Write the implementation (if not already done by Task 1)**

In `src/server.ts`, confirm the `/mcp` handler passes `env: c.env` (not `env: undefined`):

```typescript
  app.post("/mcp", (c) =>
    handleMcpRequest(c.req.raw, {
      ...
      env: c.env,
      ...
    }),
  );
```

In `src/config.ts`, update the `ToolContext.env` doc comment to be accurate for all runtimes, not just Cloudflare:

```typescript
  /**
   * The Hono request's `c.env` — Cloudflare Worker bindings when deployed there, or
   * whatever your Hono adapter supplies for other runtimes (often `undefined`/empty on
   * Node, Lambda, Vercel unless you've typed your own Hono `Env` generic). Cast to your
   * own type.
   */
  env: unknown;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/server.read-tools.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/server.ts src/config.ts test/server.read-tools.test.ts
git commit -m "fix(server): thread real c.env through to ToolContext.env (was always undefined)"
```

---

### Task 9: Fix the appointments example + `deploy.md`'s Cloudflare example

**Files:**
- Modify: `examples/appointments/server.ts`, `examples/appointments/run.ts`, `examples/appointments/README.md`
- Modify: `docs/deploy.md` (Cloudflare Workers section)

**Interfaces:** `createAppointmentsServer(baseUrl?: string)` gains an optional parameter, defaulting to the existing test-only value so `test/examples/appointments.test.ts` (which calls it with zero args) keeps passing unchanged.

- [ ] **Step 1: Fix `examples/appointments/server.ts`**

Change the signature and the `baseUrl` field:

```typescript
export function createAppointmentsServer(baseUrl = "https://example.test") {
  return createMcpServer({
    baseUrl,
    storage: createMemoryStorage(),
    ...
```

- [ ] **Step 2: Fix `examples/appointments/run.ts` to pass the real local URL**

```typescript
const port = Number(process.env.PORT ?? 3000);
serve({ fetch: createAppointmentsServer(`http://localhost:${port}`).fetch, port }, () => {
  console.log(`Appointments MCP server listening on http://localhost:${port}`);
  console.log(`Discovery: http://localhost:${port}/.well-known/oauth-authorization-server`);
});
```

- [ ] **Step 3: Clarify the import path in `examples/appointments/README.md`**

Add a note near the top (after the existing "Note" callouts):

```markdown
> **Import path:** `server.ts` imports from `../../src/index.js` (repo-relative) because
> this example is dogfooded by the kit's own test suite. A real project imports from the
> published package instead — `import { createMcpServer, ... } from "mcp-oauth-kit"` — see
> [`docs/how-to-use.md`](../../docs/how-to-use.md) for the copy-pasteable version.
```

- [ ] **Step 4: Fix `docs/deploy.md`'s Cloudflare Workers example**

Replace the whole Cloudflare Workers code block — the `globalThis` access is wrong for ES-module Workers (bindings only arrive via the `env` parameter of the `fetch` handler), so the app must be constructed per-request inside the handler where `env` is actually available:

```ts
// src/index.ts
import { createMcpServer, createCloudflareKvStorage } from "mcp-oauth-kit";
import { tools } from "./tools.js";

interface Env {
  KV: KVNamespace;
}

export default {
  // Bindings only arrive via this `env` parameter in an ES-module Worker — build the app
  // per-request so `createCloudflareKvStorage` gets the real KV namespace, not a
  // module-scope value that doesn't exist yet at module-evaluation time.
  fetch: (req: Request, env: Env) => {
    const app = createMcpServer({
      baseUrl: "https://mcp.example.com",
      storage: createCloudflareKvStorage(env.KV),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email", type: "email", required: true }],
        verify: async (fields) => (await isValidUser(fields.email)) ? fields.email : null,
      },
      tools,
    });
    return app.fetch(req, env);
  },
} satisfies ExportedHandler<Env>;
```

(`isValidUser` is illustrative — same convention as the rest of this doc's examples, which call out to an unspecified `db`/lookup function. Task 12 addresses making `how-to-use.md`'s samples runnable; this file's samples are explicitly deployment *sketches*, not a copy-paste tutorial, so illustrative calls are acceptable here as long as they're clearly named as such — don't invent a fake `db` global.)

- [ ] **Step 5: Run the full suite**

Run: `npm test && npm run typecheck`
Expected: PASS — `test/examples/appointments.test.ts` calls `createAppointmentsServer()` with no args, which still resolves to `"https://example.test"`, matching `test/helpers.ts`'s hardcoded `resource: "https://example.test/mcp"`.

- [ ] **Step 6: Commit**

```bash
git add examples/appointments/server.ts examples/appointments/run.ts examples/appointments/README.md docs/deploy.md
git commit -m "fix(examples): appointments baseUrl now matches where it actually runs; fix Cloudflare deploy.md env access"
```

---

### Task 10: README fixes bundle

**Files:**
- Modify: `README.md`

**Interfaces:** None — docs only.

Seven independent corrections to the same file:

- [ ] **Step 1: Add `zod` to the peer-dependency install line**

```markdown
Peer dependencies (not bundled):

```bash
npm install hono @modelcontextprotocol/sdk zod
```
```

- [ ] **Step 2: Add a Node/ESM note near Install**

After the peer-dependency block:

```markdown
Node **22+** is required, and your project must be ESM (`"type": "module"` in
`package.json`) — the package publishes an ESM-only `exports` map with no `require` condition.
```

- [ ] **Step 3: Fix `renderAuthorizePage`'s documented signature**

In "Advanced / low-level API":

```markdown
- `renderAuthorizePage(identity, params)` — render the built-in login form HTML (use when building a custom `/authorize` handler).
```

- [ ] **Step 4: Fix the `OAuthProviderConfig` field list**

Same section:

```markdown
- `createOAuthProvider(config)` — build the OAuth provider independently. `OAuthProviderConfig` fields: `storage`, `scopes`, `baseUrl`, optional `now?: () => number` (injectable clock for deterministic testing), and optional `allowClientIdMetadataDocuments?: boolean` (see the Config reference table above).
```

- [ ] **Step 5: Remove the sub-path-mounting self-contradiction**

The "Endpoints mounted by `createMcpServer`" section states the app must be served at the origin root; "Advanced / low-level API" offers the low-level pieces for "sub-path mounting" as if it were supported. Fix the low-level API section's framing — it's for composing a *custom app*, not for mounting under a prefix (which breaks discovery regardless of which API layer you use):

```markdown
Reach for these when you need to compose your own Hono app — custom middleware, a custom
OAuth UI, or wiring in your own routes alongside these — rather than using `createMcpServer`
directly. **The origin-root requirement above still applies** — none of these lower-level
pieces lift it; RFC 8414 discovery breaks under a path prefix regardless of which API layer
mounts the routes.
```

- [ ] **Step 6: Add a transport-version caveat**

In the "OAuth / PKCE client flow" section, add a note before the numbered list:

```markdown
> **Transport vs. authorization spec version.** This kit's authorization surface (discovery,
> DCR/CIMD, PKCE, tokens) targets MCP 2026-07-28. Its MCP *transport* layer is built on
> `@modelcontextprotocol/sdk` `^1`, which implements the `2025-11-25` wire protocol (no
> `2026-07-28`-only features like `server/discover` or `resultType`) — a fully
> `2026-07-28`-compliant client that sends `MCP-Protocol-Version: 2026-07-28` will fall back
> to legacy negotiation per the spec's own backward-compatibility rules, and the flow below
> will still work. This will be resolved when the kit migrates to the SDK's v2 line; see the
> CHANGELOG.
```

- [ ] **Step 7: Document `allowedOrigins`**

Add a row to the Config reference table (after `allowClientIdMetadataDocuments`, matching Task 1):

```markdown
| `allowedOrigins`                 | `string[]`                          | No       | Exact-match allowlist for the browser `Origin` header on `POST /mcp` (DNS-rebinding protection). Requests with no `Origin` header are always allowed; a request WITH one is rejected unless it's in this list. |
```

- [ ] **Step 8: Fix the stale scope-gating description (Task 7 changed this behavior)**

Task 7 (already complete on this branch) reversed the tool-visibility behavior this
paragraph describes — a scope-gated tool is no longer hidden from `tools/list`; it's always
listed, and calling it without the required scope now returns an `isError` result (plus, for
a single non-batch `tools/call`, an HTTP 403 with an `insufficient_scope` challenge) instead
of being invisible. Fix the "Scope gating" section:

```markdown
### Scope gating

If a tool specifies `scope`, the kit checks the caller's token at dispatch time. The tool is
always listed in `tools/list` regardless of the caller's granted scopes — a client can
discover it exists and request the scope via step-up authorization. A caller whose token
lacks the required scope receives an `isError` result naming the missing scope instead of
the handler running; for a single (non-batch) `tools/call`, the HTTP response is also a `403`
carrying a `WWW-Authenticate: Bearer error="insufficient_scope", scope="<required>", ...`
challenge (RFC 6750 §3). Scopes flagged `default: true` in the server config are
automatically granted when the client requests no explicit scopes. `ctx.scopes` inside a
handler reflects the token's full granted scope list.
```

- [ ] **Step 9: Verify and commit**

Run: `npm test` (README changes don't affect tests, but confirm nothing else broke in the same working tree state) and read the full file back once to confirm no broken Markdown tables or dangling links.

```bash
git add README.md
git commit -m "docs(readme): fix peer deps, ESM note, API signatures, sub-path contradiction, transport-version caveat, scope-gating behavior"
```

---

### Task 11: `deploy.md` fixes bundle

**Files:**
- Modify: `docs/deploy.md`

**Interfaces:** None — docs only. (The Cloudflare Workers section's env-access fix is Task 9, Step 4 — don't redo it here; this task covers the OTHER three `deploy.md` findings.)

- [ ] **Step 1: Add `identity` to all remaining examples**

Node, Lambda, and Vercel examples currently omit `identity`, producing a server nobody can log into. Add the same illustrative identity block used elsewhere in this doc to each of the three `createMcpServer({...})` calls (Node §, Lambda §, Vercel §):

```ts
  identity: {
    fields: [{ name: "email", label: "Email", type: "email", required: true }],
    verify: async (fields) => (await isValidUser(fields.email)) ? fields.email : null,
  },
```

(Same `isValidUser` convention as Task 9's Cloudflare fix — keep all four examples in this file consistent with each other.)

- [ ] **Step 2: Fix the Vercel origin-root violation**

The current example mounts everything under `app/api/[[...route]]/route.ts`, which serves at `/api/*` — violating this same file's origin-root rule three paragraphs up. Add a `vercel.json` alongside the code block with an explanation:

```markdown
Vercel Functions live under `/api` by default, which conflicts with the origin-root
requirement stated above. Add rewrites so the well-known and OAuth paths resolve at the
root while the function itself stays at its normal Vercel location:

```json
// vercel.json
{
  "rewrites": [
    { "source": "/.well-known/:path*", "destination": "/api/:path*" },
    { "source": "/authorize", "destination": "/api/authorize" },
    { "source": "/token", "destination": "/api/token" },
    { "source": "/register", "destination": "/api/register" },
    { "source": "/revoke", "destination": "/api/revoke" },
    { "source": "/mcp", "destination": "/api/mcp" }
  ]
}
```
```

Place this markdown block immediately after the existing Vercel code sample, before the "For the `"nodejs"` runtime..." paragraph.

- [ ] **Step 3: Fix the in-memory-adapter contradiction**

The Node.js section currently says "The in-memory adapter works for single-process deployments," directly contradicting `storage-adapters.md`, the README, and `SECURITY.md`, all of which say never use it in production. Fix the sentence:

```markdown
Use any `KvLike` implementation. **The in-memory adapter is for local development only —
even a single production process restarts, loses state, and (if ever scaled to more than
one instance) won't share state across them.** Use the Redis or Postgres adapter from
[docs/storage-adapters.md](storage-adapters.md) for anything beyond local dev.
```

- [ ] **Step 4: Verify and commit**

Run: `npm test` to confirm nothing else broke; read the full file back once.

```bash
git add docs/deploy.md
git commit -m "docs(deploy): add identity to all examples, fix Vercel origin-root violation, fix in-memory-adapter claim"
```

---

### Task 12: `how-to-use.md` fixes bundle

**Files:**
- Modify: `docs/how-to-use.md`

**Interfaces:** None — docs only.

- [ ] **Step 1: Make the identity `verify` code sample runnable**

Section 4 currently calls an undefined `db.verifyLoginCode(...)`. Replace with a self-contained, actually-runnable example using an in-memory `Map` (matches the guide's own "local development" framing for this section) and a clear comment marking where real persistence goes:

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

- [ ] **Step 2: Make the mutating-tool `execute` sample runnable**

Section 6's example calls an undefined `db.book(...)`. Replace with a comment-marked illustrative version, consistent with Step 1's pattern:

```ts
// Phase 2 — runs only after confirm_request with the token from phase 1.
execute: async (data, ctx) => {
  const { slot } = data as { slot: string };
  // Replace with your real persistence — this illustrates where the side effect goes.
  console.log(`booking ${slot} for ${ctx.userId}`);
  return { content: [{ type: "text", text: `Booked ${slot}.` }] };
},
```

- [ ] **Step 3: Document the mandatory `Accept` header**

Add a note right before the section 7 code block:

```markdown
> **Both `Accept` values are required.** `POST /mcp` requires
> `accept: application/json, text/event-stream` — the SDK transport rejects a request
> missing either value with `406 Not Acceptable`, even though this kit's stateless JSON
> mode never actually streams SSE. The curl commands below include it; a plain
> `fetch`/Postman request that omits it will fail.
```

- [ ] **Step 4: Document the two-phase confirm wire contract precisely**

Section 6 explains the *why* well but not the exact response shapes. Add a subsection after the existing code block, before section 7:

```markdown
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

`confirm_request` is registered **only when at least one mutating tool is present in the
caller's scope-granted set** — if none of your mutating tools are visible to a given caller
(prior to Task 7 of the 2026-07-28 fixes: because they were hidden by scope; as of Task 7:
`confirm_request` is still conditional on grant, even though the mutating tools themselves
are now always listed — see the README's scope-gating section), `confirm_request` won't
appear in that caller's `tools/list` either.
```

- [ ] **Step 5: Correct and expand the custom-identity section with a real example**

Section 4 currently says "omit `identity` and compose the lower-level pieces" with no example — and `createMcpServer` has no first-class custom-identity hook (confirmed by reading `src/server.ts` and `src/config.ts` — `identity` is the ONLY authentication path `createMcpServer` offers). Replace the one-line mention with a real, working composition example:

````markdown
If you already run your own OAuth UI or SSO flow (SAML, OIDC, an existing login page),
`createMcpServer`'s built-in `identity` form isn't your integration point — it's a credential
form, not a redirect-based federation client. Compose the lower-level pieces instead, and
call `provider.issueAuthCode` yourself from wherever your own login flow lands:

```ts
import { Hono } from "hono";
import {
  createOAuthProvider,
  mountOAuthRoutes,
  mountDiscovery,
  createMemoryStorage,
} from "mcp-oauth-kit";

const baseUrl = "https://mcp.example.com";
const storage = createMemoryStorage(); // swap for production storage
const scopes = [{ name: "account:read", default: true }];

const provider = createOAuthProvider({ storage, scopes, baseUrl });
const app = new Hono();

mountDiscovery(app, { baseUrl, scopes });
// Omit `identity` here — mountOAuthRoutes without it makes /authorize reject with
// "No identity provider configured". Mount your OWN /authorize route below instead of
// relying on the kit's login form.
mountOAuthRoutes(app, { provider, baseUrl });

// Your own login flow lands here after it has already authenticated the user via SSO/SAML/etc.
app.get("/my-custom-authorize", async (c) => {
  const userId = await mySsoMiddleware(c); // however you already authenticate users
  const { code } = await provider.issueAuthCode({
    clientId: c.req.query("client_id")!,
    redirectUri: c.req.query("redirect_uri")!,
    codeChallenge: c.req.query("code_challenge")!,
    scope: provider.normalizeScopes((c.req.query("scope") ?? "").split(" ")),
    userId,
    resource: c.req.query("resource") ?? "",
  });
  const location = new URL(c.req.query("redirect_uri")!);
  location.searchParams.set("code", code);
  const state = c.req.query("state");
  if (state) location.searchParams.set("state", state);
  return c.redirect(location.toString(), 302);
});
```

The MCP transport (`POST /mcp`) and tool registration are unaffected by this — mount them
exactly as `createMcpServer` does internally (see its source for the six-line wiring), or
just call `handleMcpRequest` directly per the README's low-level API reference.
````

- [ ] **Step 6: Fix the stale scope-gating description (Task 7 changed this behavior)**

Section 5 ("Scopes and scope gating") currently says a caller "won't even see" an
ungranted tool in `tools/list` — Task 7 (already complete on this branch) reversed this:
the tool is always listed, and calling it without the scope now returns an `isError`
result (plus an HTTP 403 for a single non-batch `tools/call`). Fix the paragraph and code
comment:

```markdown
Attach `scope` to a tool to gate it. The tool is always listed in `tools/list` regardless
of the caller's granted scopes — a client can discover it exists and ask for the scope via
step-up authorization. A caller whose token lacks the scope gets an `isError` result
naming the missing scope instead of the handler running:

```ts
{
  name: "delete_thing",
  description: "Delete a thing.",
  scope: "write",          // always listed; blocked unless the token has "write"
  inputSchema: z.object({ id: z.string() }),
  handler: async (input, ctx) => { /* ctx.scopes lists everything granted */ },
}
```
```

- [ ] **Step 7: Verify and commit**

Run: `npm test` to confirm nothing else broke; read the full file back once.

```bash
git add docs/how-to-use.md
git commit -m "docs(how-to-use): runnable code samples, two-phase wire contract, mandatory Accept header, real custom-identity example, scope-gating behavior"
```

---

### Task 13: `package.json` metadata + `CONTRIBUTING.md` + `CHANGELOG.md` fixes

**Files:**
- Modify: `package.json`
- Modify: `CONTRIBUTING.md`
- Modify: `CHANGELOG.md`

**Interfaces:** None — metadata/docs only.

- [ ] **Step 1: Add npm package metadata**

In `package.json`, add (verify the actual GitHub org/repo name first — `git remote -v` — the CHANGELOG's existing release link uses `bradburch/mcp-auth-kit`, but confirm against the real remote rather than assuming, since the repo directory is `mcp-server-kit` and the package is `mcp-oauth-kit`; use whichever the actual `origin` remote resolves to):

```json
  "repository": {
    "type": "git",
    "url": "git+https://github.com/<org>/<repo>.git"
  },
  "homepage": "https://github.com/<org>/<repo>#readme",
  "bugs": {
    "url": "https://github.com/<org>/<repo>/issues"
  },
  "keywords": ["mcp", "model-context-protocol", "oauth", "oauth2", "pkce", "authorization-server"],
  "author": "",
```

(Leave `author` empty unless you know what the repo owner wants there — an empty string is valid and better than a guessed name. `repository`/`homepage`/`bugs` are what actually fixes the "npm can't rewrite the README's relative doc links" and "no source link on the npm page" findings — those are the load-bearing fields.)

- [ ] **Step 2: Also add `files` entries so `docs/` and `examples/` ship**

The README links to `docs/how-to-use.md` and references `examples/appointments/server.ts`, but `package.json`'s `files` array currently only ships `dist`. Either the README's relative links need `repository` to resolve on npm's website (Step 1 covers that for GitHub-rendered links) — but the direct file references (`README.md:82`, "See `examples/appointments/server.ts`") only work for someone who clones the repo, not an npm consumer. The cheapest correct fix is Step 1 (npm's package page then links to GitHub, where those paths resolve); do NOT add `docs`/`examples` to `files` — that would ship maintainer-facing content (they reference the repo's own test suite, `../../src/index.js`, etc.) inside the installed package for no benefit to a consumer. Leave `files: ["dist"]` as is; this step is a no-op confirming that decision — note it in the commit message so it's not silently unconsidered.

- [ ] **Step 3: Soften `CONTRIBUTING.md`'s overclaim**

```markdown
Thanks for your interest in improving the kit. This project aims to be a small,
auditable foundation for OAuth-protected MCP servers — contributions
that keep it that way are very welcome.
```

(Removes "production-grade," which contradicts the README's own pre-1.0 status banner — the rest of the sentence, and the file, already sets the right tone otherwise.)

- [ ] **Step 4: Fix `CHANGELOG.md`'s release link**

```markdown
[0.1.0]: https://github.com/<org>/<repo>/releases/tag/v0.1.0
```

(Same org/repo confirmation as Step 1 — use the real remote, not a guess, and use the same value in both places.)

- [ ] **Step 5: Verify and commit**

Run: `npm run typecheck && npm test` (package.json changes shouldn't affect either, but confirm) and `git remote -v` one more time to sanity-check the URLs you wrote match reality.

```bash
git add package.json CONTRIBUTING.md CHANGELOG.md
git commit -m "chore: add npm package metadata, fix repo links, soften production-grade overclaim"
```

---

### Task 14: Version bump, final CHANGELOG, and release

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `package.json` (version)

**Interfaces:** None — this task also performs the actual `npm publish`, which the controller runs directly (not delegated to a subagent) after this task's diff passes review, per the user's explicit approval for a version bump + publish as part of this work.

This is the last task — every other task must be complete, reviewed, and merged onto this branch first, since the CHANGELOG entry summarizes all of them.

- [ ] **Step 1: Rewrite `CHANGELOG.md`'s `[Unreleased]` section**

Replace the `## [Unreleased]` block (keep everything below `## [0.1.0]` unchanged) with a new, dated version section summarizing Tasks 1–13 in Keep-a-Changelog style. Use the ACTUAL commit history on this branch as the source of truth for what to list — don't just copy this plan's task titles verbatim; read `git log <merge-base>..HEAD --oneline` and write the changelog from what actually landed, in case a task's scope shifted during implementation or review. At minimum it must cover:

- `Origin` header validation (DNS rebinding protection)
- Discovery metadata fixes (`authorization_response_iss_parameter_supported`, PRM `scopes_supported`, PRM sub-path mount, dropped non-standard AS `resource` field)
- Redirect URI hostname display + localhost warning on the login page; `frame-ancestors` CSP
- `baseUrl` HTTPS validation; token audience re-check; SDK peer dependency pinned to `^1`
- CIMD cache now respects `Cache-Control`
- `Mcp-Method`/`Mcp-Name` header validation
- **Breaking:** scope-gated tools are no longer hidden from `tools/list`; an ungranted call now returns an `isError` result and, for a single non-batch `tools/call`, an HTTP 403 with an `insufficient_scope` `WWW-Authenticate` challenge
- `ToolContext.env` now carries the real Hono `c.env` (was previously always `undefined`)
- Numerous documentation corrections (README, deploy.md, how-to-use.md, CONTRIBUTING.md) and the appointments example's `baseUrl` fix

Mark the tools/list scope-gating change clearly as `### Changed` with a `**Breaking:**` prefix, per the existing CHANGELOG's own conventions (it already uses bold labels for load-bearing behavior changes, e.g. "Access, refresh... tokens now use 256-bit... entropy").

- [ ] **Step 2: Bump the version**

Decide the correct semver bump: the `tools/list` scope-gating change (Task 7) is a breaking behavior change for any existing consumer relying on ungranted tools being hidden — but this package is pre-1.0 (`0.1.0`), where minor-version bumps may include breaking changes per semver's own pre-1.0 carve-out, which is also what the README's status banner already tells consumers to expect ("the API may still change"). Bump to `0.2.0` (a `0.x` minor bump), not `0.1.1` (patch — wrong, this isn't just a fix) and not `1.0.0` (too strong a signal given `README.md`'s own pre-1.0 caveats haven't been resolved by this work — the "best-effort, not exactly-once" limitations are unchanged).

```json
  "version": "0.2.0",
```

- [ ] **Step 3: Run the full verification gate**

```bash
npm run format:check && npm run typecheck && npm run lint && npm run build && npm test
```
All five must pass. This is the exact gate `CONTRIBUTING.md` documents as mirroring CI — do not skip `format:check` or `build` (the prior plan's final review caught a `format:check` failure specifically because an earlier gate check omitted it).

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md package.json
git commit -m "chore(release): v0.2.0"
```

- [ ] **Step 5: Publish (controller-only — do not delegate this step to a subagent)**

After this task's diff has been through the normal task-review gate AND the final whole-branch review has passed AND the branch is merged to `main`, the controller (not an implementer subagent) runs, from `main`, after pulling the merge commit:

```bash
npm publish
```

Confirm the published version on npm afterward (`npm view mcp-oauth-kit version`) and report the result plainly — this is a real, externally-visible action with no undo.

---

## Self-Review

**Coverage check against both source reports:**

*Spec-compliance report* — Critical: Origin validation (Task 1) ✓, SDK version mismatch (Task 4's peer pin + Task 10's README caveat — full SDK v2 migration explicitly deferred, unchanged from the prior plan) ✓. Important: `authorization_response_iss_parameter_supported` (Task 2) ✓, `Mcp-Method`/`Mcp-Name` (Task 6) ✓, `insufficient_scope` 403 (Task 7, per explicit approval) ✓, PRM `scopes_supported` (Task 2) ✓, redirect URI display (Task 3) ✓. Minor: `frame-ancestors` (Task 3) ✓, `baseUrl` HTTPS (Task 4) ✓, PRM resource/sub-path (Task 2) ✓, CIMD `Cache-Control` (Task 5) ✓, audience re-check (Task 4) ✓. Ambiguous items (proxy-scoped MUSTs, per-client scope allowlisting, CSRF on `/authorize`, KV multi-tenancy) — left as-is per the prior report's own read that they don't bind a first-party AS, with the KV-sharing one now at least documented (Task 4).

*Onboarding report* — friction #1 (ESM undocumented) → Task 10 Step 2 ✓. #2 (`ctx.env` always undefined) → Task 8 ✓. #3 (docs describe unshipped features) → resolved by Task 14's publish, not a doc fix — the features ARE shipping now. #4 (npm metadata / dead doc link) → Task 13 ✓. #5 (deploy.md missing `identity`) → Task 11 ✓. Docs-vs-code drift table: `ctx.env` (Task 8), Cloudflare `globalThis` (Task 9), `renderAuthorizePage` arg count (Task 10), `OAuthProviderConfig` fields (Task 10), CIMD/`iss` unshipped (Task 14), missing `zod` peer (Task 10), sub-path self-contradiction (Task 10), Vercel origin-root violation (Task 11), in-memory-adapter contradiction (Task 11), CHANGELOG repo link (Task 13), appointments `baseUrl` (Task 9). Custom-identity provider gap → Task 12 Step 5 (documented as a composition pattern, not a new config API, per this plan's explicit out-of-scope note).

**Placeholder scan:** every code step above carries the actual diff/text to apply, not a description of what to do. The two spots that name an illustrative-only helper (`isValidUser`, `db.book`) are `deploy.md`/`how-to-use.md` documentation examples, explicitly marked as illustrative in the surrounding prose — consistent with that doc's existing convention, not a placeholder standing in for real plan content.

**Type consistency:** `McpServerConfig.allowedOrigins` (Task 1) → `McpRequestDeps.allowedOrigins` (Task 1) → `server.ts`'s `/mcp` handler (Task 1). `ClientIdMetadata.maxAgeSeconds` (Task 5) → consumed in `provider.ts`'s `resolveClientRedirectUris` (Task 5). `JSON_RPC_ERROR` gains `ORIGIN_NOT_ALLOWED: -32003` (Task 1), `HEADER_MISMATCH: -32020` (Task 6), `INSUFFICIENT_SCOPE: -32021` (Task 7) — sequential, non-colliding, matching the spec's error-code allocation policy discussed in the prior plan's final review. `registerTools`'s new `registerUngrantedMutatingTool` helper (Task 7) is called exactly once, from the one branch that needs it.

**Cross-task file collisions:** `src/server.ts` is touched by Tasks 1, 4, and 8 — Task 1's step already includes Task 8's `env: c.env` change as a drive-by (both note this explicitly); Task 4 adds `assertHttpsBaseUrl` at the top of the same function but doesn't touch the `/mcp` handler body, so no line-level collision. `src/transport.ts` is touched by Tasks 1, 6, and 7 — sequential, each adding a distinct check to `handleMcpRequest`'s top; Task 7's design note explicitly says to reuse Task 6's parsed body if it already landed, to avoid a third duplicate `JSON.parse`. `src/oauth/discovery.ts` is touched only by Task 2 — no collision. Execute tasks in the numbered order to keep these dependencies resolved in sequence.
