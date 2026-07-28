# MCP 2026-07-28 Spec Compliance (OAuth surface) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring this kit's hand-rolled OAuth/authorization surface up to date with the changes the [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/draft/changelog) makes to authorization (finalizing today, superseding the current `2025-11-25` revision), without touching the wire-protocol mechanics that `@modelcontextprotocol/sdk` owns.

**Architecture:** No new subsystems. Each task is a small, additive change to the existing `src/oauth/*` files, following the file's existing patterns (Hono context, `KvLike` storage, the existing `oauthError`/audit-hook helpers). One new file (`src/oauth/cimd.ts`) is added for Client ID Metadata Document support, since that's a genuinely new capability (an outbound fetch at authorization time) that deserves its own module and test file rather than being folded into `provider.ts`.

**Tech Stack:** TypeScript, Hono, vitest, `KvLike` storage abstraction — all already in use, no new dependencies.

## Global Constraints

- Target: authorization-related changes in the [2026-07-28 changelog](https://modelcontextprotocol.io/specification/draft/changelog) (the "Minor changes" and "Deprecated" sections — items 4, 7, 8 — plus the [Authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)'s CIMD section, which the changelog deprecates DCR in favor of).
- **Out of scope for this plan** (see the "Explicitly Out of Scope" section at the end — do not implement these here):
  - The TypeScript SDK v2 beta (`@modelcontextprotocol/server`/`@modelcontextprotocol/client`) migration — it's a beta package with a different name, not a drop-in upgrade.
  - Any change to `src/transport.ts`'s core request handling, `src/two-phase.ts`, or `src/tools/registry.ts` beyond the one `WWW-Authenticate` header tweak in Task 5 — the stateless-session removal, `resultType` field, `server/discover` RPC, and JSON-RPC error-code renumbering are all mechanics `@modelcontextprotocol/sdk`'s `McpServer` / `WebStandardStreamableHTTPServerTransport` already own; this kit only consumes those classes.
  - Client-side requirements (`iss` validation by the *client*, credentials keyed by issuer) — this kit only ever acts as the OAuth **authorization server** and **resource server**, never as a client.
- Node >=22 (existing `engines` floor), ESM (`"type": "module"`), strict TypeScript (`tsconfig.json`).
- Every new/changed file follows existing conventions: file-header comment block, `KvLike` for all persistence (no direct fetch to storage backends), errors surfaced as `Error` with a message routes.ts pattern-matches on (see the `if (msg.includes(...))` blocks in `routes.ts`'s `/token` handler) — don't introduce a different error-signaling convention.
- Any new outbound network call (Task 2/3's CIMD fetch) must be: HTTPS-only, time-bounded, response-size-capped, and guarded against the obvious SSRF targets (loopback/link-local/RFC1918 literals) — mirroring the existing security posture (`body-limit.ts` caps request bodies, `rate-limit.ts` guards abuse). It must default to **off**, since it's an outbound-request surface operators need to opt into.
- Run `npm run typecheck && npm run lint && npm test` before every commit (matches existing CI, see `.github/`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/oauth/routes.ts` | *Modify.* Add `iss` to the `/authorize` redirect (Task 1); accept/validate/echo `application_type` on `/register` (Task 4). |
| `src/oauth/cimd.ts` | *Create.* Fetch + validate a Client ID Metadata Document from an `https://` `client_id` URL. Pure function, no storage access (Task 2). |
| `src/oauth/provider.ts` | *Modify.* Resolve a client's allowed redirect URIs from either a stored (DCR/pre-registered) record or, if enabled, a cached CIMD fetch; store `application_type` on registration (Tasks 3, 4). |
| `src/oauth/discovery.ts` | *Modify.* Advertise `client_id_metadata_document_supported` in AS metadata (Task 3). |
| `src/storage/keys.ts` | *Modify.* Add `cimdKey` for the CIMD response cache (Task 3). |
| `src/config.ts` | *Modify.* Add `allowClientIdMetadataDocuments` to `McpServerConfig` (Task 3). |
| `src/server.ts` | *Modify.* Wire the new config option to `createOAuthProvider` and `mountDiscovery` (Task 3). |
| `src/transport.ts` | *Modify.* Add a `scope` attribute to the 401 `WWW-Authenticate` challenge (Task 5). |
| `test/oauth/cimd.test.ts` | *Create.* Unit tests for the CIMD fetch/validate helper. |
| `test/oauth/routes.test.ts` | *Modify.* Tests for `iss` and `application_type`. |
| `test/oauth/provider.test.ts` | *Modify.* Tests for CIMD-backed client resolution. |
| `test/transport.test.ts` | *Create.* Tests for the `WWW-Authenticate` scope hint. |
| `README.md`, `CHANGELOG.md`, `docs/how-to-use.md` | *Modify.* Document the new config option and record the change (Task 6). |

---

### Task 1: RFC 9207 `iss` parameter on the authorization redirect

**Files:**
- Modify: `src/oauth/routes.ts:156-159` (destructure), `src/oauth/routes.ts:376-381` (redirect)
- Test: `test/oauth/routes.test.ts`

**Interfaces:**
- Consumes: `OAuthRouteDeps.baseUrl` (already declared in the interface at `routes.ts:122`, just not currently destructured/used).
- Produces: no new exports — internal behavior change to the `POST /authorize` redirect only.

- [ ] **Step 1: Write the failing test**

Add to `test/oauth/routes.test.ts` (inside the existing `describe("oauth routes", ...)` block, or a new adjacent `describe`):

```typescript
import { pkce } from "../helpers.js";

// ─── RFC 9207 — iss parameter on the authorization redirect ───────────────────

describe("POST /authorize — RFC 9207 iss parameter", () => {
  it("includes iss=<baseUrl> on the success redirect", async () => {
    const app = new Hono();
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });
    mountOAuthRoutes(app, {
      provider,
      baseUrl,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
    });

    const reg = await (
      await app.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
      })
    ).json();
    const { challenge } = await pkce();

    const res = await app.request("/authorize", {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        response_type: "code",
        client_id: reg.client_id,
        redirect_uri: "https://app/cb",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: `${baseUrl}/mcp`,
        email: "a@b.c",
      }).toString(),
    });

    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location")!);
    expect(location.searchParams.get("iss")).toBe(baseUrl);
    expect(location.searchParams.get("code")).toBeTruthy();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/oauth/routes.test.ts -t "RFC 9207"`
Expected: FAIL — `location.searchParams.get("iss")` is `null`, not `baseUrl`.

- [ ] **Step 3: Write minimal implementation**

In `src/oauth/routes.ts`, add `baseUrl` to the destructure at line 158:

```typescript
export function mountOAuthRoutes(
  app: Hono,
  { provider, identity, baseUrl, hooks, rateLimiter, ipExtractor }: OAuthRouteDeps,
): void {
```

Then in the `POST /authorize` success path (around line 376-381):

```typescript
      // 302 redirect back to client with code (and state if provided).
      const location = new URL(redirectUri);
      location.searchParams.set("code", code);
      if (state) location.searchParams.set("state", state);
      // RFC 9207 (MCP 2026-07-28 changelog item 7): echo the issuer so clients can
      // detect a mix-up attack before redeeming the code.
      location.searchParams.set("iss", baseUrl);

      return c.redirect(location.toString(), 302);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/oauth/routes.test.ts`
Expected: PASS (all tests in the file, including the new one and the existing ones — confirms the added destructure didn't break anything).

- [ ] **Step 5: Commit**

```bash
git add src/oauth/routes.ts test/oauth/routes.test.ts
git commit -m "feat(oauth): echo iss on the authorization redirect (RFC 9207)"
```

---

### Task 2: Client ID Metadata Document fetch + validation helper

**Files:**
- Create: `src/oauth/cimd.ts`
- Test: `test/oauth/cimd.test.ts`

**Interfaces:**
- Produces: `fetchClientIdMetadata(clientIdUrl: string): Promise<ClientIdMetadata | null>` and `interface ClientIdMetadata { clientId: string; clientName?: string; redirectUris: string[] }` — Task 3 imports both.

- [ ] **Step 1: Write the failing tests**

Create `test/oauth/cimd.test.ts`:

```typescript
// test/oauth/cimd.test.ts
import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchClientIdMetadata } from "../../src/oauth/cimd.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchClientIdMetadata", () => {
  it("returns the parsed metadata for a valid document", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    const doc = {
      client_id: clientId,
      client_name: "Example Client",
      redirect_uris: ["https://app.example.com/callback"],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(doc), { status: 200 })),
    );

    expect(await fetchClientIdMetadata(clientId)).toEqual({
      clientId,
      clientName: "Example Client",
      redirectUris: ["https://app.example.com/callback"],
    });
  });

  it("rejects a document whose client_id doesn't match the fetch URL", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              client_id: "https://evil.example.com/client.json",
              redirect_uris: ["https://app.example.com/callback"],
            }),
            { status: 200 },
          ),
      ),
    );

    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });

  it("refuses a non-https client_id without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("http://app.example.com/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a client_id with no path component", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("https://app.example.com")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks loopback and private-range hosts without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    expect(await fetchClientIdMetadata("https://127.0.0.1/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://192.168.1.5/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://10.0.0.1/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://localhost/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a document larger than the size cap", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    const huge = "x".repeat(20_000);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(huge, { status: 200 })),
    );
    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });

  it("rejects a document missing redirect_uris", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ client_id: clientId }), { status: 200 })),
    );
    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/cimd.test.ts`
Expected: FAIL — `src/oauth/cimd.ts` doesn't exist yet (module resolution error).

- [ ] **Step 3: Write the implementation**

Create `src/oauth/cimd.ts`:

```typescript
// OAuth Client ID Metadata Documents (CIMD) — draft-ietf-oauth-client-id-metadata-document-00.
// MCP 2026-07-28 deprecates Dynamic Client Registration in favor of this: the client_id IS
// an HTTPS URL pointing at a JSON document describing the client (see the MCP spec's
// "Client ID Metadata Documents" section, deprecating RFC 7591 DCR per changelog item 4).

/** Response body cap for a metadata document fetch — these are small JSON files. */
const MAX_DOCUMENT_BYTES = 16 * 1024;

/** Abort a metadata fetch that hangs (e.g. a slow-loris endpoint). */
const FETCH_TIMEOUT_MS = 3000;

/** A validated Client ID Metadata Document, narrowed to the fields MCP needs. */
export interface ClientIdMetadata {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
}

/**
 * Hostnames/IP literals that must never be fetched — loopback, link-local, and RFC1918
 * private ranges. Best-effort SSRF guard: it blocks the obvious literal forms, but does NOT
 * resolve DNS and pin the connection, so it cannot stop DNS-rebinding against a public
 * hostname that later resolves to a private address. Deployments with strict SSRF
 * requirements should also enforce network-level egress controls (e.g. an egress proxy
 * that resolves and filters at connect time).
 */
function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "0.0.0.0" || h === "::1") return true;
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  return false;
}

/** Read a Response body with a byte cap enforced while streaming. Returns null if exceeded. */
async function readCappedText(res: Response, maxBytes: number): Promise<string | null> {
  const body = res.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/**
 * Fetch and validate a Client ID Metadata Document. Returns null (never throws) on any
 * validation failure — an invalid/unreachable document means "not a CIMD client," not a
 * server error, so callers fall back to other registration mechanisms.
 */
export async function fetchClientIdMetadata(
  clientIdUrl: string,
): Promise<ClientIdMetadata | null> {
  let url: URL;
  try {
    url = new URL(clientIdUrl);
  } catch {
    return null;
  }
  // Spec: client_id MUST use "https" and contain a path component.
  if (url.protocol !== "https:" || url.pathname === "" || url.pathname === "/") return null;
  if (isBlockedHost(url.hostname)) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(url, { redirect: "error", signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
  if (!res.ok) return null;

  const text = await readCappedText(res, MAX_DOCUMENT_BYTES);
  if (text === null) return null;

  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object") return null;
  const d = doc as Record<string, unknown>;

  // MUST match the fetch URL exactly (prevents a document claiming someone else's client_id).
  if (d.client_id !== clientIdUrl) return null;
  if (!Array.isArray(d.redirect_uris) || d.redirect_uris.length === 0) return null;
  if (!d.redirect_uris.every((u) => typeof u === "string")) return null;

  return {
    clientId: clientIdUrl,
    clientName: typeof d.client_name === "string" ? d.client_name : undefined,
    redirectUris: d.redirect_uris as string[],
  };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/cimd.test.ts`
Expected: PASS (all 7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/oauth/cimd.ts test/oauth/cimd.test.ts
git commit -m "feat(oauth): add Client ID Metadata Document fetch/validate helper"
```

---

### Task 3: Wire CIMD into the provider + advertise support in discovery

**Files:**
- Modify: `src/oauth/provider.ts`
- Modify: `src/oauth/discovery.ts`
- Modify: `src/storage/keys.ts`
- Modify: `src/config.ts`
- Modify: `src/server.ts`
- Test: `test/oauth/provider.test.ts`, `test/oauth/routes.test.ts`

**Interfaces:**
- Consumes: `fetchClientIdMetadata` from `./cimd.js` (Task 2).
- Produces: `OAuthProviderConfig.allowClientIdMetadataDocuments?: boolean`; `McpServerConfig.allowClientIdMetadataDocuments?: boolean`; `DiscoveryDeps.clientIdMetadataDocumentsSupported?: boolean`.

- [ ] **Step 1: Write the failing tests**

Add to `test/oauth/provider.test.ts`:

```typescript
import { describe, it, expect, vi, afterEach } from "vitest";
// (merge with existing imports in the file rather than duplicating)

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Client ID Metadata Document resolution", () => {
  const cimdClientId = "https://app.example.com/oauth/client.json";

  function stubCimdDocument(redirectUris: string[]) {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ client_id: cimdClientId, redirect_uris: redirectUris }),
            { status: 200 },
          ),
      ),
    );
  }

  it("resolves an unregistered https client_id via CIMD when enabled", async () => {
    stubCimdDocument(["https://app.example.com/callback"]);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    const ok = await provider.validateClientRedirect(
      cimdClientId,
      "https://app.example.com/callback",
    );
    expect(ok).toBe(true);
  });

  it("rejects a redirect_uri not listed in the CIMD document", async () => {
    stubCimdDocument(["https://app.example.com/callback"]);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    expect(
      await provider.validateClientRedirect(cimdClientId, "https://app.example.com/other"),
    ).toBe(false);
  });

  it("does not attempt CIMD resolution when disabled (default)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });

    expect(
      await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback"),
    ).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("caches the CIMD result so a second lookup doesn't re-fetch", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            client_id: cimdClientId,
            redirect_uris: ["https://app.example.com/callback"],
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback");
    await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
```

Add to `test/oauth/routes.test.ts` (discovery advertisement):

```typescript
it("advertises client_id_metadata_document_supported when enabled", async () => {
  const app = new Hono();
  mountDiscovery(app, { baseUrl, scopes, clientIdMetadataDocumentsSupported: true });
  const res = await app.request("/.well-known/oauth-authorization-server");
  expect((await res.json()).client_id_metadata_document_supported).toBe(true);
});

it("defaults client_id_metadata_document_supported to false", async () => {
  const app = new Hono();
  mountDiscovery(app, { baseUrl, scopes });
  const res = await app.request("/.well-known/oauth-authorization-server");
  expect((await res.json()).client_id_metadata_document_supported).toBe(false);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/provider.test.ts test/oauth/routes.test.ts`
Expected: FAIL — `allowClientIdMetadataDocuments` / `clientIdMetadataDocumentsSupported` don't exist yet; `validateClientRedirect` always returns `false` for the CIMD client_id.

- [ ] **Step 3: Write the implementation**

In `src/storage/keys.ts`, add:

```typescript
export const cimdKey = (clientIdHash: string) => `mcp:cimd:${clientIdHash}`;
```

In `src/oauth/provider.ts`:

Extend the imports (line 1-10) — add `cimdKey` to the `storage/keys.js` import and add a new import:

```typescript
import {
  clientKey,
  authCodeKey,
  accessTokenKey,
  refreshTokenKey,
  tokenFamilyKey,
  cimdKey,
} from "../storage/keys.js";
import { fetchClientIdMetadata } from "./cimd.js";
```

Add a TTL entry (in the `TTL` const, ~line 13-18):

```typescript
const TTL = {
  CLIENT: 30 * 24 * 60 * 60, // 30 days
  AUTH_CODE: 5 * 60, // 5 minutes
  ACCESS_TOKEN: 60 * 60, // 1 hour
  REFRESH_TOKEN: 90 * 24 * 60 * 60, // 90 days
  CIMD_CACHE: 60 * 60, // 1 hour — bounds staleness without needing to parse Cache-Control
} as const;
```

Extend `OAuthProviderConfig` (~line 75-81):

```typescript
export interface OAuthProviderConfig {
  storage: KvLike;
  scopes: ScopeConfig[];
  baseUrl: string;
  /** Injectable clock for deterministic TTL/expiry in tests. */
  now?: () => number;
  /**
   * Resolve unregistered HTTPS client_ids as OAuth Client ID Metadata Documents
   * (MCP 2026-07-28, deprecating Dynamic Client Registration). Off by default —
   * enabling it makes this server fetch an operator-uncontrolled URL during
   * authorization; only turn it on once you're comfortable with that outbound
   * request surface. See `docs/oauth.md`.
   */
  allowClientIdMetadataDocuments?: boolean;
}
```

Update the config destructure (~line 127):

```typescript
  const { storage, scopes, baseUrl, allowClientIdMetadataDocuments = false } = config;
```

Add a helper next to `assertResource` (~after line 151):

```typescript
  /**
   * Resolve the redirect URIs a client_id is allowed to use — from a stored
   * (pre-registered / DCR) record first, falling back to a cached Client ID Metadata
   * Document fetch when `allowClientIdMetadataDocuments` is enabled and the client_id
   * looks like an https URL not already registered.
   */
  async function resolveClientRedirectUris(clientId: string): Promise<string[] | null> {
    const raw = await storage.get(clientKey(clientId));
    if (raw) return (JSON.parse(raw) as ClientData).redirectUris;

    if (!allowClientIdMetadataDocuments || !clientId.startsWith("https://")) return null;

    const cacheKey = cimdKey(await sha256Hex(clientId));
    const cached = await storage.get(cacheKey);
    if (cached !== null) {
      // Empty string is the cached "fetched but invalid/unreachable" sentinel.
      return cached === "" ? null : (JSON.parse(cached) as string[]);
    }

    const doc = await fetchClientIdMetadata(clientId);
    await storage.put(cacheKey, doc ? JSON.stringify(doc.redirectUris) : "", {
      ttlSeconds: TTL.CIMD_CACHE,
    });
    return doc?.redirectUris ?? null;
  }
```

Replace `validateClientRedirect` (~line 273-279):

```typescript
    async validateClientRedirect(clientId, redirectUri) {
      if (!clientId || !redirectUri) return false;
      const redirectUris = await resolveClientRedirectUris(clientId);
      return redirectUris?.includes(redirectUri) ?? false;
    },
```

Replace the client lookup at the top of `issueAuthCode` (~line 246-255):

```typescript
      const redirectUris = await resolveClientRedirectUris(input.clientId);
      if (!redirectUris) {
        throw new Error("Unknown client");
      }

      // RFC 6749 §3.1.2.3: the redirect_uri must match one the client registered.
      if (!redirectUris.includes(input.redirectUri)) {
        throw new Error("Redirect URI mismatch");
      }
```

(This replaces the old `const raw = await storage.get(clientKey(input.clientId)); ... const client = JSON.parse(raw) as ClientData; if (!client.redirectUris.includes(...))` block — `client` is no longer referenced elsewhere in `issueAuthCode`.)

In `src/oauth/discovery.ts`, extend `DiscoveryDeps` and the AS metadata response:

```typescript
export interface DiscoveryDeps {
  baseUrl: string;
  scopes: ScopeConfig[];
  /** Advertise support for OAuth Client ID Metadata Documents (MCP 2026-07-28). */
  clientIdMetadataDocumentsSupported?: boolean;
}

export function mountDiscovery(
  app: Hono,
  { baseUrl, scopes, clientIdMetadataDocumentsSupported = false }: DiscoveryDeps,
): void {
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
      scopes_supported: scopes.map((s) => s.name),
      resource: `${baseUrl}/mcp`,
      client_id_metadata_document_supported: clientIdMetadataDocumentsSupported,
    });
  });
  // ... (RFC 9728 route unchanged)
```

In `src/config.ts`, add to `McpServerConfig` (~end of interface):

```typescript
  /**
   * Resolve unregistered HTTPS client_ids as OAuth Client ID Metadata Documents instead of
   * requiring Dynamic Client Registration (MCP 2026-07-28; DCR is now deprecated in the spec
   * but still fully supported here). Off by default.
   */
  allowClientIdMetadataDocuments?: boolean;
```

In `src/server.ts`, thread it through:

```typescript
  const provider = createOAuthProvider({
    storage: config.storage,
    scopes: config.scopes,
    baseUrl: config.baseUrl,
    allowClientIdMetadataDocuments: config.allowClientIdMetadataDocuments,
  });

  // ...

  mountDiscovery(app, {
    baseUrl: config.baseUrl,
    scopes: config.scopes,
    clientIdMetadataDocumentsSupported: config.allowClientIdMetadataDocuments,
  });
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/provider.test.ts test/oauth/routes.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oauth/provider.ts src/oauth/discovery.ts src/storage/keys.ts src/config.ts src/server.ts test/oauth/provider.test.ts test/oauth/routes.test.ts
git commit -m "feat(oauth): support Client ID Metadata Documents as a DCR alternative"
```

---

### Task 4: `application_type` on Dynamic Client Registration

**Files:**
- Modify: `src/oauth/provider.ts`
- Modify: `src/oauth/routes.ts`
- Test: `test/oauth/routes.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `OAuthProvider.registerClient` input/output gains `applicationType?: "web" | "native"`.

- [ ] **Step 1: Write the failing tests**

Add to `test/oauth/routes.test.ts`:

```typescript
describe("POST /register — application_type", () => {
  it("accepts and echoes a valid application_type", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app/cb"], application_type: "web" }),
    });
    expect(res.status).toBe(201);
    expect((await res.json()).application_type).toBe("web");
  });

  it("rejects an invalid application_type", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app/cb"], application_type: "desktop" }),
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("invalid_client_metadata");
  });

  it("omits application_type from the response when not supplied", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
    });
    expect((await res.json()).application_type).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run test/oauth/routes.test.ts -t "application_type"`
Expected: FAIL — response has no `application_type` field; the invalid-value request returns 201 instead of 400.

- [ ] **Step 3: Write the implementation**

In `src/oauth/provider.ts`, extend `ClientData` (~line 30-38):

```typescript
interface ClientData {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
  applicationType?: "web" | "native";
  // NOTE: no `scope` field. ...
  createdAt: number;
}
```

Extend the `OAuthProvider.registerClient` signature (~line 84-87):

```typescript
  registerClient(input: {
    redirectUris: string[];
    clientName?: string;
    applicationType?: "web" | "native";
  }): Promise<{
    clientId: string;
    redirectUris: string[];
    createdAt: number;
    applicationType?: "web" | "native";
  }>;
```

Update the implementation (~line 226-240):

```typescript
    async registerClient(input) {
      const clientId = crypto.randomUUID();
      const createdAt = now();
      const redirectUris = input.redirectUris.map((u) => u.toString());
      const clientData: ClientData = {
        clientId,
        redirectUris,
        clientName: input.clientName,
        applicationType: input.applicationType,
        createdAt,
      };
      await storage.put(clientKey(clientId), JSON.stringify(clientData), {
        ttlSeconds: TTL.CLIENT,
      });
      return { clientId, redirectUris, createdAt, applicationType: input.applicationType };
    },
```

In `src/oauth/routes.ts`, in the `POST /register` handler, after the existing redirect-URI validation block (~line 223) and before the `try { const result = await provider.registerClient(...)` call:

```typescript
    // SEP-837 (MCP 2026-07-28 changelog item 8): validate application_type if supplied.
    const applicationType = body.application_type;
    if (
      applicationType !== undefined &&
      applicationType !== "web" &&
      applicationType !== "native"
    ) {
      return c.json(
        oauthError("invalid_client_metadata", 'application_type must be "web" or "native"'),
        400,
      );
    }
```

Update the `provider.registerClient` call and the 201 response body:

```typescript
    try {
      const result = await provider.registerClient({
        redirectUris: parsedUris,
        clientName: typeof body.client_name === "string" ? body.client_name : undefined,
        applicationType: applicationType as "web" | "native" | undefined,
      });
      void fireAudit(hooks, {
        event: "client_registered",
        clientId: result.clientId,
      });
      // RFC 7591 §3.2.1: echo client_id, redirect_uris, client_id_issued_at,
      // and token_endpoint_auth_method in the registration response.
      return c.json(
        {
          client_id: result.clientId,
          client_id_issued_at: Math.floor(result.createdAt / 1000),
          redirect_uris: result.redirectUris,
          token_endpoint_auth_method: "none",
          ...(result.applicationType ? { application_type: result.applicationType } : {}),
        },
        201,
      );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run test/oauth/routes.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oauth/provider.ts src/oauth/routes.ts test/oauth/routes.test.ts
git commit -m "feat(oauth): accept and validate application_type on DCR (SEP-837)"
```

---

### Task 5: `scope` hint on the 401 `WWW-Authenticate` challenge

**Files:**
- Modify: `src/transport.ts`
- Modify: `src/server.ts`
- Test: `test/transport.test.ts` (new)

**Interfaces:**
- Consumes: `McpServerConfig.scopes` (already exists).
- Produces: `McpRequestDeps` gains `defaultScopes: string[]`.

- [ ] **Step 1: Write the failing test**

Create `test/transport.test.ts`:

```typescript
// test/transport.test.ts
import { describe, it, expect } from "vitest";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";

const baseUrl = "https://example.test";

describe("POST /mcp — 401 WWW-Authenticate", () => {
  it("includes a scope attribute listing the default scopes", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [
        { name: "account:read", default: true },
        { name: "account:write" },
      ],
      tools: [],
    });

    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

    expect(res.status).toBe(401);
    const header = res.headers.get("WWW-Authenticate")!;
    expect(header).toContain('resource_metadata="https://example.test/.well-known/oauth-protected-resource"');
    expect(header).toContain('scope="account:read"');
  });

  it("omits the scope attribute when no scopes are configured as default", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read" }],
      tools: [],
    });

    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

    expect(res.headers.get("WWW-Authenticate")).not.toContain("scope=");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run test/transport.test.ts`
Expected: FAIL — `WWW-Authenticate` header has no `scope=` attribute.

- [ ] **Step 3: Write the implementation**

In `src/transport.ts`, extend `McpRequestDeps` (~line 32-42):

```typescript
export interface McpRequestDeps {
  provider: OAuthProvider;
  rateLimiter: RateLimiter;
  storage: KvLike;
  tools: Array<ToolDef | MutatingToolDef>;
  baseUrl: string;
  serverName: string;
  serverVersion: string;
  env: unknown;
  hooks: ObservabilityHooks;
  /** Scopes granted when a client requests none — hinted in the 401 WWW-Authenticate (RFC 6750 §3). */
  defaultScopes: string[];
}
```

Update the `unauthorized` builder (~line 57-64):

```typescript
  // RFC 9728: tell clients where to discover OAuth endpoints on a 401.
  const resourceMetadataUrl = `${deps.baseUrl}/.well-known/oauth-protected-resource`;
  // RFC 6750 §3 / MCP 2026-07-28 Authorization spec: hint the scopes needed so
  // clients don't have to guess before their first authorization attempt.
  const scopeAttr =
    deps.defaultScopes.length > 0 ? `, scope="${deps.defaultScopes.join(" ")}"` : "";
  const wwwAuthenticate = `Bearer resource_metadata="${resourceMetadataUrl}"${scopeAttr}`;
  const unauthorized = () =>
    Response.json(jsonRpcError(JSON_RPC_ERROR.AUTH_REQUIRED, "Authentication required"), {
      status: 401,
      headers: { "WWW-Authenticate": wwwAuthenticate },
    });
```

In `src/server.ts`, pass it through in the `/mcp` handler:

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
      env: undefined,
      hooks,
      defaultScopes: config.scopes.filter((s) => s.default).map((s) => s.name),
    }),
  );
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run test/transport.test.ts && npm test`
Expected: PASS — including the full existing suite (confirms `McpRequestDeps.defaultScopes` being required didn't break another caller; grep for other `handleMcpRequest(` call sites first if any exist outside `server.ts` and update them too).

- [ ] **Step 5: Commit**

```bash
git add src/transport.ts src/server.ts test/transport.test.ts
git commit -m "feat(oauth): hint required scopes in the 401 WWW-Authenticate challenge"
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/how-to-use.md`

**Interfaces:** None — docs only.

- [ ] **Step 1: Update the config reference table**

In `README.md`, add a row to the `## Config reference` table (~line 88-97), after the `ipExtractor` row:

```markdown
| `allowClientIdMetadataDocuments` | `boolean` | No | Resolve unregistered `https://` client_ids as [Client ID Metadata Documents](https://modelcontextprotocol.io/specification/draft/basic/authorization) instead of requiring Dynamic Client Registration. Off by default (see "OAuth / PKCE client flow" below). |
```

- [ ] **Step 2: Update the OAuth flow section**

In `README.md`'s `## OAuth / PKCE client flow` section (~line 266-277), update step 2 and add a note after step 3:

```markdown
2. **Client registration** — either **Dynamic Client Registration**: `POST /register` with `{ "redirect_uris": ["https://your-client/callback"] }` returns a `client_id`; or, if `allowClientIdMetadataDocuments` is enabled, a **Client ID Metadata Document**: use an `https://` URL hosting a `{ client_id, redirect_uris, ... }` JSON document as the `client_id` directly, with no registration call (MCP 2026-07-28 deprecates DCR in favor of this — DCR remains fully supported here).
3. **Authorization** — redirect the user to `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `code_challenge` (S256 PKCE), and optionally `scope`. The built-in identity form collects credentials and calls your `identity.verify`. On success, the server 302-redirects to `redirect_uri?code=<auth_code>&iss=<baseUrl>` (the `iss` parameter, RFC 9207, lets a compliant client detect an authorization-server mix-up before redeeming the code).
```

- [ ] **Step 3: Update the end-to-end curl walkthrough and production checklist**

In `docs/how-to-use.md`, section `## 7. Drive the full OAuth + MCP flow (end to end)`
(~line 188-236), add a note after the closing code fence (after line 233, before the
"In a real MCP client..." line):

```markdown
> **`iss` on the redirect.** Step (c)'s 302 now also carries `&iss=<baseUrl>` (RFC 9207) —
> a compliant client checks this matches the issuer it expects before proceeding, to catch
> an authorization-server mix-up. The `sed` extraction above only pulls `code`, so it's
> unaffected; a real client parses the full redirect URL.

> **Client ID Metadata Documents.** Step (b) shows Dynamic Client Registration. If the
> server has `allowClientIdMetadataDocuments: true`, you can skip registration entirely and
> use an `https://` URL (hosting a `{ client_id, redirect_uris, ... }` JSON document) as
> `CLIENT_ID` directly — see the Config reference in the README.
```

In section `## 9. Going to production — checklist` (~line 252-265), add a checklist item
after the `ipExtractor` item:

```markdown
- [ ] **Decide on `allowClientIdMetadataDocuments`.** Off by default. Turning it on lets
      unregistered HTTPS `client_id`s authorize by hosting a metadata document — an
      outbound-fetch surface at authorization time. Leave it off unless you have clients
      that need it.
```

- [ ] **Step 4: Add a CHANGELOG entry**

In `CHANGELOG.md`, add a new `## [Unreleased]` section above `## [0.1.0] - 2026-06-25`:

```markdown
## [Unreleased]

### Added

- **MCP 2026-07-28 authorization compliance:**
  - `iss` parameter on the authorization-code redirect (RFC 9207).
  - Optional support for [OAuth Client ID Metadata Documents](https://modelcontextprotocol.io/specification/draft/basic/authorization) as an alternative to Dynamic Client Registration, via the new `allowClientIdMetadataDocuments` config option (off by default). DCR remains fully supported — the spec deprecates it with a 12-month minimum window, it does not remove it.
  - `application_type` (`"web" | "native"`) accepted and echoed on `POST /register` (SEP-837).
  - `scope` attribute on the 401 `WWW-Authenticate` challenge, hinting the default scopes.
- Not yet adopted: the MCP TypeScript SDK v2 beta (`@modelcontextprotocol/server`/`@modelcontextprotocol/client`) implementing the non-authorization parts of the 2026-07-28 spec (stateless handshake, `resultType`, `server/discover`, etc.) — see the plan doc for rationale.
```

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md docs/how-to-use.md
git commit -m "docs: record MCP 2026-07-28 authorization compliance"
```

---

### Task 7: Runtime validation — run the server and verify with a live client

Not a code task — no diff for a task reviewer to gate. This is an end-to-end acceptance
check run once, after Task 6, before the final whole-branch review: start a real instance
of the kit and drive it with an actual HTTP client to confirm the OAuth + MCP flow the prior
six tasks touched still works end to end, not just under vitest mocks.

**Files:** None created or modified (unless the check surfaces a bug, in which case: fix it
in the file it lives in, re-run this task from the top, and note the fix in the ledger).

- [ ] **Step 1: Start the server**

Use the existing example server as the runnable instance — it's already wired with an
in-memory store, an identity provider, and a couple of tools (see
`examples/appointments/server.ts` and `run.ts`, and `docs/how-to-use.md` section 3 "Run it
locally"). Run it in the background:

```bash
npx tsx examples/appointments/run.ts &
sleep 1
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq .
```

Expected: JSON metadata including `client_id_metadata_document_supported` (from Task 3) and
`code_challenge_methods_supported: ["S256"]`.

- [ ] **Step 2: Drive the full OAuth + MCP flow from a second, independent process**

The point of this step is a client with no shared code or state with the server — not
another vitest mock. Use the exact `curl` sequence in `docs/how-to-use.md` section 7
(steps a-e: PKCE generation, register, authorize, token exchange, `tools/call`), run from a
plain shell, to confirm:
- the `iss` parameter is present on the step-(c) redirect and equals the server's `baseUrl`
  (Task 1)
- the step-(e) tool call succeeds and returns the expected content

Then additionally exercise what Tasks 3-5 added, from that same external shell:
- **CIMD (Task 3):** re-run step (b)-(e) using a `client_id` that is an `https://` URL
  instead of registering — this requires a second, tiny process serving a static
  `{ "client_id": "<url>", "redirect_uris": [...] }` JSON document (e.g.
  `npx serve` on a temp directory, or `python3 -m http.server`) so the flow has a real
  metadata document to fetch over the network — and confirm the authorization succeeds
  without a prior `/register` call. Requires the running server to have
  `allowClientIdMetadataDocuments: true`; if the example server doesn't set it, start a
  second instance that does (a one-line inline config change is fine for this check, not a
  permanent edit).
- **`application_type` (Task 4):** re-run step (b) with `"application_type": "web"` in the
  body and confirm the 201 response echoes it; retry with `"application_type": "bogus"` and
  confirm a 400.
- **`WWW-Authenticate` scope hint (Task 5):** `curl -i -X POST http://localhost:3000/mcp
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`
  with no `Authorization` header, and confirm the `WWW-Authenticate` response header
  includes a `scope="..."` attribute.

- [ ] **Step 3: Attach a second agent as the verifying client**

Dispatch a fresh subagent (general-purpose, no special tools beyond Bash/curl) with:
the server's base URL, the exact checks from Step 2 above, and instructions to run them
independently and report PASS/FAIL per check with the actual response bodies/headers —
not to trust this plan's predictions. This agent must not read this repo's source or tests
first; it verifies the server's *observable* behavior as an outside HTTP client would, the
same way a real MCP client integration test would. Report back pass/fail per check.

- [ ] **Step 4: Tear down**

```bash
kill %1  # or the PID from Step 1
```

- [ ] **Step 5: Record the result**

Append to the SDD ledger: `Task 7: runtime validation <PASS|FAIL> — <one line per check>`.
Any FAIL routes back into the normal fix flow (resume the relevant task's implementer,
re-review, done) before the final whole-branch review runs.

---

## Explicitly Out of Scope (tracked, not built here)

- **TypeScript SDK v2 migration.** The 2026-07-28 spec's wire-protocol changes (removing the `initialize` handshake, protocol version in `_meta`, the `server/discover` RPC, `subscriptions/listen` replacing SSE resumability, `resultType`, JSON-RPC error-code renumbering) are implemented by `@modelcontextprotocol/server`/`@modelcontextprotocol/client` — new, beta-only packages (`v2`, per the [SDK beta announcement](https://blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/)) that replace `@modelcontextprotocol/sdk` entirely, require Node 20+/ESM-only, and change `.tool()` to `registerTool()` plus a Hono adapter. This kit already runs fully stateless (`sessionIdGenerator: undefined` in `src/transport.ts`), so the session-removal change costs nothing once adopted — but migrating a "production-minded" kit onto a beta dependency is a separate, higher-risk effort that should wait for GA. Revisit when `@modelcontextprotocol/server` ships a stable `1.0.0`.
- **`WWW-Authenticate: error="insufficient_scope"` step-up flow (403).** The spec's Scope Challenge Handling section describes a runtime 403 for a token with insufficient scope. This kit currently enforces scope by silently omitting ungranted tools from `tools/list` rather than erroring on `tools/call` — a different, already-working design (the client never sees a tool it can't call). Adding a 403 flow changes that design decision and is a separate feature, not a compliance gap in the *current* design; revisit only if adopters ask for step-up authorization.
- **Client-side requirements** (`iss` validation, credentials keyed by issuer, `application_type` defaulting on the client) — this kit is the authorization server / resource server, never an MCP client.
- **JSON-RPC error-code renumbering** (changelog item 12) — this kit's custom codes (`METHOD_NOT_ALLOWED: -32000`, `AUTH_REQUIRED: -32001`, `RATE_LIMITED: -32002`) fall in the `-32000`–`-32019` range the new allocation policy leaves implementation-defined/grandfathered; they don't collide with the newly-reserved `-32020`–`-32099` MCP range. No change needed — verified during Task 6, not a separate task.

---

## Self-Review

**Spec coverage:** RFC 9207 `iss` (Task 1) ✓. CIMD / DCR deprecation (Tasks 2-3) ✓. `application_type` / SEP-837 (Task 4) ✓. `WWW-Authenticate` scope hint, RFC 6750 §3 (Task 5) ✓. Docs, including the end-to-end `curl` walkthrough and production checklist (Task 6) ✓. Live, out-of-process verification against a running instance (Task 7) ✓. Client-credentials-by-issuer, insufficient-scope 403, error-code renumbering, and the full SDK v2 wire-protocol rewrite are explicitly logged as out of scope with rationale above, not silently dropped.

**Placeholder scan:** No TBD/TODO markers introduced by this plan (the pre-existing `TODO(fix6)` comment at `transport.ts:123` is untouched — out of scope here). All steps carry runnable code.

**Type consistency:** `ClientIdMetadata` (Task 2) → consumed as `fetchClientIdMetadata(...): Promise<ClientIdMetadata | null>` in Task 3's `resolveClientRedirectUris`. `OAuthProviderConfig.allowClientIdMetadataDocuments` (Task 3) → `McpServerConfig.allowClientIdMetadataDocuments` (Task 3) → threaded through `server.ts` to both `createOAuthProvider` and `mountDiscovery`'s `clientIdMetadataDocumentsSupported`. `applicationType?: "web" | "native"` is consistent across `ClientData`, `registerClient`'s input and return type, and the route handler (Task 4). `McpRequestDeps.defaultScopes` (Task 5) is produced once in `server.ts` and consumed once in `transport.ts` — no other call site of `handleMcpRequest` exists in `src/`, so no other update site is needed (confirm with `grep -rn "handleMcpRequest(" src/` before Task 5 Step 3 in case that's changed since this plan was written).
