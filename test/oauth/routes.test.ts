// test/oauth/routes.test.ts
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createMemoryStorage } from "../../src/storage/memory.js";
import { createOAuthProvider } from "../../src/oauth/provider.js";
import { mountOAuthRoutes } from "../../src/oauth/routes.js";
import { mountDiscovery } from "../../src/oauth/discovery.js";
import { pkce } from "../helpers.js";

const scopes = [{ name: "account:read", default: true }];
const baseUrl = "https://example.test";

function appUnderTest() {
  const app = new Hono();
  const provider = createOAuthProvider({
    storage: createMemoryStorage(),
    scopes,
    baseUrl,
  });
  mountDiscovery(app, { baseUrl, scopes });
  mountOAuthRoutes(app, { provider, baseUrl });
  return app;
}

describe("oauth routes", () => {
  it("advertises S256 in discovery metadata", async () => {
    const res = await appUnderTest().request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("registers a client via POST /register", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["https://app/cb"],
        client_name: "x",
      }),
    });
    expect(res.status).toBe(201);
    expect((await res.json()).client_id).toBeTruthy();
  });

  it("sets Cache-Control no-store on /token errors", async () => {
    const res = await appUnderTest().request("/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code",
    });
    expect(res.headers.get("cache-control")).toContain("no-store");
  });

  // ─── RFC 7591 — DCR response shape (R1) ────────────────────────────────────

  it("DCR 201 response includes client_id_issued_at, redirect_uris, token_endpoint_auth_method", async () => {
    const redirectUris = ["https://app/cb", "https://app/cb2"];
    const before = Math.floor(Date.now() / 1000);
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: redirectUris }),
    });
    const after = Math.floor(Date.now() / 1000);
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(typeof body.client_id).toBe("string");
    expect(body.redirect_uris).toEqual(redirectUris);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(typeof body.client_id_issued_at).toBe("number");
    expect(body.client_id_issued_at).toBeGreaterThanOrEqual(before);
    expect(body.client_id_issued_at).toBeLessThanOrEqual(after);
  });

  // ─── RFC 7591 — redirect-uri validation error codes (R2) ───────────────────

  it("returns invalid_redirect_uri when a redirect URI contains a fragment", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["https://app/cb#fragment"],
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_redirect_uri");
  });

  it("returns invalid_redirect_uri for a bad scheme (ftp:)", async () => {
    const res = await appUnderTest().request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["ftp://app/cb"],
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_redirect_uri");
  });

  // ─── RFC 8414 — scopes_supported in AS metadata (R3) ──────────────────────

  it("discovery AS metadata includes scopes_supported with configured scope names", async () => {
    const res = await appUnderTest().request("/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.scopes_supported).toEqual(["account:read"]);
  });
});

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
    // Assert on the new redirect-notice element specifically, not just any occurrence of
    // the hostname (which also appears — trivially — in the pre-existing hidden
    // redirect_uri input's value attribute).
    expect(html).toContain('class="redirect-notice"');
    expect(html).toContain("<strong>app.example.com</strong>");
  });

  it("HTML-escapes the displayed hostname (regression: dropping escapeHtml must fail this)", async () => {
    // `&` is not rejected or percent-encoded by WHATWG URL host parsing — it survives
    // verbatim into `url.hostname` — and survives encodeURIComponent/query-string
    // transport unchanged too, so it's a real, reachable payload for this code path
    // (verified: `new URL("https://app&x.example.com/cb").hostname === "app&x.example.com"`).
    // `<` and `>` are rejected outright by URL host parsing (Invalid URL), so they can't
    // reach this code path — `&` is the reachable HTML-metacharacter proof that
    // escapeHtml() is actually being applied to redirectHostname.
    const app = new Hono();
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });
    mountOAuthRoutes(app, {
      provider,
      baseUrl,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
    });
    const redirectUri = "https://app&x.example.com/cb";
    const { client_id } = await (
      await app.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: [redirectUri] }),
      })
    ).json();

    const res = await app.request(
      `/authorize?response_type=code&client_id=${client_id}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=x&code_challenge_method=S256`,
    );
    const html = await res.text();
    expect(html).toContain(
      'class="redirect-notice">Signing in to: <strong>app&amp;x.example.com</strong></div>',
    );
    // The unescaped raw form must never appear inside the notice text.
    expect(html).not.toContain("<strong>app&x.example.com</strong>");
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

describe("OAuth error mapping on /token and /revoke", () => {
  const RESOURCE = `${baseUrl}/mcp`;

  async function setup(
    provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl }),
  ) {
    const app = new Hono();
    mountOAuthRoutes(app, { provider, baseUrl });
    const { clientId } = await provider.registerClient({ redirectUris: ["https://app/cb"] });
    const { challenge, verifier } = await pkce();
    const { code } = await provider.issueAuthCode({
      clientId,
      redirectUri: "https://app/cb",
      codeChallenge: challenge,
      scope: [],
      userId: "u",
      resource: RESOURCE,
    });
    const token = (fields: Record<string, string>) =>
      app.request("/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: clientId,
          redirect_uri: "https://app/cb",
          code_verifier: verifier,
          resource: RESOURCE,
          ...fields,
        }).toString(),
      });
    return { app, clientId, token };
  }

  const errorOf = async (res: Response) => [res.status, (await res.json()).error];

  it("maps each provider failure to its OAuth code and status", async () => {
    expect(await errorOf(await (await setup()).token({ code: "nope" }))).toEqual([
      400,
      "invalid_grant",
    ]);
    expect(await errorOf(await (await setup()).token({ client_id: "other" }))).toEqual([
      401,
      "invalid_client",
    ]);
    expect(await errorOf(await (await setup()).token({ resource: "https://x/mcp" }))).toEqual([
      400,
      "invalid_target",
    ]);
    expect(await errorOf(await (await setup()).token({ code_verifier: "w".repeat(43) }))).toEqual([
      400,
      "invalid_grant",
    ]);
  });

  it("maps a refresh by the wrong client to 401 invalid_client, and revoke to unauthorized_client", async () => {
    const { app, token } = await setup();
    const { refresh_token } = await (await token({})).json();
    const refresh = await app.request("/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token,
        client_id: "other",
      }).toString(),
    });
    expect(await errorOf(refresh)).toEqual([401, "invalid_client"]);
    const revoke = await app.request("/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refresh_token, client_id: "other" }).toString(),
    });
    expect(revoke.status).toBe(401);
    expect(await revoke.json()).toEqual({
      error: "unauthorized_client",
      error_description: "Token was issued to a different client",
    });
  });

  it("maps a custom provider's plain Error to invalid_grant", async () => {
    const base = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });
    const { token } = await setup({
      ...base,
      exchangeCode: async () => {
        throw new Error("backend says no");
      },
    });
    const res = await token({});
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "invalid_grant",
      error_description: "backend says no",
    });
  });
});
