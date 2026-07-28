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
