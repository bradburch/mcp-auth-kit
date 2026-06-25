// test/security.test.ts — focused tests for security fixes
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { createOAuthProvider } from "../src/oauth/provider.js";
import { createRateLimiter } from "../src/rate-limit.js";
import { mountOAuthRoutes } from "../src/oauth/routes.js";
import { mountDiscovery } from "../src/oauth/discovery.js";
import { renderAuthorizePage } from "../src/identity/page.js";
import { getToken } from "./helpers.js";
import type { IdentityConfig } from "../src/config.js";

const BASE_URL = "https://example.test";
const SCOPES = [{ name: "account:read", default: true }];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeIdentity(): IdentityConfig {
  return {
    fields: [{ name: "email", label: "Email" }],
    verify: async () => "user-1",
  };
}

/**
 * Build a Hono app with OAuth routes and an injected rate limiter for testing.
 * Accepts a custom config to support low-limit rate limiters.
 */
function appWithRateLimiter(ipAuthLimit: number, ipTokenLimit: number) {
  const app = new Hono();
  const storage = createMemoryStorage();
  const now = () => 0; // fixed clock — all requests in the same hour bucket

  const provider = createOAuthProvider({
    storage,
    scopes: SCOPES,
    baseUrl: BASE_URL,
  });
  const rateLimiter = createRateLimiter({
    storage,
    now,
    config: { ipAuthorizePerHour: ipAuthLimit, ipTokenPerHour: ipTokenLimit },
  });

  mountDiscovery(app, { baseUrl: BASE_URL, scopes: SCOPES });
  mountOAuthRoutes(app, {
    provider,
    identity: makeIdentity(),
    baseUrl: BASE_URL,
    rateLimiter,
  });
  return app;
}

// ─── FIX 1: Per-IP rate limiting on /authorize and /token ─────────────────────

describe("IP rate limiting — POST /authorize", () => {
  it("allows up to the limit then returns 429", async () => {
    const app = appWithRateLimiter(2, 100); // limit of 2 for authorize

    const makeAuthorizeRequest = () =>
      app.request("/authorize", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "CF-Connecting-IP": "10.0.0.1",
        },
        body: new URLSearchParams({
          response_type: "code",
          client_id: "test",
          redirect_uri: "https://app/cb",
          code_challenge: "abc",
          code_challenge_method: "S256",
          state: "",
          resource: "",
          scope: "",
          email: "a@b.c",
        }).toString(),
      });

    // First two requests allowed (will fail with auth errors but NOT 429)
    const res1 = await makeAuthorizeRequest();
    expect(res1.status).not.toBe(429);

    const res2 = await makeAuthorizeRequest();
    expect(res2.status).not.toBe(429);

    // Third request hits the limit
    const res3 = await makeAuthorizeRequest();
    expect(res3.status).toBe(429);
    const body3 = await res3.json();
    expect(body3.error).toBe("temporarily_unavailable");
    expect(body3.error_description).toContain("rate limit exceeded");
  });
});

describe("IP rate limiting — POST /token", () => {
  it("allows up to the limit then returns 429 with Cache-Control: no-store", async () => {
    const app = appWithRateLimiter(100, 2); // limit of 2 for token

    const makeTokenRequest = () =>
      app.request("/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "CF-Connecting-IP": "10.0.0.2",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: "fake-code",
          client_id: "fake-client",
          redirect_uri: "https://app/cb",
          code_verifier: "fake-verifier",
        }).toString(),
      });

    // First two requests allowed (will fail with grant errors but NOT 429)
    const res1 = await makeTokenRequest();
    expect(res1.status).not.toBe(429);

    const res2 = await makeTokenRequest();
    expect(res2.status).not.toBe(429);

    // Third request hits the limit
    const res3 = await makeTokenRequest();
    expect(res3.status).toBe(429);
    const body3 = await res3.json();
    expect(body3.error).toBe("temporarily_unavailable");
    // Cache-Control: no-store must still be set on 429 from /token
    expect(res3.headers.get("cache-control")).toContain("no-store");
  });
});

// ─── FIX 5: Body-size cap on POST /mcp ────────────────────────────────────────

describe("body-size cap — POST /mcp", () => {
  it("returns 413 when Content-Length exceeds 1 MB", async () => {
    const app = createMcpServer({
      baseUrl: BASE_URL,
      storage: createMemoryStorage(),
      scopes: SCOPES,
      identity: makeIdentity(),
      tools: [],
    });

    // Obtain a valid token so the 413 is tested before auth, not after
    const token = await getToken(app);

    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "Content-Length": String(2_000_000), // > 1 MB
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      }),
    });

    expect(res.status).toBe(413);
  });
});

// ─── FIX 4: logoUrl scheme validation ─────────────────────────────────────────

describe("logoUrl scheme validation — renderAuthorizePage", () => {
  const baseParams = {
    response_type: "code",
    client_id: "client-1",
    redirect_uri: "https://app/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    state: "",
    resource: "",
    scope: "",
  };

  it("does NOT emit an <img> for a javascript: logoUrl", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: {
        appName: "Test",
        logoUrl: "javascript:alert(1)",
      },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("javascript:");
  });

  it("does NOT emit an <img> for a data: logoUrl", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: {
        appName: "Test",
        logoUrl: "data:text/html,<script>alert(1)</script>",
      },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).not.toContain("<img");
  });

  it("DOES emit an <img> for a valid https: logoUrl", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: {
        appName: "Test",
        logoUrl: "https://example.com/logo.png",
      },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).toContain('<img class="logo" src="https://example.com/logo.png"');
  });

  it("DOES emit an <img> for a valid http: logoUrl", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: {
        appName: "Test",
        logoUrl: "http://localhost/logo.png",
      },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).toContain('<img class="logo" src="http://localhost/logo.png"');
  });
});
