// test/oauth/routes.test.ts
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createMemoryStorage } from "../../src/storage/memory.js";
import { createOAuthProvider } from "../../src/oauth/provider.js";
import { mountOAuthRoutes, mountDiscovery } from "../../src/oauth/routes.js";

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
    const res = await appUnderTest().request(
      "/.well-known/oauth-authorization-server",
    );
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
});
