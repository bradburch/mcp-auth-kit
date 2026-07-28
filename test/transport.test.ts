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
      scopes: [{ name: "account:read", default: true }, { name: "account:write" }],
      tools: [],
    });

    const res = await app.request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

    expect(res.status).toBe(401);
    const header = res.headers.get("WWW-Authenticate")!;
    expect(header).toContain(
      'resource_metadata="https://example.test/.well-known/oauth-protected-resource"',
    );
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
