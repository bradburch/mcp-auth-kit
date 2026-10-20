// test/transport.test.ts
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { getToken, mcpRequest, readRpc } from "./helpers.js";

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

describe("POST /mcp — Mcp-Method / Mcp-Name header validation", () => {
  // The SDK validates these headers on 2026-07-28 (envelope-carrying) requests; 2025-era
  // clients don't send them, so legacy traffic is unaffected (see the last two tests).
  const headerApp = () =>
    createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      tools: [
        {
          name: "list_slots",
          description: "list",
          inputSchema: z.object({}),
          handler: async () => ({ content: [{ type: "text", text: "ok" }] }),
        },
      ],
    });

  it("rejects a request whose Mcp-Method header doesn't match the JSON-RPC method", async () => {
    const app = headerApp();
    const token = await getToken(app);
    const res = await mcpRequest(app, token, "tools/list", {}, { "mcp-method": "resources/list" });
    expect(res.status).toBe(400);
    expect((await readRpc(res)).error.code).toBe(-32020);
  });

  it("rejects a tools/call whose Mcp-Name header doesn't match params.name", async () => {
    const app = headerApp();
    const token = await getToken(app);
    const res = await mcpRequest(
      app,
      token,
      "tools/call",
      { name: "list_slots", arguments: {} },
      { "mcp-name": "book_slot" },
    );
    expect(res.status).toBe(400);
    expect((await readRpc(res)).error.code).toBe(-32020);
  });

  it("allows a matching Mcp-Method/Mcp-Name pair through", async () => {
    const app = headerApp();
    const token = await getToken(app);
    const res = await mcpRequest(app, token, "tools/call", { name: "list_slots", arguments: {} });
    expect(res.status).toBe(200);
  });

  it("does not reject a JSON-RPC batch (array body) with HEADER_MISMATCH even when Mcp-Method is present", async () => {
    // A 2025-era batch is served by the SDK's legacy fallback, which doesn't apply the
    // 2026-07-28 header rules — a stray Mcp-Method header must not break it.
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
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
      },
      body: JSON.stringify([
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "list_slots", arguments: {} },
        },
      ]),
    });
    // Falls through to normal 200 dispatch — specifically not a 400 HEADER_MISMATCH.
    expect(res.status).toBe(200);
  });

  it("allows a request with no Mcp-Method/Mcp-Name headers at all (older clients)", async () => {
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
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
