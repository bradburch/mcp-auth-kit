import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { getToken } from "./helpers.js";

function makeApp() {
  return createMcpServer({
    baseUrl: "https://example.test",
    storage: createMemoryStorage(),
    scopes: [{ name: "account:read", default: true }],
    identity: {
      fields: [{ name: "email", label: "Email" }],
      verify: async () => "user-1",
    },
    tools: [
      {
        name: "echo",
        description: "echoes input",
        inputSchema: z.object({ msg: z.string() }),
        annotations: { readOnlyHint: true },
        handler: async (input: any) => ({
          content: [{ type: "text", text: input.msg }],
        }),
      },
    ],
  });
}

describe("createMcpServer read tools", () => {
  it("lists the echo tool for an authenticated caller", async () => {
    const app = makeApp();
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
        method: "tools/list",
        params: {},
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const names = body.result.tools.map((t: any) => t.name);
    expect(names).toContain("echo");
  });

  it("rejects an unauthenticated tool call with 401", async () => {
    const res = await makeApp().request("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      }),
    });
    expect(res.status).toBe(401);
  });
});

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

describe("ToolContext.env", () => {
  it("passes the Hono request's c.env through to tool handlers, not always undefined", async () => {
    const baseUrl = "https://example.test";
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
