// test/scope-gating.test.ts — verify that tool scope gating works end-to-end.
//
// Strategy: drive the real OAuth flow, requesting a specific scope subset, then
// confirm that tools gated on an absent scope are not listed while tools gated
// on a granted scope (or un-gated) appear.
//
// We also test the registry unit directly (registerTools) for the case where
// constructing a narrow-scope token via the HTTP flow would be awkward.
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { registerTools } from "../src/tools/registry.js";
import { getToken } from "./helpers.js";
import type { ToolContext } from "../src/config.js";

const baseUrl = "https://example.test";

// ─── Unit-level scope gating (registerTools) ─────────────────────────────────

/**
 * Spin up a McpServer, register tools with registerTools, and ask for the tool
 * list via JSON-RPC. Returns the list of registered tool names.
 */
async function listRegisteredTools(
  tools: Parameters<typeof registerTools>[1],
  grantedScopes: string[],
): Promise<string[]> {
  const server = new McpServer({ name: "test", version: "0.0.0" });
  const ctx: ToolContext = {
    userId: "u1",
    scopes: grantedScopes,
    storage: createMemoryStorage(),
    env: undefined,
    hooks: {},
  };
  registerTools(server, tools, ctx, grantedScopes);
  // Ask the server's internal registry (the SDK exposes tools as a Map).
  // Access via the public `listTools` capability if available, otherwise inspect.
  // We can ask via the transport — but it's simpler to inspect the names that were
  // registered, since McpServer registers them on a Handler map we can iterate.
  // Simplest approach: use JSON-RPC over WebStandardStreamableHTTPServerTransport.
  const { WebStandardStreamableHTTPServerTransport } =
    await import("@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js");
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);
  const req = new Request("https://test/mcp", {
    method: "POST",
    headers: {
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
  const res = await transport.handleRequest(req, {
    authInfo: { token: "t", clientId: "", scopes: grantedScopes },
  });
  await transport.close();
  await server.close();
  const body = (await res!.json()) as any;
  return (body.result?.tools ?? []).map((t: any) => t.name as string);
}

describe("scope gating (registry unit)", () => {
  const tools = [
    {
      name: "public_tool",
      description: "no scope required",
      inputSchema: z.object({}),
      handler: async () => ({ content: [] }),
    },
    {
      name: "read_tool",
      description: "requires read scope",
      scope: "account:read",
      inputSchema: z.object({}),
      handler: async () => ({ content: [] }),
    },
    {
      name: "write_tool",
      description: "requires write scope",
      scope: "write",
      inputSchema: z.object({}),
      handler: async () => ({ content: [] }),
    },
  ];

  it("all tools appear when all scopes are granted", async () => {
    const names = await listRegisteredTools(tools, ["account:read", "write"]);
    expect(names).toContain("public_tool");
    expect(names).toContain("read_tool");
    expect(names).toContain("write_tool");
  });

  it("scope-gated tool is still listed when its scope is not granted (discovery for step-up auth)", async () => {
    const names = await listRegisteredTools(tools, ["account:read"]);
    expect(names).toContain("public_tool");
    expect(names).toContain("read_tool");
    expect(names).toContain("write_tool"); // "write" not in grantedScopes, but still listed
  });

  it("every tool appears in tools/list regardless of granted scopes", async () => {
    const names = await listRegisteredTools(tools, []); // no scopes at all
    expect(names).toContain("public_tool");
    expect(names).toContain("read_tool");
    expect(names).toContain("write_tool");
  });
});

// ─── Integration: scope-gated mutating tool still listed for a non-write token ─

describe("scope gating (integration via HTTP)", () => {
  it("mutating tool scoped to 'write' is still listed (for discovery) but rejects a call for a 'account:read'-only token", async () => {
    // The helpers.ts getToken always requests default scopes. Build an app where
    // 'write' is NOT default, then getToken will only grant 'account:read'.
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes: [
        { name: "account:read", default: true },
        { name: "write", default: false }, // not default — won't be granted
      ],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      tools: [
        {
          name: "open_tool",
          description: "no scope",
          inputSchema: z.object({}),
          handler: async () => ({ content: [{ type: "text", text: "ok" }] }),
        },
        {
          name: "write_action",
          description: "requires write scope",
          scope: "write",
          inputSchema: z.object({ x: z.string() }),
          mutating: {
            preview: async (input: any) => ({
              summary: `write ${input.x}`,
              data: input,
            }),
            execute: async () => ({
              content: [{ type: "text", text: "done" }],
            }),
          },
        },
      ],
    });

    // getToken requests no explicit scope → falls back to default scopes → "account:read" only.
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
    const names: string[] = body.result.tools.map((t: any) => t.name);
    expect(names).toContain("open_tool");
    expect(names).toContain("write_action"); // listed for discovery, even though ungranted
    // confirm_request also absent (no mutating tools were granted)
    expect(names).not.toContain("confirm_request");

    // Calling the ungranted mutating tool rejects — HTTP-level 403 insufficient_scope
    // (single non-batch tools/call for an ungranted tool), same as a plain read tool.
    const callRes = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "write_action", arguments: { x: "y" } },
      }),
    });
    expect(callRes.status).toBe(403);
    const callWwwAuth = callRes.headers.get("WWW-Authenticate")!;
    expect(callWwwAuth).toContain('error="insufficient_scope"');
    expect(callWwwAuth).toContain('scope="write"');
  });
});

// ─── insufficient_scope 403 step-up flow ───────────────────────────────────

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

  it("gates an ungranted mutating tool called inside a JSON-RPC batch (transport-level 403 only covers a single non-batch call)", async () => {
    // A batch request is an array — the transport-level 403 short-circuit deliberately only
    // fires for a single, non-batch tools/call (a batch mixing granted/ungranted calls can't
    // map cleanly to one HTTP status). This proves the ONLY thing protecting an ungranted
    // mutating tool called via a batch is registerTools's own per-call gating in registry.ts
    // (registerUngrantedMutatingTool) — not the transport-level check.
    const mutatingWriteTool = {
      name: "delete_thing_mutating",
      description: "delete (two-phase)",
      scope: "write",
      inputSchema: z.object({}),
      mutating: {
        preview: async () => ({ summary: "delete the thing", data: {} }),
        execute: async () => ({ content: [{ type: "text" as const, text: "deleted" }] }),
      },
    };
    const app = createMcpServer({
      baseUrl,
      storage: createMemoryStorage(),
      scopes,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "u1" },
      tools: [mutatingWriteTool],
    });
    const token = await getToken(app); // defaults to account:read only — no "write"
    const res = await app.request("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify([
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "delete_thing_mutating", arguments: {} },
        },
      ]),
    });
    // The batch falls through the transport-level 403 check by design — normal 200 dispatch.
    expect(res.status).toBe(200);
    const body = await res.json();
    const bodyText = JSON.stringify(body);
    // The real preview/confirm machinery (two-phase.ts) was never reached — no confirmation
    // token was minted, proving registerUngrantedMutatingTool's immediate-reject handler ran
    // instead of registerMutatingTool's real preview handler.
    expect(bodyText).not.toContain("confirmationToken");
    const rpcResponse = Array.isArray(body) ? body[0] : body;
    expect(rpcResponse.result.isError).toBe(true);
    expect(JSON.stringify(rpcResponse.result)).toContain("write");
  });
});
