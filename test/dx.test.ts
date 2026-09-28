// FastMCP-style ergonomics: typed handlers via defineTool, plain return values, configurable
// server identity, fail-fast config validation, and sanitized mutating-tool errors.
import { describe, it, expect, expectTypeOf } from "vitest";
import { z } from "zod";
import {
  createMcpServer,
  createMemoryStorage,
  defineTool,
  ToolError,
  type McpServerConfig,
} from "../src/index.js";
import { getToken, callTool } from "./helpers.js";

const base = {
  baseUrl: "https://example.test",
  scopes: [{ name: "write", default: true }],
  identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
} satisfies Partial<McpServerConfig>;

function makeApp(extra: Partial<McpServerConfig> = {}) {
  return createMcpServer({
    ...base,
    storage: createMemoryStorage(),
    tools: [
      defineTool({
        name: "greet",
        description: "greets",
        inputSchema: z.object({ name: z.string() }),
        handler: async ({ name }) => {
          expectTypeOf(name).toEqualTypeOf<string>();
          return `hi ${name}`;
        },
      }),
      defineTool({
        name: "stats",
        description: "returns an object",
        inputSchema: z.object({}),
        handler: async () => ({ count: 2 }),
      }),
      defineTool({
        name: "book",
        description: "books",
        scope: "write",
        inputSchema: z.object({ slot: z.string() }),
        mutating: {
          preview: async ({ slot }) => ({ summary: `book ${slot}`, data: { slot, at: 9 } }),
          execute: async (data) => {
            expectTypeOf(data).toEqualTypeOf<{ slot: string; at: number }>();
            return `booked ${data.slot}@${data.at}`;
          },
        },
      }),
      defineTool({
        name: "explode",
        description: "throws in preview",
        inputSchema: z.object({}),
        mutating: {
          preview: async () => {
            throw new Error("secret db password in message");
          },
          execute: async () => "never",
        },
      }),
      defineTool({
        name: "explode_exec",
        description: "throws in execute",
        inputSchema: z.object({}),
        mutating: {
          preview: async () => ({ summary: "x", data: null }),
          execute: async () => {
            throw new Error("secret stack detail");
          },
        },
      }),
    ],
    ...extra,
  });
}

async function previewToken(
  app: ReturnType<typeof makeApp>,
  token: string,
  name: string,
  args = {},
) {
  const res = (await callTool(app, token, name, args)) as {
    structuredContent: { confirmationToken: string };
  };
  return res.structuredContent.confirmationToken;
}

describe("FastMCP-style DX", () => {
  it("wraps a string return as text content", async () => {
    const app = makeApp();
    const token = await getToken(app);
    expect(await callTool(app, token, "greet", { name: "Ada" })).toEqual({
      content: [{ type: "text", text: "hi Ada" }],
    });
  });

  it("serializes a plain object return as JSON text", async () => {
    const app = makeApp();
    const token = await getToken(app);
    expect(await callTool(app, token, "stats", {})).toEqual({
      content: [{ type: "text", text: '{"count":2}' }],
    });
  });

  it("confirm returns the execute result, and a replay returns the identical result", async () => {
    const app = makeApp();
    const token = await getToken(app);
    const confirmationToken = await previewToken(app, token, "book", { slot: "A" });
    const args = { confirmationToken, idempotencyKey: "k1" };
    const first = await callTool(app, token, "confirm_request", args);
    expect(first).toEqual({ content: [{ type: "text", text: "booked A@9" }] });
    expect(await callTool(app, token, "confirm_request", args)).toEqual(first);
  });

  it("does not leak preview/execute error messages to the client", async () => {
    const app = makeApp();
    const token = await getToken(app);
    const pre = await callTool(app, token, "explode", {});
    expect(pre).toMatchObject({ isError: true });
    expect(JSON.stringify(pre)).not.toContain("secret");

    const confirmationToken = await previewToken(app, token, "explode_exec");
    const exec = await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "k2",
    });
    expect(exec).toMatchObject({ isError: true });
    expect(JSON.stringify(exec)).not.toContain("secret");
  });

  it("reports the configured server name and version on initialize", async () => {
    const app = makeApp({ name: "my-server", version: "9.9.9" });
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
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "t", version: "1" },
        },
      }),
    });
    expect((await res.json()).result.serverInfo).toEqual({ name: "my-server", version: "9.9.9" });
  });
});

describe("config validation fails fast at construction", () => {
  const tool = (name: string, extra: object = {}) => ({
    name,
    description: "d",
    inputSchema: z.object({}),
    handler: async () => "ok",
    ...extra,
  });
  const build = (tools: McpServerConfig["tools"]) =>
    createMcpServer({ ...base, storage: createMemoryStorage(), tools });

  it("rejects duplicate tool names", () => {
    expect(() => build([tool("a"), tool("a")])).toThrow(/duplicate tool name "a"/i);
  });

  it("reserves confirm_request", () => {
    expect(() => build([tool("confirm_request")])).toThrow(/reserved/);
  });

  it("rejects a scope that is not declared in config.scopes", () => {
    expect(() => build([tool("a", { scope: "admin" })])).toThrow(/undeclared scope "admin"/);
  });

  it("rejects a non-object input schema", () => {
    expect(() => build([tool("a", { inputSchema: z.string() })])).toThrow(/z\.object/);
  });

  it("rejects a wrapped object schema (no shape to advertise in tools/list)", () => {
    const wrapped = z.object({ a: z.string() }).transform((v) => v);
    expect(() => build([tool("a", { inputSchema: wrapped })])).toThrow(/z\.object/);
  });
});

describe("review fixes", () => {
  type ErrEvent = { userId: string; toolName: string; phase: string; error: unknown };
  const errors: ErrEvent[] = [];
  const mutations: string[] = [];
  let executed = 0;
  const storage = createMemoryStorage();

  const app = createMcpServer({
    ...base,
    storage,
    hooks: {
      onToolError: async (e) => {
        errors.push(e);
      },
      onMutation: async (e) => {
        mutations.push(e.toolName);
      },
    },
    tools: [
      defineTool({
        name: "bigint",
        description: "returns an unserializable value",
        inputSchema: z.object({}),
        handler: async () => ({ n: 1n }),
      }),
      defineTool({
        name: "domain",
        description: "returns a domain object that happens to have a content array",
        inputSchema: z.object({}),
        handler: async () => ({ id: 1, content: [1, 2] }),
      }),
      defineTool({
        name: "reject",
        description: "throws a user-facing ToolError",
        inputSchema: z.object({}),
        handler: async () => {
          throw new ToolError("slot is full");
        },
      }),
      defineTool({
        name: "refined",
        description: "zod refinement must run",
        inputSchema: z.object({ a: z.string() }).refine((v) => v.a === "ok"),
        handler: async ({ a }) => `got ${a}`,
      }),
      defineTool({
        name: "book_full",
        description: "preview rejects with a reason",
        inputSchema: z.object({}),
        mutating: {
          preview: async () => {
            throw new ToolError("09:00 is already booked");
          },
          execute: async () => "never",
        },
      }),
      defineTool({
        name: "book_bigint",
        description: "side effect succeeds but result is unserializable",
        inputSchema: z.object({}),
        mutating: {
          preview: async () => ({ summary: "b", data: null }),
          execute: async () => {
            executed++;
            return { n: 1n };
          },
        },
      }),
      defineTool({
        name: "book_reject",
        description: "execute rejects with a reason",
        inputSchema: z.object({}),
        mutating: {
          preview: async () => ({ summary: "r", data: null }),
          execute: async () => {
            throw new ToolError("card declined");
          },
        },
      }),
    ],
  });

  const text = (r: unknown) => (r as { content: Array<{ text: string }> }).content[0].text;

  it("sanitizes a handler return that cannot be serialized, and reports it via onToolError", async () => {
    const token = await getToken(app);
    const res = await callTool(app, token, "bigint", {});
    expect(res).toMatchObject({ isError: true });
    expect(text(res)).not.toMatch(/BigInt/);
    expect(errors.at(-1)).toMatchObject({ toolName: "bigint", phase: "handler" });
  });

  it("JSON-serializes an object whose content array is not MCP content", async () => {
    const token = await getToken(app);
    expect(text(await callTool(app, token, "domain", {}))).toBe('{"id":1,"content":[1,2]}');
  });

  it("forwards a ToolError message from handler, preview, and execute", async () => {
    const token = await getToken(app);
    expect(await callTool(app, token, "reject", {})).toMatchObject({ isError: true });
    expect(text(await callTool(app, token, "reject", {}))).toBe("slot is full");
    expect(text(await callTool(app, token, "book_full", {}))).toBe("09:00 is already booked");
    const confirmationToken = await previewToken(app, token, "book_reject");
    const res = await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "rej",
    });
    expect(res).toMatchObject({ isError: true });
    expect(text(res)).toBe("card declined");
    expect(errors.at(-1)).toMatchObject({ toolName: "book_reject", phase: "execute" });
  });

  it("runs zod refinements on the input schema", async () => {
    const token = await getToken(app);
    expect(text(await callTool(app, token, "refined", { a: "ok" }))).toBe("got ok");
    expect(await callTool(app, token, "refined", { a: "bad" })).toMatchObject({ isError: true });
  });

  it("treats a completed side effect with an unserializable result as success (no re-execute)", async () => {
    const token = await getToken(app);
    const confirmationToken = await previewToken(app, token, "book_bigint");
    const args = { confirmationToken, idempotencyKey: "big" };
    const first = await callTool(app, token, "confirm_request", args);
    expect(first).not.toMatchObject({ isError: true });
    expect(mutations).toContain("book_bigint");
    expect(await callTool(app, token, "confirm_request", args)).toEqual(first);
    expect(executed).toBe(1);
  });

  it("returns a generic error when a cached idempotent result is corrupt", async () => {
    const token = await getToken(app);
    await storage.put("mcp:idempotent:user-1:corrupt", "not json {", { ttlSeconds: 60 });
    const res = await callTool(app, token, "confirm_request", {
      confirmationToken: "x",
      idempotencyKey: "corrupt",
    });
    expect(res).toMatchObject({ isError: true });
    expect(text(res)).not.toMatch(/JSON|not json/);
  });
});
