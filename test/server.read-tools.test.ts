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
    const res = await app.request("/", {
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
    const res = await makeApp().request("/", {
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
