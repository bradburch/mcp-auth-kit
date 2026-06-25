// test/hooks.test.ts
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { getToken, callTool } from "./helpers.js";

describe("observability hooks", () => {
  it("fires onToolCall for each invocation", async () => {
    const calls: string[] = [];
    const app = createMcpServer({
      baseUrl: "https://example.test",
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      hooks: {
        onToolCall: async (e) => {
          calls.push(e.toolName);
        },
      },
      tools: [
        {
          name: "echo",
          description: "e",
          inputSchema: z.object({ msg: z.string() }),
          annotations: { readOnlyHint: true },
          handler: async (i: any) => ({
            content: [{ type: "text", text: i.msg }],
          }),
        },
      ],
    });
    const token = await getToken(app);
    await callTool(app, token, "echo", { msg: "hi" });
    expect(calls).toContain("echo");
  });

  it("does not fail the request when a hook throws", async () => {
    const app = createMcpServer({
      baseUrl: "https://example.test",
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      hooks: {
        onToolCall: async () => {
          throw new Error("boom");
        },
      },
      tools: [
        {
          name: "echo",
          description: "e",
          inputSchema: z.object({ msg: z.string() }),
          annotations: { readOnlyHint: true },
          handler: async (i: any) => ({
            content: [{ type: "text", text: i.msg }],
          }),
        },
      ],
    });
    const token = await getToken(app);
    const result = await callTool(app, token, "echo", { msg: "hi" });
    expect(JSON.stringify(result)).toContain("hi");
  });

  it("fires onMutation after confirm_request executes", async () => {
    const mutations: Array<{
      userId: string;
      toolName: string;
      summary: string;
    }> = [];
    const app = createMcpServer({
      baseUrl: "https://example.test",
      storage: createMemoryStorage(),
      scopes: [
        { name: "account:read", default: true },
        { name: "write", default: true },
      ],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      hooks: {
        onMutation: async (e) => {
          mutations.push(e);
        },
      },
      tools: [
        {
          name: "book",
          description: "books a thing",
          scope: "write",
          inputSchema: z.object({ slot: z.string() }),
          mutating: {
            preview: async (input: any) => ({
              summary: `book ${input.slot}`,
              data: { slot: input.slot },
            }),
            execute: async () => ({
              content: [{ type: "text", text: "booked" }],
            }),
          },
        },
      ],
    });
    const token = await getToken(app);
    const preview = await callTool(app, token, "book", { slot: "A" });
    const confirmationToken = /"confirmationToken":"([^"]+)"/.exec(JSON.stringify(preview))![1];
    await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-mut-1",
    });
    expect(mutations).toHaveLength(1);
    expect(mutations[0].toolName).toBe("book");
    expect(mutations[0].userId).toBe("user-1");
  });

  it("sanitizes tool errors — returns isError result, does not leak raw message", async () => {
    const app = createMcpServer({
      baseUrl: "https://example.test",
      storage: createMemoryStorage(),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async () => "user-1",
      },
      tools: [
        {
          name: "explode",
          description: "always throws",
          inputSchema: z.object({}),
          annotations: { readOnlyHint: true },
          handler: async () => {
            throw new Error("secret internal detail");
          },
        },
      ],
    });
    const token = await getToken(app);
    const result = await callTool(app, token, "explode", {});
    const str = JSON.stringify(result);
    expect(str).toContain("isError");
    expect(str).not.toContain("secret internal detail");
  });
});
