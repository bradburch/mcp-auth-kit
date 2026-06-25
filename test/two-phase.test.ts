import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
// reuse the getToken helper pattern from server.read-tools.test.ts (extract to test/helpers.ts during this task)
import { getToken, callTool } from "./helpers.js";

let executed = 0;
function makeApp() {
  executed = 0;
  return createMcpServer({
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
          execute: async () => {
            executed += 1;
            return { content: [{ type: "text", text: "booked" }] };
          },
        },
      },
    ],
  });
}

describe("two-phase confirm", () => {
  it("preview returns a confirmationToken and does NOT execute", async () => {
    const app = makeApp();
    const token = await getToken(app);
    const preview = await callTool(app, token, "book", { slot: "A" });
    expect(JSON.stringify(preview)).toContain("confirmationToken");
    expect(executed).toBe(0);
  });

  it("confirm_request executes exactly once; replay returns cached result", async () => {
    const app = makeApp();
    const token = await getToken(app);
    const preview = await callTool(app, token, "book", { slot: "A" });
    const confirmationToken = /"confirmationToken":"([^"]+)"/.exec(
      JSON.stringify(preview),
    )![1];
    await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-1",
    });
    expect(executed).toBe(1);
    // a token is single-use; replay must come through the idempotency cache, not re-execute
    await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-1",
    });
    expect(executed).toBe(1);
  });
});
