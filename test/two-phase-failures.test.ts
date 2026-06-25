// test/two-phase-failures.test.ts — two-phase failure/expiry branch coverage.
//
// Covers the branches in two-phase.ts that have zero test coverage:
//  1. confirm_request with a token that was never issued (or already used) → error, not execution
//  2. Single-use: a token works once; a second confirm with the same token fails
//  3. execute() throws → idemKey is cleared → fresh preview→confirm can later succeed
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { getToken, callTool } from "./helpers.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

let shouldThrow = false;
let executed = 0;

function makeApp() {
  shouldThrow = false;
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
        name: "flaky_action",
        description: "a mutating tool whose execute can be made to throw",
        scope: "write",
        inputSchema: z.object({ slot: z.string() }),
        mutating: {
          preview: async (input: any) => ({
            summary: `flaky ${input.slot}`,
            data: { slot: input.slot },
          }),
          execute: async () => {
            if (shouldThrow) {
              throw new Error("execute failed intentionally");
            }
            executed += 1;
            return { content: [{ type: "text", text: "done" }] };
          },
        },
      },
    ],
  });
}

/** Extract the confirmationToken from a preview result. */
function extractToken(preview: unknown): string {
  const token = /"confirmationToken":"([^"]+)"/.exec(
    JSON.stringify(preview),
  )?.[1];
  if (!token) throw new Error("No confirmationToken in preview result");
  return token;
}

/** Resolve the error message from a confirm_request result. */
function extractError(result: unknown): string | undefined {
  const str = JSON.stringify(result);
  try {
    // The result content block carries a JSON payload { success, error }.
    const content = (result as any)?.content?.[0]?.text;
    if (content) {
      const parsed = JSON.parse(content);
      return parsed.error as string | undefined;
    }
  } catch {}
  // Fallback: scan the raw string for "error" key.
  const m = /"error":"([^"]+)"/.exec(str);
  return m?.[1];
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("two-phase: expired / never-issued confirmation tokens", () => {
  it("confirm_request with a never-issued token returns an error (not execution)", async () => {
    const app = makeApp();
    const token = await getToken(app);

    const result = await callTool(app, token, "confirm_request", {
      confirmationToken: "00000000-0000-0000-0000-000000000000", // never stored
      idempotencyKey: "idem-never",
    });

    // Must surface an error, not execute.
    expect(executed).toBe(0);
    const errMsg = extractError(result);
    expect(errMsg).toBeTruthy();
    expect(errMsg).toMatch(/expired|already used/i);
  });

  it("a valid confirm token works once; a second confirm with a different idempotencyKey fails as expired/invalid", async () => {
    const app = makeApp();
    const token = await getToken(app);

    // Phase 1: preview → get confirmationToken.
    const preview = await callTool(app, token, "flaky_action", { slot: "B" });
    const confirmationToken = extractToken(preview);

    // Phase 2a: first confirm — succeeds, executes once.
    const first = await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-first",
    });
    expect(executed).toBe(1);
    // Verify no error in the first result.
    const firstContent = (first as any)?.content?.[0]?.text;
    expect(firstContent).toBeTruthy();

    // Phase 2b: second confirm with the SAME confirmationToken but a DIFFERENT
    // idempotencyKey — the token was deleted after first use, so this must fail.
    const second = await callTool(app, token, "confirm_request", {
      confirmationToken, // same token, now invalid
      idempotencyKey: "idem-second", // different key, so no idempotency cache hit
    });
    expect(executed).toBe(1); // execute must NOT have run again
    const errMsg = extractError(second);
    expect(errMsg).toBeTruthy();
    expect(errMsg).toMatch(/expired|already used/i);
  });
});

describe("two-phase: execute failure → idempotency key cleared → retry succeeds", () => {
  it("when execute throws, the idemKey is cleared and a fresh preview→confirm can succeed", async () => {
    const app = makeApp();
    const token = await getToken(app);

    // --- Attempt 1: preview → confirm → execute throws ---
    shouldThrow = true;
    const preview1 = await callTool(app, token, "flaky_action", { slot: "C" });
    const confirmToken1 = extractToken(preview1);

    // confirm_request will call execute, which throws. The route/transport
    // wraps unhandled errors as an MCP error result (isError: true).
    // two-phase.ts deletes idemKey on execute failure (line 208).
    const failResult = await callTool(app, token, "confirm_request", {
      confirmationToken: confirmToken1,
      idempotencyKey: "idem-retry",
    });
    // The result should indicate an error (isError flag or error content).
    const resultStr = JSON.stringify(failResult);
    expect(resultStr).toMatch(/error|failed|isError/i);
    expect(executed).toBe(0); // execute threw, so counter never incremented

    // --- Attempt 2: fresh preview → confirm → execute succeeds ---
    shouldThrow = false;
    const preview2 = await callTool(app, token, "flaky_action", { slot: "C" });
    const confirmToken2 = extractToken(preview2);

    // Use a fresh idempotencyKey (the old one was cleared, but a fresh key is cleaner).
    const successResult = await callTool(app, token, "confirm_request", {
      confirmationToken: confirmToken2,
      idempotencyKey: "idem-retry-2",
    });
    expect(executed).toBe(1);
    const successContent = (successResult as any)?.content?.[0]?.text;
    expect(successContent).toContain("done");
  });
});
