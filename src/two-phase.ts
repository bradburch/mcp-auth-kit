// Two-phase preview → confirm wiring for mutating tools.
//
// A mutating tool never executes its side effect on its own call. Instead:
//   1. Calling the tool runs `preview(input, ctx)`, stores the preview under a single-use
//      `confirmKey(token)` in storage (5-min TTL), and returns the summary + a
//      `confirmationToken`. No side effect happens.
//   2. The caller invokes the ONE shared `confirm_request` tool with that token plus an
//      `idempotencyKey`. confirm_request loads+deletes the token, runs `execute(data, ctx)`,
//      caches the result under the idempotency key (10-min TTL), and fires `hooks.onMutation`.
//
// Idempotency (ported from brad-paws `mcp-server.ts`): KV has no compare-and-swap, so we
// claim the idempotency key with a pending sentinel before executing. A concurrent/retried
// confirm that sees a cached RESULT returns it (no re-exec); one that sees the pending
// sentinel backs off and asks the caller to retry. This NARROWS — but does not fully close —
// the double-execute window; true exactly-once would require a strongly-consistent store
// (e.g. a Durable Object). On execute failure the key is deleted so a legitimate retry re-runs.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MutatingToolDef, ToolContext } from "./config.js";
import { confirmKey, idempotencyKey } from "./storage/keys.js";
import { toShape } from "./tools/shape.js";

/** Confirmation-token TTL — a previewed mutation expires after 5 minutes. */
const CONFIRM_TTL_SECONDS = 300;

/** Idempotency-key TTL — cached confirm results / pending sentinel expire after 10 minutes. */
const IDEMPOTENCY_TTL_SECONDS = 600;

/** Sentinel written to the idempotency key while a confirm is executing. */
const PENDING_SENTINEL = JSON.stringify({ __pending: true });

/** Stored preview payload, keyed by `confirmKey(token)`. */
interface ConfirmPayload {
  toolName: string;
  summary: string;
  data: unknown;
}

/** A tool result with MCP content (what tool handlers must return). */
type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

/** Wrap an arbitrary JSON-serialisable value as a single-text-block tool result. */
function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

/**
 * Register a single mutating tool. Calling it runs `preview`, stashes the result under a
 * single-use confirmation token, and returns the summary + token — no side effect runs here.
 *
 * Annotations default to `destructiveHint: true` unless the tool overrides it.
 */
export function registerMutatingTool(
  server: McpServer,
  tool: MutatingToolDef,
  ctx: ToolContext,
): void {
  const shape = toShape(tool.inputSchema);
  const annotations = { destructiveHint: true, ...(tool.annotations ?? {}) };

  server.registerTool(
    tool.name,
    { description: tool.description, inputSchema: shape, annotations },
    async (input: unknown) => {
      const preview = await tool.mutating.preview(input, ctx);

      const token = crypto.randomUUID();
      const payload: ConfirmPayload = {
        toolName: tool.name,
        summary: preview.summary,
        data: preview.data,
      };
      await ctx.storage.put(confirmKey(token), JSON.stringify(payload), {
        ttlSeconds: CONFIRM_TTL_SECONDS,
      });

      const previewPayload = {
        status: "preview" as const,
        summary: preview.summary,
        confirmationToken: token,
      };
      // Carry the fields both as text (for clients that only read content) and as
      // structuredContent so they surface unescaped at the result's top level.
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(previewPayload) },
        ],
        structuredContent: previewPayload,
      };
    },
  );
}

/** Input schema for the shared confirm_request tool. */
const CONFIRM_INPUT = z.object({
  confirmationToken: z.string(),
  idempotencyKey: z.string(),
});

/**
 * Register the single shared `confirm_request` tool. It loads a previously previewed
 * mutation by its confirmation token and executes it exactly-once-ish under an
 * idempotency key (see file header). `mutatingTools` is the set of mutating tools whose
 * `execute` it dispatches to (matched by the stored `toolName`).
 */
export function registerConfirmTool(
  server: McpServer,
  ctx: ToolContext,
  mutatingTools: MutatingToolDef[],
): void {
  const byName = new Map(mutatingTools.map((t) => [t.name, t]));

  server.registerTool(
    "confirm_request",
    {
      description:
        "Confirm and execute a previously previewed mutating request. " +
        "Requires the confirmationToken from the preview and a unique idempotencyKey.",
      inputSchema: CONFIRM_INPUT.shape,
      annotations: { destructiveHint: true },
    },
    async (input: unknown): Promise<ToolResult> => {
      const { confirmationToken, idempotencyKey: rawKey } = input as z.infer<
        typeof CONFIRM_INPUT
      >;

      const idemKey = idempotencyKey(ctx.userId, rawKey);

      // (a) Idempotency check — return a cached RESULT, or back off on a pending sentinel.
      const cached = await ctx.storage.get(idemKey);
      if (cached !== null) {
        if (cached === PENDING_SENTINEL) {
          return jsonResult({
            success: false,
            error:
              "This request is already being processed — please retry in a moment.",
          });
        }
        // Cached result — replay without re-executing.
        return { content: [{ type: "text", text: cached }] };
      }

      // (b) Claim the key with the pending sentinel, then load + delete the confirm token
      //     (single-use) so a concurrent retry can't reuse it.
      await ctx.storage.put(idemKey, PENDING_SENTINEL, {
        ttlSeconds: IDEMPOTENCY_TTL_SECONDS,
      });

      const cKey = confirmKey(confirmationToken);
      const rawPayload = await ctx.storage.get(cKey);
      if (rawPayload === null) {
        // Expired / invalid / already used — release the claim so a fresh confirm can run.
        await ctx.storage.delete(idemKey);
        return jsonResult({
          success: false,
          error: "This confirmation has expired or was already used.",
        });
      }
      await ctx.storage.delete(cKey);

      let payload: ConfirmPayload;
      try {
        payload = JSON.parse(rawPayload) as ConfirmPayload;
      } catch {
        await ctx.storage.delete(idemKey);
        return jsonResult({
          success: false,
          error: "Invalid confirmation payload.",
        });
      }

      const tool = byName.get(payload.toolName);
      if (!tool) {
        await ctx.storage.delete(idemKey);
        return jsonResult({
          success: false,
          error: `Unknown mutating tool: ${payload.toolName}`,
        });
      }

      // (c)/(d) Execute; on success cache the result and fire the (awaited) mutation hook.
      try {
        const result = (await tool.mutating.execute(
          payload.data,
          ctx,
        )) as ToolResult;
        const resultJson = JSON.stringify(result);

        await ctx.storage.put(idemKey, resultJson, {
          ttlSeconds: IDEMPOTENCY_TTL_SECONDS,
        });

        await ctx.hooks.onMutation?.({
          userId: ctx.userId,
          toolName: payload.toolName,
          summary: payload.summary,
        });

        return result;
      } catch (e) {
        // (e) Execution failed — release the claim so a legitimate retry can re-run.
        await ctx.storage.delete(idemKey);
        throw e;
      }
    },
  );
}
