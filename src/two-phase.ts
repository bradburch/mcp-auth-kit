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
// Idempotency: KV has no compare-and-swap, so we
// claim the idempotency key with a pending sentinel before executing. A concurrent/retried
// confirm that sees a cached RESULT returns it (no re-exec); one that sees the pending
// sentinel backs off and asks the caller to retry. This NARROWS — but does not fully close —
// the double-execute window; true exactly-once would require a strongly-consistent store
// (e.g. a Durable Object). On execute failure the key is deleted so a legitimate retry re-runs.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  ToolError,
  TOOL_ERROR_BRAND,
  type MutatingToolDef,
  type ToolContext,
  type ToolErrorPhase,
} from "./config.js";
import { confirmKey, idempotencyKey } from "./storage/keys.js";
import { randomToken } from "./crypto.js";

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
  /** The user who previewed the mutation — only they may confirm it. */
  userId: string;
}

/** A tool result with MCP content (what tool handlers must return). */
type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

/** Generic client-facing message when a tool handler throws — raw errors never reach the client. */
const TOOL_ERROR_MESSAGE = "Tool execution failed. Please try again.";

/**
 * isError result for a thrown error: a `ToolError`'s message verbatim, otherwise generic. The
 * brand check also recognizes a ToolError from a duplicate copy of this package (`Symbol.for`
 * is shared across copies) without trusting any unrelated error that happens to be named so.
 */
function toolErrorResult(error?: unknown): ToolResult {
  const isToolError =
    error instanceof ToolError ||
    (error instanceof Error &&
      (error as unknown as Record<symbol, unknown>)[TOOL_ERROR_BRAND] === true);
  const text = isToolError ? (error as Error).message : TOOL_ERROR_MESSAGE;
  return { content: [{ type: "text", text }], isError: true };
}

/** Report a tool failure to `onToolError` (fire-and-forget) and return the sanitized result. */
export function toolFailure(
  ctx: ToolContext,
  toolName: string,
  phase: ToolErrorPhase,
  error: unknown,
): ToolResult {
  void Promise.resolve()
    .then(() => ctx.hooks.onToolError?.({ userId: ctx.userId, toolName, phase, error }))
    .catch(() => {});
  return toolErrorResult(error);
}

/**
 * Wrap a tool callback so any throw that escapes it — in practice a storage error, since
 * preview/execute failures are handled inline — is sanitized and reported as "storage".
 */
function guarded(ctx: ToolContext, toolName: string, fn: (input: unknown) => Promise<ToolResult>) {
  return async (input: unknown): Promise<ToolResult> => {
    try {
      return await fn(input);
    } catch (e) {
      return toolFailure(ctx, toolName, "storage", e);
    }
  };
}

/** Fire onToolCall (fire-and-forget — a misbehaving hook never fails the tool request). */
export function fireToolCall(ctx: ToolContext, toolName: string, input: unknown): void {
  void Promise.resolve()
    .then(() => ctx.hooks.onToolCall?.({ userId: ctx.userId, toolName, channel: "mcp", input }))
    .catch(() => {});
}

/** True when `value` looks like an MCP CallToolResult (every content item has a string type). */
function isCallToolResult(value: unknown): value is ToolResult {
  const content = (value as { content?: unknown } | null)?.content;
  return (
    Array.isArray(content) &&
    content.every((c) => typeof (c as { type?: unknown } | null)?.type === "string")
  );
}

/**
 * Normalize a handler's return value into an MCP CallToolResult: a string becomes one text
 * block, a CallToolResult passes through, anything else is JSON text. Throws if the value
 * can't be serialized (BigInt, cycles) — callers treat that as a tool failure.
 */
export function toToolResult(value: unknown): ToolResult {
  if (typeof value === "string") return { content: [{ type: "text", text: value }] };
  const result: ToolResult = isCallToolResult(value)
    ? value
    : { content: [{ type: "text", text: JSON.stringify(value) ?? "null" }] };
  JSON.stringify(result); // surface unserializable passthrough values here, not in the transport
  return result;
}

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
  const annotations = { destructiveHint: true, ...(tool.annotations ?? {}) };

  server.registerTool(
    tool.name,
    { description: tool.description, inputSchema: tool.inputSchema, annotations },
    guarded(ctx, tool.name, async (input: unknown) => {
      fireToolCall(ctx, tool.name, input);
      let preview: { summary: string; data: unknown };
      try {
        preview = await tool.mutating.preview(input, ctx);
      } catch (e) {
        return toolFailure(ctx, tool.name, "preview", e);
      }

      const token = randomToken();
      const payload: ConfirmPayload = {
        toolName: tool.name,
        summary: preview.summary,
        data: preview.data,
        userId: ctx.userId,
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
        content: [{ type: "text" as const, text: JSON.stringify(previewPayload) }],
        structuredContent: previewPayload,
      };
    }),
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
    guarded(ctx, "confirm_request", async (input: unknown): Promise<ToolResult> => {
      const { confirmationToken, idempotencyKey: rawKey } = input as z.infer<typeof CONFIRM_INPUT>;

      const idemKey = idempotencyKey(ctx.userId, rawKey);

      // (a) Idempotency check — return a cached RESULT, or back off on a pending sentinel.
      const cached = await ctx.storage.get(idemKey);
      if (cached !== null) {
        if (cached === PENDING_SENTINEL) {
          return jsonResult({
            success: false,
            error: "This request is already being processed — please retry in a moment.",
          });
        }
        // Cached result — replay without re-executing. A corrupt entry gets a generic error
        // (a JSON.parse message would echo the stored string back to the client).
        try {
          const replay: unknown = JSON.parse(cached);
          if (isCallToolResult(replay)) return replay;
        } catch {
          // fall through
        }
        // Deliberately NOT deleted: with no compare-and-swap a delete could wipe a concurrent
        // request's fresh claim/result. A corrupt entry only comes from a broken store; the
        // 10-minute TTL clears it.
        return toolErrorResult();
      }

      // (b) Claim the key with the pending sentinel, then load + delete the confirm token
      //     (single-use) so a concurrent retry can't reuse it.
      await ctx.storage.put(idemKey, PENDING_SENTINEL, {
        ttlSeconds: IDEMPOTENCY_TTL_SECONDS,
      });

      // Anything that throws between the claim and execute (a storage error) releases the
      // claim — nothing ran yet — then propagates to `guarded` for sanitizing.
      let tool: MutatingToolDef | undefined;
      let payload: ConfirmPayload;
      try {
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

        try {
          payload = JSON.parse(rawPayload) as ConfirmPayload;
        } catch {
          await ctx.storage.delete(idemKey);
          return jsonResult({
            success: false,
            error: "Invalid confirmation payload.",
          });
        }

        // Bind the confirmation to the user who previewed it — a leaked token must not let
        // another user execute someone else's previewed mutation. Check ownership BEFORE
        // consuming the single-use token so a wrong-user attempt can't burn the rightful
        // user's token (denial of service).
        if (payload.userId !== ctx.userId) {
          await ctx.storage.delete(idemKey);
          return jsonResult({
            success: false,
            error: "This confirmation has expired or was already used.",
          });
        }

        // Ownership confirmed — consume the token (single-use) before executing.
        await ctx.storage.delete(cKey);

        tool = byName.get(payload.toolName);
        if (!tool) {
          await ctx.storage.delete(idemKey);
          return jsonResult({
            success: false,
            error: `Unknown mutating tool: ${payload.toolName}`,
          });
        }
      } catch (e) {
        await ctx.storage.delete(idemKey).catch(() => {});
        throw e;
      }

      // (c) Execute. Only a throw from execute itself counts as failure: release the claim so
      //     a legitimate retry can re-run.
      let raw: unknown;
      try {
        raw = await tool.mutating.execute(payload.data, ctx);
      } catch (e) {
        await ctx.storage.delete(idemKey);
        return toolFailure(ctx, payload.toolName, "execute", e);
      }

      // (d) The side effect HAS happened — from here on never report failure or release the
      //     claim, or the client's retry would run it twice. An unserializable result is
      //     reported to onToolError and replaced with a generic success.
      let result: ToolResult;
      try {
        result = toToolResult(raw);
      } catch (e) {
        toolFailure(ctx, payload.toolName, "execute", e);
        result = jsonResult({ success: true });
      }
      try {
        await ctx.storage.put(idemKey, JSON.stringify(result), {
          ttlSeconds: IDEMPOTENCY_TTL_SECONDS,
        });
      } catch (e) {
        // The client still gets its result, so it won't retry; the pending sentinel expires.
        toolFailure(ctx, payload.toolName, "storage", e);
      }

      try {
        await ctx.hooks.onMutation?.({
          userId: ctx.userId,
          toolName: payload.toolName,
          summary: payload.summary,
        });
      } catch {
        // Swallowed like every hook — the mutation already succeeded.
      }

      return result;
    }),
  );
}
