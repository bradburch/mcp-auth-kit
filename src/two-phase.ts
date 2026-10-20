// Two-phase preview → confirm wiring for mutating tools.
//
// A mutating tool never executes its side effect on its own call. Instead:
//   1. Calling the tool runs `preview(input, ctx)`, stores the preview under a single-use
//      `confirmKey(sha256(token))` in storage (5-min TTL), and returns the summary + a
//      `confirmationToken`. No side effect happens.
//   2. The caller invokes the ONE shared `confirm_request` tool with that token plus an
//      `idempotencyKey`. confirm_request loads+deletes the token, runs `execute(data, ctx)`,
//      caches the result under the idempotency key (10-min TTL), and fires `hooks.onMutation`.
//
// Idempotency: KV has no compare-and-swap, so we
// claim the idempotency key with a pending sentinel before executing. A concurrent/retried
// confirm that sees a cached RESULT returns it (no re-exec); one that sees the pending
// sentinel backs off and asks the caller to retry. Both are bound to the confirmation token
// they were claimed for: the same key arriving with a DIFFERENT token is a client bug (a
// reused key) and gets a conflict error — never another payment's cached result. This NARROWS — but does not fully close —
// the double-execute window; true exactly-once would require a strongly-consistent store
// (e.g. a Durable Object). On execute failure the key is deleted so a legitimate retry re-runs.
import { requireScopes, type McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
  ToolError,
  TOOL_ERROR_BRAND,
  type MutatingToolDef,
  type PreviewResult,
  type ToolContext,
  type ToolErrorPhase,
} from "./config.js";
import { confirmKey, idempotencyKey } from "./storage/keys.js";
import { randomToken, sha256Hex } from "./crypto.js";
import { fireAndForget } from "./http/wait-until.js";

/** Confirmation-token TTL — a previewed mutation expires after 5 minutes. */
const CONFIRM_TTL_SECONDS = 300;

/** Idempotency-key TTL — cached confirm results / pending sentinel expire after 10 minutes. */
const IDEMPOTENCY_TTL_SECONDS = 600;

/**
 * Stored under the idempotency key: a pending claim while a confirm executes, then the
 * cached result. `tokenHash` binds the record to the confirmation it was claimed for.
 */
type IdempotencyRecord =
  { tokenHash: string; pending: true } | { tokenHash: string; result: ToolResult };

/** Stored preview payload, keyed by `confirmKey(sha256(token))`. */
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
 * True for a `ToolError`. The brand check also recognizes a ToolError from a duplicate copy
 * of this package (`Symbol.for` is shared across copies) without trusting any unrelated
 * error that happens to be named so.
 */
function isToolError(error: unknown): boolean {
  try {
    return (
      error instanceof ToolError ||
      (error instanceof Error &&
        (error as unknown as Record<symbol, unknown>)[TOOL_ERROR_BRAND] === true)
    );
  } catch {
    // A hostile error object (throwing Proxy trap / getter) is treated as foreign.
    return false;
  }
}

/** isError result for a thrown error: a `ToolError`'s message verbatim, otherwise generic. */
function toolErrorResult(error?: unknown): ToolResult {
  const text = isToolError(error) ? (error as Error).message : TOOL_ERROR_MESSAGE;
  return { content: [{ type: "text", text }], isError: true };
}

/** Report a tool failure to `onToolError` (fire-and-forget) and return the sanitized result. */
export function toolFailure(
  ctx: ToolContext,
  toolName: string,
  phase: ToolErrorPhase,
  error: unknown,
): ToolResult {
  const expected = isToolError(error);
  fireAndForget(
    () => ctx.hooks.onToolError?.({ userId: ctx.userId, toolName, phase, error, expected }),
    ctx.waitUntil,
  );
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

/** The SDK scope challenge for a scoped tool (undefined for an unscoped one). */
export function scopeChallengeFor(tool: { scope?: string }) {
  return tool.scope === undefined ? undefined : requireScopes(tool.scope);
}

/** Fire onToolCall (fire-and-forget — a misbehaving hook never fails the tool request). */
export function fireToolCall(ctx: ToolContext, toolName: string, input: unknown): void {
  fireAndForget(
    () => ctx.hooks.onToolCall?.({ userId: ctx.userId, toolName, channel: "mcp", input }),
    ctx.waitUntil,
  );
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
  if (isCallToolResult(value)) {
    JSON.stringify(value); // surface an unserializable passthrough here, not in the transport
    return value;
  }
  return { content: [{ type: "text", text: JSON.stringify(value) ?? "null" }] };
}

/** Wrap an arbitrary JSON-serialisable value as a single-text-block tool result. */
function jsonResult(value: unknown, isError = false): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError,
  };
}

/** A confirm that did not execute: `{ success: false, error }` text, flagged `isError`. */
function confirmRefused(error: string): ToolResult {
  return jsonResult({ success: false, error }, true);
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
  const annotations = { destructiveHint: true, ...tool.annotations };

  server.registerTool(
    tool.name,
    {
      description: tool.description,
      inputSchema: tool.inputSchema,
      annotations,
      scopeChallenge: scopeChallengeFor(tool),
    },
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
      await ctx.storage.put(confirmKey(await sha256Hex(token)), JSON.stringify(payload), {
        ttlSeconds: CONFIRM_TTL_SECONDS,
      });

      const previewPayload: PreviewResult = {
        status: "preview",
        summary: preview.summary,
        confirmationToken: token,
      };
      // Carry the fields both as text (for clients that only read content) and as
      // structuredContent so they surface unescaped at the result's top level.
      return {
        content: [{ type: "text" as const, text: JSON.stringify(previewPayload) }],
        structuredContent: { ...previewPayload },
      };
    }),
  );
}

const EXPIRED = "This confirmation has expired or was already used.";

/**
 * Load the previewed mutation behind a confirmation token and consume the token. Returns a
 * refusal message instead when it can't run. Never touches the idempotency claim — the caller
 * releases that in one place.
 */
async function loadConfirmation(
  ctx: ToolContext,
  cKey: string,
  byName: Map<string, MutatingToolDef>,
): Promise<{ tool: MutatingToolDef; payload: ConfirmPayload; rawPayload: string } | string> {
  const rawPayload = await ctx.storage.get(cKey);
  if (rawPayload === null) return EXPIRED; // expired, invalid, or already used

  let payload: ConfirmPayload;
  try {
    payload = JSON.parse(rawPayload) as ConfirmPayload;
  } catch {
    return "Invalid confirmation payload.";
  }

  // Bind the confirmation to the user who previewed it — a leaked token must not let another
  // user execute someone else's previewed mutation. Check ownership BEFORE consuming the
  // single-use token so a wrong-user attempt can't burn the rightful user's token (DoS).
  if (payload.userId !== ctx.userId) return EXPIRED;

  // Ownership confirmed — consume the token (single-use) before executing.
  await ctx.storage.delete(cKey);

  const tool = byName.get(payload.toolName);
  if (!tool) return `Unknown mutating tool: ${payload.toolName}`;
  return { tool, payload, rawPayload };
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
      inputSchema: CONFIRM_INPUT,
      annotations: { destructiveHint: true },
    },
    guarded(ctx, "confirm_request", async (input: unknown): Promise<ToolResult> => {
      const { confirmationToken, idempotencyKey: rawKey } = input as z.infer<typeof CONFIRM_INPUT>;

      const idemKey = idempotencyKey(ctx.userId, rawKey);

      // (a) Idempotency check — return a cached RESULT, or back off on a pending claim.
      const [tokenHash, cached] = await Promise.all([
        sha256Hex(confirmationToken),
        ctx.storage.get(idemKey),
      ]);
      if (cached !== null) {
        // A corrupt entry gets a generic error (a JSON.parse message would echo the stored
        // string back). Deliberately NOT deleted: with no compare-and-swap a delete could wipe
        // a concurrent request's fresh claim/result; the 10-minute TTL clears it.
        let record: IdempotencyRecord;
        try {
          record = JSON.parse(cached) as IdempotencyRecord;
        } catch {
          return toolErrorResult();
        }
        if (record?.tokenHash !== tokenHash) {
          if (typeof record?.tokenHash !== "string") return toolErrorResult();
          return confirmRefused(
            "This idempotencyKey was already used for a different confirmation — use a new key per confirmation.",
          );
        }
        if ("pending" in record) {
          return confirmRefused(
            "This request is already being processed — please retry in a moment.",
          );
        }
        if (isCallToolResult(record.result)) return record.result;
        return toolErrorResult();
      }

      // (b) Claim the key with a pending record, then load + delete the confirm token
      //     (single-use) so a concurrent retry can't reuse it.
      const pending: IdempotencyRecord = { tokenHash, pending: true };
      await ctx.storage.put(idemKey, JSON.stringify(pending), {
        ttlSeconds: IDEMPOTENCY_TTL_SECONDS,
      });

      // Release the claim on any refusal or storage error before execute — nothing ran yet.
      // A storage error then propagates to `guarded` for sanitizing.
      const cKey = confirmKey(tokenHash);
      let loaded: Awaited<ReturnType<typeof loadConfirmation>>;
      try {
        loaded = await loadConfirmation(ctx, cKey, byName);
      } catch (e) {
        await ctx.storage.delete(idemKey).catch(() => {});
        throw e;
      }
      if (typeof loaded === "string") {
        await ctx.storage.delete(idemKey);
        return confirmRefused(loaded);
      }
      const { tool, payload, rawPayload } = loaded;

      // (c) Execute. Only a throw from execute itself counts as failure: restore the consumed
      //     token and release the claim so a legitimate retry (same token + key) can re-run.
      //     ponytail: the restored token gets a fresh 5-minute TTL rather than its remainder.
      let raw: unknown;
      try {
        raw = await tool.mutating.execute(payload.data, ctx);
      } catch (e) {
        await Promise.all([
          ctx.storage.put(cKey, rawPayload, { ttlSeconds: CONFIRM_TTL_SECONDS }).catch(() => {}),
          ctx.storage.delete(idemKey),
        ]);
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
      // Cache the result and run the (awaited) onMutation hook concurrently — independent.
      const done: IdempotencyRecord = { tokenHash, result };
      await Promise.all([
        ctx.storage
          .put(idemKey, JSON.stringify(done), { ttlSeconds: IDEMPOTENCY_TTL_SECONDS })
          // The client still gets its result, so it won't retry; the pending claim expires.
          .catch((e) => void toolFailure(ctx, payload.toolName, "storage", e)),
        Promise.resolve()
          .then(() =>
            ctx.hooks.onMutation?.({
              userId: ctx.userId,
              toolName: payload.toolName,
              summary: payload.summary,
              data: payload.data,
              result,
              idempotencyKey: rawKey,
            }),
          )
          // Swallowed like every hook — the mutation already succeeded.
          .catch(() => {}),
      ]);

      return result;
    }),
  );
}
