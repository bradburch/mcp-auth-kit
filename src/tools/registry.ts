// Tool registry + scope gating.
//
// Registers EVERY configured tool onto a per-request McpServer — scope gating happens at
// dispatch time, not at registration time. This is deliberate (MCP 2026-07-28 step-up
// authorization flow): a client must be able to DISCOVER a scope-gated tool via `tools/list`
// before it can know to request the scope for it, so silently omitting ungranted tools from
// the list would make that discovery impossible.
//   - A scoped tool carries `scopeChallenge: requireScopes(tool.scope)`, so the SDK answers a
//     call from a caller lacking the scope with the spec's HTTP 403 `insufficient_scope`
//     challenge before the handler runs (single calls and legacy batches alike).
//   - Mutating tools register via `registerMutatingTool` (two-phase preview); when ANY
//     mutating tool is GRANTED, ONE shared `confirm_request` tool is registered to execute
//     them (see two-phase.ts) — it only dispatches to granted tools.
//
// The whole Zod object (not its `.shape`) goes to `registerTool`, so refinements on it run
// during the SDK's input validation.
//
// Per-tool error sanitization: if a read tool handler throws (or returns an unserializable
// value), we return a generic isError result — or a ToolError's own message — and report the
// real error to onToolError; the raw message/stack is never forwarded to the client.
import type { McpServer } from "@modelcontextprotocol/server";
import { isMutating, type ToolDef, type MutatingToolDef, type ToolContext } from "../config.js";
import {
  registerMutatingTool,
  registerConfirmTool,
  toToolResult,
  toolFailure,
  fireToolCall,
  scopeChallengeFor,
} from "../two-phase.js";

type AnyTool = ToolDef | MutatingToolDef;

/** True when a scoped tool is permitted given the caller's granted scopes. */
function isGranted(tool: AnyTool, grantedScopes: string[]): boolean {
  return tool.scope === undefined || grantedScopes.includes(tool.scope);
}

/**
 * Register EVERY configured tool onto `server`, regardless of `ctx.scopes` — scope gating
 * happens at dispatch time via each tool's `scopeChallenge` (see file header).
 */
export function registerTools(server: McpServer, tools: AnyTool[], ctx: ToolContext): void {
  const grantedMutating: MutatingToolDef[] = [];

  for (const tool of tools) {
    if (isMutating(tool)) {
      // Two-phase: the tool call previews; execution happens via confirm_request.
      registerMutatingTool(server, tool, ctx);
      if (isGranted(tool, ctx.scopes)) grantedMutating.push(tool);
      continue;
    }

    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
        scopeChallenge: scopeChallengeFor(tool),
      },
      async (input: unknown) => {
        fireToolCall(ctx, tool.name, input);
        try {
          return toToolResult(await tool.handler(input, ctx));
        } catch (e) {
          return toolFailure(ctx, tool.name, "handler", e);
        }
      },
    );
  }

  // Register the shared confirm_request tool whenever any mutating tool is GRANTED — an
  // ungranted mutating tool never reaches the preview phase that would create a token for
  // confirm_request to act on, so there's nothing for it to do for a caller with none granted.
  if (grantedMutating.length > 0) {
    registerConfirmTool(server, ctx, grantedMutating);
  }
}
