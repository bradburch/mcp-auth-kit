// Tool registry + scope gating.
//
// Registers EVERY configured tool onto a per-request McpServer — scope gating happens at
// dispatch time, not at registration time. This is deliberate (MCP 2026-07-28 step-up
// authorization flow): a client must be able to DISCOVER a scope-gated tool via `tools/list`
// before it can know to request the scope for it, so silently omitting ungranted tools from
// the list would make that discovery impossible.
//   - Read tools (no `scope`, or a granted `scope`) delegate straight to their handler.
//   - A read tool whose `scope` the caller lacks still registers, but its handler
//     short-circuits to an `isError` result naming the missing scope (see
//     `insufficientScopeResult`) — see also transport.ts, which additionally returns an
//     HTTP-level 403 `insufficient_scope` challenge for the single-non-batch-call case.
//   - Mutating tools register via `registerMutatingTool` (two-phase preview) when granted, or
//     via `registerUngrantedMutatingTool` (immediate reject) when not; when ANY mutating tool
//     is GRANTED, ONE shared `confirm_request` tool is registered to execute them (see
//     two-phase.ts) — an ungranted mutating tool never reaches the preview phase that would
//     create a token for confirm_request to act on.
//
// The whole Zod object (not its `.shape`) goes to `registerTool`, so refinements on it run
// during the SDK's input validation.
//
// Per-tool error sanitization: if a read tool handler throws (or returns an unserializable
// value), we return a generic isError result — or a ToolError's own message — and report the
// real error to onToolError; the raw message/stack is never forwarded to the client.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { isMutating, type ToolDef, type MutatingToolDef, type ToolContext } from "../config.js";
import {
  registerMutatingTool,
  registerConfirmTool,
  toToolResult,
  toolFailure,
  fireToolCall,
} from "../two-phase.js";

type AnyTool = ToolDef | MutatingToolDef;

/** True when a scoped tool is permitted given the caller's granted scopes. */
function isGranted(tool: AnyTool, grantedScopes: string[]): boolean {
  return tool.scope === undefined || grantedScopes.includes(tool.scope);
}

/** Result returned (as an isError tool result, not a thrown exception) when a caller's
 *  token lacks the scope a tool requires. The tool is still listed in tools/list — see
 *  registerTools's file header — so this path is reachable by a caller who saw the tool. */
function insufficientScopeResult(requiredScope: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: `This tool requires the "${requiredScope}" scope, which your current token does not have.`,
      },
    ],
    isError: true,
  };
}

/**
 * Register EVERY configured tool onto `server`, regardless of `grantedScopes` — scope gating
 * happens at dispatch time (see file header). Mutating tools register via
 * `registerMutatingTool` (two-phase preview → confirm) when granted, or via
 * `registerUngrantedMutatingTool` (a lightweight handler that always rejects) when not;
 * read tools delegate to their handler when granted.
 */
export function registerTools(
  server: McpServer,
  tools: AnyTool[],
  ctx: ToolContext,
  grantedScopes: string[],
): void {
  const grantedMutating: MutatingToolDef[] = [];

  for (const tool of tools) {
    const granted = isGranted(tool, grantedScopes);

    if (isMutating(tool)) {
      if (granted) {
        // Two-phase: the tool call previews; execution happens via confirm_request.
        registerMutatingTool(server, tool, ctx);
        grantedMutating.push(tool);
      } else {
        registerUngrantedMutatingTool(server, tool);
      }
      continue;
    }

    const readTool = tool as ToolDef;

    // Build the per-call handler. The SDK passes the parsed args object as the first
    // argument; we forward it to the tool's handler as-is.
    const cb = async (input: unknown) => {
      if (!granted) {
        // tool.scope is guaranteed defined here — isGranted only returns false when it is.
        return insufficientScopeResult(tool.scope!);
      }
      fireToolCall(ctx, tool.name, input);
      try {
        return toToolResult(await readTool.handler(input, ctx));
      } catch (e) {
        return toolFailure(ctx, tool.name, "handler", e);
      }
    };

    // registerTool uses a config object — no overload ambiguity between an empty
    // shape ({}) and empty annotations ({}). Pass annotations straightforwardly.
    server.registerTool(
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      cb,
    );
  }

  // Register the shared confirm_request tool whenever any mutating tool is GRANTED — an
  // ungranted mutating tool never reaches the preview phase that would create a token for
  // confirm_request to act on, so there's nothing for it to do for a caller with none granted.
  if (grantedMutating.length > 0) {
    registerConfirmTool(server, ctx, grantedMutating);
  }
}

/** Register an ungranted mutating tool with a preview handler that immediately rejects —
 *  it never reaches two-phase.ts's real preview/confirm machinery.
 *
 *  Annotations are built the same way `registerMutatingTool` (two-phase.ts) builds them
 *  (`destructiveHint: true` unless overridden) so a tool's discovery metadata in tools/list
 *  is identical whether or not the caller happens to have the scope — a caller stepping up
 *  from ungranted to granted must not see the tool's annotations change out from under it. */
function registerUngrantedMutatingTool(server: McpServer, tool: MutatingToolDef): void {
  const annotations = { destructiveHint: true, ...(tool.annotations ?? {}) };
  server.registerTool(
    tool.name,
    { description: tool.description, inputSchema: tool.inputSchema, annotations },
    async () => insufficientScopeResult(tool.scope!),
  );
}
