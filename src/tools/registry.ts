// Tool registry + scope gating.
//
// Registers each configured tool onto a per-request McpServer:
//   - Read tools (no `scope`) always register.
//   - A tool carrying a `scope` registers only when `grantedScopes` includes it.
//   - Mutating tools register via `registerMutatingTool` (two-phase preview), and when ANY
//     mutating tool is granted, ONE shared `confirm_request` tool is registered to execute
//     them (see two-phase.ts).
//
// The Zod inputSchema → SDK shape conversion mirrors brad-paws `mcp-server.ts`: the SDK's
// deprecated `tool(name, description, shape, annotations, cb)` overload takes the Zod object's
// `.shape` (a ZodRawShape), not the ZodObject itself.
//
// Per-tool error sanitization: if a read tool handler throws, we catch it here and return a
// generic isError result — the raw error message/stack is never forwarded to the client.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  isMutating,
  type ToolDef,
  type MutatingToolDef,
  type ToolContext,
} from "../config.js";
import { registerMutatingTool, registerConfirmTool } from "../two-phase.js";

type AnyTool = ToolDef | MutatingToolDef;

/** Generic client-facing message when a tool handler throws. */
const TOOL_ERROR_MESSAGE = "Tool execution failed. Please try again.";

/** Extract the SDK-expected ZodRawShape from a tool's Zod object inputSchema. */
function toShape(schema: z.ZodTypeAny): z.ZodRawShape {
  return (schema as z.ZodObject<z.ZodRawShape>).shape;
}

/** True when a scoped tool is permitted given the caller's granted scopes. */
function isGranted(tool: AnyTool, grantedScopes: string[]): boolean {
  return tool.scope === undefined || grantedScopes.includes(tool.scope);
}

/**
 * Fire onToolCall (fire-and-forget — errors are swallowed so a misbehaving
 * hook never fails the tool request).
 */
async function fireToolCall(
  ctx: ToolContext,
  toolName: string,
  input: unknown,
): Promise<void> {
  try {
    await ctx.hooks.onToolCall?.({
      userId: ctx.userId,
      toolName,
      channel: "mcp",
      input,
    });
  } catch {
    // Intentionally swallowed — hook errors must not surface to the client.
  }
}

/**
 * Register the configured tools onto `server`, gated by `grantedScopes`. Mutating tools
 * register a placeholder handler (replaced in Task 9); read tools delegate to their handler.
 */
export function registerTools(
  server: McpServer,
  tools: AnyTool[],
  ctx: ToolContext,
  grantedScopes: string[],
): void {
  const grantedMutating: MutatingToolDef[] = [];

  for (const tool of tools) {
    if (!isGranted(tool, grantedScopes)) continue;

    if (isMutating(tool)) {
      // Two-phase: the tool call previews; execution happens via confirm_request.
      registerMutatingTool(server, tool, ctx);
      grantedMutating.push(tool);
      continue;
    }

    const readTool = tool as ToolDef;
    const shape = toShape(tool.inputSchema);

    // Build the per-call handler (identical logic regardless of annotations).
    const cb = async (input: unknown) => {
      let result: unknown;
      try {
        result = await readTool.handler(input, ctx);
      } catch {
        // Fire hook even on error (best-effort).
        void fireToolCall(ctx, tool.name, input);
        return {
          content: [{ type: "text" as const, text: TOOL_ERROR_MESSAGE }],
          isError: true,
        };
      }
      void fireToolCall(ctx, tool.name, input);
      return result as { content: Array<{ type: "text"; text: string }> };
    };

    // Only pass annotations when the tool explicitly defines them.
    // The SDK's tool() overload resolution uses isZodRawShapeCompat() to distinguish
    // a params shape from a ToolAnnotations object. Both are plain objects, so an
    // empty {} annotations is indistinguishable from an empty {} shape — the callback
    // ends up misbound. Omit the argument entirely when annotations is undefined.
    if (tool.annotations !== undefined) {
      server.tool(tool.name, tool.description, shape, tool.annotations, cb);
    } else {
      server.tool(tool.name, tool.description, shape, cb);
    }
  }

  // Register the ONE shared confirm_request tool whenever any mutating tool is present.
  if (grantedMutating.length > 0) {
    registerConfirmTool(server, ctx, grantedMutating);
  }
}
