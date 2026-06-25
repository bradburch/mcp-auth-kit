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

/** Extract the SDK-expected ZodRawShape from a tool's Zod object inputSchema. */
function toShape(schema: z.ZodTypeAny): z.ZodRawShape {
  return (schema as z.ZodObject<z.ZodRawShape>).shape;
}

/** True when a scoped tool is permitted given the caller's granted scopes. */
function isGranted(tool: AnyTool, grantedScopes: string[]): boolean {
  return tool.scope === undefined || grantedScopes.includes(tool.scope);
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
    const annotations = tool.annotations ?? {};
    server.tool(
      tool.name,
      tool.description,
      shape,
      annotations,
      async (input: unknown) => {
        const result = await readTool.handler(input, ctx);
        return result as { content: Array<{ type: "text"; text: string }> };
      },
    );
  }

  // Register the ONE shared confirm_request tool whenever any mutating tool is present.
  if (grantedMutating.length > 0) {
    registerConfirmTool(server, ctx, grantedMutating);
  }
}
