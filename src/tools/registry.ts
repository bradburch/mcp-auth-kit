// Tool registry + scope gating.
//
// Registers each configured tool onto a per-request McpServer:
//   - Read tools (no `scope`) always register.
//   - A tool carrying a `scope` registers only when `grantedScopes` includes it.
//   - Mutating tools register a STUB that throws "two-phase not enabled" — the real
//     two-phase preview/confirm wiring lands in Task 9 (this keeps the read path runnable).
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
  for (const tool of tools) {
    if (!isGranted(tool, grantedScopes)) continue;

    const shape = toShape(tool.inputSchema);
    const annotations = tool.annotations ?? {};

    if (isMutating(tool)) {
      // Task 9 replaces this stub with the two-phase preview/confirm handler.
      server.tool(tool.name, tool.description, shape, annotations, async () => {
        throw new Error("two-phase not enabled");
      });
      continue;
    }

    const readTool = tool as ToolDef;
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
}
