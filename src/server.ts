// Public factory: assemble an MCP server (OAuth + discovery + tool transport) as a Hono app.
//
// Wires together the pieces built in Tasks 4–7:
//   - OAuth provider (DCR, PKCE, token issuance/rotation)
//   - rate limiter (per-user tool calls, per-IP authorize/token)
//   - discovery endpoints (RFC 8414 / RFC 9728)
//   - OAuth HTTP routes (/register, /authorize, /token, /revoke)
//   - MCP transport at POST / (GET/DELETE → 405, stateless mode)
import { Hono } from "hono";
import type { McpServerConfig } from "./config.js";
import { createOAuthProvider } from "./oauth/provider.js";
import { mountOAuthRoutes } from "./oauth/routes.js";
import { mountDiscovery } from "./oauth/discovery.js";
import { createRateLimiter } from "./rate-limit.js";
import { handleMcpRequest } from "./transport.js";

/** Default server identity reported to MCP clients (adopter can't yet override). */
const DEFAULT_SERVER_NAME = "mcp-server-kit";
const DEFAULT_SERVER_VERSION = "0.0.0";

/** JSON-RPC error for the GET/DELETE 405 responses (no SSE / sessions in stateless mode). */
function methodNotAllowed(message: string): Response {
  return Response.json(
    { jsonrpc: "2.0", id: null, error: { code: -32000, message } },
    { status: 405 },
  );
}

/**
 * Build the runnable MCP server as a Hono app. Mounts discovery + OAuth routes and the
 * MCP transport. The caller owns feature-gating (wrap with their own middleware if desired).
 */
export function createMcpServer(config: McpServerConfig): Hono {
  const app = new Hono();

  const provider = createOAuthProvider({
    storage: config.storage,
    scopes: config.scopes,
    baseUrl: config.baseUrl,
  });

  const rateLimiter = createRateLimiter({
    storage: config.storage,
    config: config.rateLimits,
  });

  // Discovery (well-known) + OAuth HTTP endpoints.
  mountDiscovery(app, { baseUrl: config.baseUrl, scopes: config.scopes });
  mountOAuthRoutes(app, {
    provider,
    identity: config.identity,
    baseUrl: config.baseUrl,
  });

  const hooks = config.hooks ?? {};

  // MCP transport — stateless JSON mode.
  app.post("/", (c) =>
    handleMcpRequest(c.req.raw, {
      provider,
      rateLimiter,
      storage: config.storage,
      tools: config.tools,
      baseUrl: config.baseUrl,
      serverName: DEFAULT_SERVER_NAME,
      serverVersion: DEFAULT_SERVER_VERSION,
      env: undefined,
      hooks,
    }),
  );

  app.get("/", () => methodNotAllowed("Stateless mode — use POST"));
  app.delete("/", () =>
    methodNotAllowed("Stateless mode — no sessions to terminate"),
  );

  return app;
}
