// Public factory: assemble an MCP server (OAuth + discovery + tool transport) as a Hono app.
//
// Wires together the pieces built in Tasks 4–7:
//   - OAuth provider (DCR, PKCE, token issuance/rotation)
//   - rate limiter (per-user tool calls, per-IP authorize/token)
//   - discovery endpoints (RFC 8414 / RFC 9728)
//   - OAuth HTTP routes (/register, /authorize, /token, /revoke)
//   - MCP transport at POST /mcp (GET/DELETE → 405, stateless mode)
import { Hono } from "hono";
import type { McpServerConfig } from "./config.js";
import { createOAuthProvider } from "./oauth/provider.js";
import { mountOAuthRoutes } from "./oauth/routes.js";
import { mountDiscovery } from "./oauth/discovery.js";
import { createRateLimiter } from "./rate-limit.js";
import { handleMcpRequest, jsonRpcError, JSON_RPC_ERROR } from "./transport.js";

/** Default server identity reported to MCP clients (override via config.name / config.version). */
const DEFAULT_SERVER_NAME = "mcp-oauth-kit";
// Keep in sync with package.json's "version" — nothing enforces this automatically.
const DEFAULT_SERVER_VERSION = "0.3.0";

/** JSON-RPC error for the GET/DELETE 405 responses (no SSE / sessions in stateless mode). */
function methodNotAllowed(message: string): Response {
  return Response.json(jsonRpcError(JSON_RPC_ERROR.METHOD_NOT_ALLOWED, message), { status: 405 });
}

/** Security-considerations: "All authorization server endpoints MUST be served over HTTPS." */
function assertHttpsBaseUrl(baseUrl: string): void {
  const url = new URL(baseUrl);
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !isLocal) {
    throw new Error(
      `baseUrl must be https:// (got "${baseUrl}") — http is only allowed for localhost/127.0.0.1 during local development.`,
    );
  }
}

/**
 * Catch tool-config mistakes at startup instead of on every request: the SDK throws on a
 * duplicate registration per request, a scope nobody can be granted silently locks a tool,
 * and a schema without an object `.shape` (z.string(), or a wrapper like .transform()) would
 * be advertised in tools/list as an empty object, so clients couldn't know its arguments.
 */
function assertValidTools(config: McpServerConfig): void {
  const declared = new Set(config.scopes.map((s) => s.name));
  const seen = new Set<string>();
  for (const tool of config.tools) {
    if (tool.name === "confirm_request") {
      throw new Error(`Tool name "confirm_request" is reserved for the two-phase confirm flow.`);
    }
    if (seen.has(tool.name)) throw new Error(`Duplicate tool name "${tool.name}".`);
    seen.add(tool.name);
    if (tool.scope !== undefined && !declared.has(tool.scope)) {
      throw new Error(
        `Tool "${tool.name}" requires undeclared scope "${tool.scope}" — add it to config.scopes.`,
      );
    }
    // Duck-typed, not `instanceof z.ZodObject`: the adopter's schema may come from a different
    // zod build (e.g. `zod/v4` under zod@3.25) than the one this module resolves.
    const shape = (tool.inputSchema as { shape?: unknown }).shape;
    if (typeof shape !== "object" || shape === null) {
      throw new Error(
        `Tool "${tool.name}": inputSchema must be a z.object(...) — wrappers like .transform()/.pipe()/.default() (and .refine() under zod 3) hide its shape from tools/list; validate those inside the handler instead.`,
      );
    }
  }
}

/**
 * Build the runnable MCP server as a Hono app. Mounts discovery + OAuth routes and the
 * MCP transport. The caller owns feature-gating (wrap with their own middleware if desired).
 */
export function createMcpServer(config: McpServerConfig): Hono {
  assertHttpsBaseUrl(config.baseUrl);
  assertValidTools(config);

  const app = new Hono();

  const provider = createOAuthProvider({
    storage: config.storage,
    scopes: config.scopes,
    baseUrl: config.baseUrl,
    allowClientIdMetadataDocuments: config.allowClientIdMetadataDocuments,
  });

  const rateLimiter = createRateLimiter({
    storage: config.storage,
    config: config.rateLimits,
  });

  // Discovery (well-known) + OAuth HTTP endpoints.
  mountDiscovery(app, {
    baseUrl: config.baseUrl,
    scopes: config.scopes,
    clientIdMetadataDocumentsSupported: config.allowClientIdMetadataDocuments,
  });
  mountOAuthRoutes(app, {
    provider,
    identity: config.identity,
    baseUrl: config.baseUrl,
    hooks: config.hooks,
    rateLimiter,
    ipExtractor: config.ipExtractor,
  });

  const hooks = config.hooks ?? {};

  // MCP transport — stateless JSON mode.
  app.post("/mcp", (c) =>
    handleMcpRequest(c.req.raw, {
      provider,
      rateLimiter,
      storage: config.storage,
      tools: config.tools,
      baseUrl: config.baseUrl,
      serverName: config.name ?? DEFAULT_SERVER_NAME,
      serverVersion: config.version ?? DEFAULT_SERVER_VERSION,
      env: c.env,
      hooks,
      defaultScopes: config.scopes.filter((s) => s.default).map((s) => s.name),
      allowedOrigins: config.allowedOrigins ?? [],
    }),
  );

  app.get("/mcp", () => methodNotAllowed("Stateless mode — use POST"));
  app.delete("/mcp", () => methodNotAllowed("Stateless mode — no sessions to terminate"));

  return app;
}
