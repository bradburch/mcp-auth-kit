// MCP Streamable HTTP transport handler (stateless JSON mode).
//
// Each POST creates a fresh McpServer + WebStandardStreamableHTTPServerTransport
// (sessionIdGenerator: undefined, enableJsonResponse: true) — no sessions, auth is
// per-request via Bearer token. GET/DELETE are 405 (no SSE, no sessions to terminate).
//
// Key subtlety: the request body must be read once up front (before any middleware could
// consume the stream), then a fresh Request is reconstructed from that text so the SDK
// transport can re-read it.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { OAuthProvider } from "./oauth/provider.js";
import type { RateLimiter } from "./rate-limit.js";
import type { KvLike } from "./storage/types.js";
import type { ToolContext, ToolDef, MutatingToolDef, ObservabilityHooks } from "./config.js";
import { registerTools } from "./tools/registry.js";
import { readCappedBody } from "./http/body-limit.js";

/** JSON-RPC error codes used by the transport layer. */
export const JSON_RPC_ERROR = {
  METHOD_NOT_ALLOWED: -32000,
  AUTH_REQUIRED: -32001,
  RATE_LIMITED: -32002,
  INTERNAL: -32603,
} as const;

/** Build a JSON-RPC error envelope (id: null — no request id at the transport boundary). */
export function jsonRpcError(code: number, message: string) {
  return { jsonrpc: "2.0" as const, id: null, error: { code, message } };
}

export interface McpRequestDeps {
  provider: OAuthProvider;
  rateLimiter: RateLimiter;
  storage: KvLike;
  tools: Array<ToolDef | MutatingToolDef>;
  baseUrl: string;
  serverName: string;
  serverVersion: string;
  env: unknown;
  hooks: ObservabilityHooks;
  /** Scopes granted when a client requests none — hinted in the 401 WWW-Authenticate (RFC 6750 §3). */
  defaultScopes: string[];
}

/**
 * Handle a single MCP `POST /` request: verify the Bearer token, rate-limit by user,
 * build a ToolContext, spin up a fresh McpServer + transport, register the granted tools,
 * and dispatch. Returns a JSON-RPC error Response on auth/rate-limit failure.
 */
export async function handleMcpRequest(req: Request, deps: McpRequestDeps): Promise<Response> {
  // Read the body up front (before anything else could consume the stream), with the
  // 1 MB cap enforced while streaming — a pre-auth DoS guard that never buffers an
  // unbounded chunked body into memory.
  const capped = await readCappedBody(req);
  if (capped instanceof Response) return capped;
  const requestBody = capped;

  // RFC 9728: tell clients where to discover OAuth endpoints on a 401.
  const resourceMetadataUrl = `${deps.baseUrl}/.well-known/oauth-protected-resource`;
  // RFC 6750 §3 / MCP 2026-07-28 Authorization spec: hint the scopes needed so
  // clients don't have to guess before their first authorization attempt.
  const scopeAttr =
    deps.defaultScopes.length > 0 ? `, scope="${deps.defaultScopes.join(" ")}"` : "";
  const wwwAuthenticate = `Bearer resource_metadata="${resourceMetadataUrl}"${scopeAttr}`;
  const unauthorized = () =>
    Response.json(jsonRpcError(JSON_RPC_ERROR.AUTH_REQUIRED, "Authentication required"), {
      status: 401,
      headers: { "WWW-Authenticate": wwwAuthenticate },
    });

  // Extract Bearer token.
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return unauthorized();
  }
  const token = authHeader.slice("Bearer ".length);

  // Verify access token.
  let auth: { userId: string; scopes: string[] } | null;
  try {
    auth = await deps.provider.verifyAccessToken(token);
  } catch {
    auth = null;
  }
  if (!auth) {
    return unauthorized();
  }

  // Rate limit by user.
  const allowed = await deps.rateLimiter.checkUser(auth.userId);
  if (!allowed) {
    return Response.json(jsonRpcError(JSON_RPC_ERROR.RATE_LIMITED, "Rate limit exceeded"), {
      status: 429,
      headers: { "Retry-After": "60" },
    });
  }

  // Build the per-request tool context.
  const ctx: ToolContext = {
    userId: auth.userId,
    scopes: auth.scopes,
    storage: deps.storage,
    env: deps.env,
    hooks: deps.hooks,
  };

  // Fresh server + stateless JSON transport for this request.
  const server = new McpServer({
    name: deps.serverName,
    version: deps.serverVersion,
  });
  registerTools(server, deps.tools, ctx, auth.scopes);

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined, // stateless — no sessions
    enableJsonResponse: true,
  });

  await server.connect(transport);

  // Reconstruct the request with the body read above so the transport can re-read it.
  const freshRequest = new Request(req.url, {
    method: "POST",
    headers: req.headers,
    body: requestBody,
  });

  // TODO(fix6): verifyAccessToken currently returns { userId, scopes } only.
  // To thread a real clientId here, update the OAuthProvider interface and the
  // provider implementation to include clientId in the verifyAccessToken return
  // shape — the underlying TokenData already stores it.
  const response = await transport.handleRequest(freshRequest, {
    authInfo: {
      token,
      clientId: "",
      scopes: auth.scopes,
      extra: { userId: auth.userId },
    },
  });

  // JSON mode resolves synchronously — safe to tear down now.
  await transport.close();
  await server.close();

  if (!response) {
    return Response.json(jsonRpcError(JSON_RPC_ERROR.INTERNAL, "No response from transport"), {
      status: 500,
    });
  }
  return response;
}
