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
  ORIGIN_NOT_ALLOWED: -32003,
  HEADER_MISMATCH: -32020, // matches the MCP 2026-07-28 error-code allocation policy
  INSUFFICIENT_SCOPE: -32021, // matches the MCP 2026-07-28 error-code allocation policy
  INTERNAL: -32603,
} as const;

/** Build a JSON-RPC error envelope (id: null — no request id at the transport boundary). */
export function jsonRpcError(code: number, message: string) {
  return { jsonrpc: "2.0" as const, id: null, error: { code, message } };
}

/**
 * MCP 2026-07-28 streamable-http spec: reject a request where `Mcp-Method` (and, for
 * `tools/call`, `Mcp-Name`) don't match the JSON-RPC body — guards against an edge proxy
 * routing/authorizing on the header while the server executes on the body. A request with
 * NO such headers (older clients) is unaffected; only a present-but-mismatched header is
 * rejected. An unparseable body is not rejected here — the SDK transport handles that.
 */
function headerMismatch(req: Request, requestBody: string): boolean {
  const mcpMethod = req.headers.get("Mcp-Method");
  const mcpName = req.headers.get("Mcp-Name");
  if (mcpMethod === null && mcpName === null) return false;

  let parsedRaw: unknown;
  try {
    parsedRaw = JSON.parse(requestBody);
  } catch {
    return false; // let the SDK's own JSON-RPC parse-error handling take over
  }
  // A bare null/array/scalar isn't a JSON-RPC request shape — treat it the same as
  // unparseable and let the SDK transport reject it downstream (mirrors the same guard
  // in oauth/routes.ts's readBodyParsed). Arrays (JSON-RPC batch requests) are explicitly
  // excluded here too: they fall through to normal dispatch, where registry-level scope
  // gating handles each element individually.
  if (parsedRaw === null || Array.isArray(parsedRaw) || typeof parsedRaw !== "object") {
    return false;
  }
  const parsed = parsedRaw as { method?: unknown; params?: { name?: unknown } };

  if (mcpMethod !== null && parsed.method !== mcpMethod) return true;
  if (mcpName !== null && parsed.method === "tools/call" && parsed.params?.name !== mcpName) {
    return true;
  }
  return false;
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
  /**
   * Exact-match allowlist for the `Origin` header — see `McpServerConfig.allowedOrigins`.
   * Optional for backward compatibility with existing low-level callers; omitting it is
   * equivalent to passing `[]` and preserves the secure-by-default behavior (any request
   * carrying an `Origin` header is rejected).
   */
  allowedOrigins?: string[];
}

/**
 * Handle a single MCP `POST /` request: verify the Bearer token, rate-limit by user,
 * build a ToolContext, spin up a fresh McpServer + transport, register the granted tools,
 * and dispatch. Returns a JSON-RPC error Response on auth/rate-limit failure.
 */
export async function handleMcpRequest(req: Request, deps: McpRequestDeps): Promise<Response> {
  // MCP 2026-07-28 streamable-http spec: validate Origin to prevent DNS-rebinding attacks
  // from a malicious webpage against a locally-running server. No Origin header means a
  // non-browser client (the common case) — always allowed. An Origin header present but
  // not in the configured allowlist (default: nothing allowed) is rejected outright.
  const origin = req.headers.get("Origin");
  if (origin !== null && !(deps.allowedOrigins ?? []).includes(origin)) {
    return Response.json(jsonRpcError(JSON_RPC_ERROR.ORIGIN_NOT_ALLOWED, "Origin not allowed"), {
      status: 403,
    });
  }

  // Read the body up front (before anything else could consume the stream), with the
  // 1 MB cap enforced while streaming — a pre-auth DoS guard that never buffers an
  // unbounded chunked body into memory.
  const capped = await readCappedBody(req);
  if (capped instanceof Response) return capped;
  const requestBody = capped;

  if (headerMismatch(req, requestBody)) {
    return Response.json(
      jsonRpcError(
        JSON_RPC_ERROR.HEADER_MISMATCH,
        "Mcp-Method/Mcp-Name header does not match request body",
      ),
      { status: 400 },
    );
  }

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

  // Spec SHOULD: a single (non-batch) tools/call for a tool the caller's scopes don't
  // grant gets the HTTP-level 403 insufficient_scope challenge, in addition to (not
  // instead of) the isError tool result registry.ts already returns — a batch request or
  // any other method falls through to the normal 200 JSON-RPC dispatch, where per-call
  // scope handling in registry.ts still applies.
  let parsedForScopeCheck: { method?: unknown; params?: { name?: unknown } } | null = null;
  try {
    parsedForScopeCheck = JSON.parse(requestBody);
  } catch {
    parsedForScopeCheck = null;
  }
  if (
    parsedForScopeCheck &&
    !Array.isArray(parsedForScopeCheck) &&
    parsedForScopeCheck.method === "tools/call" &&
    typeof parsedForScopeCheck.params?.name === "string"
  ) {
    const calledTool = deps.tools.find((t) => t.name === parsedForScopeCheck!.params!.name);
    if (calledTool?.scope && !auth.scopes.includes(calledTool.scope)) {
      return Response.json(jsonRpcError(JSON_RPC_ERROR.INSUFFICIENT_SCOPE, "Insufficient scope"), {
        status: 403,
        headers: {
          "WWW-Authenticate": `Bearer error="insufficient_scope", scope="${calledTool.scope}", resource_metadata="${resourceMetadataUrl}"`,
        },
      });
    }
  }

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
