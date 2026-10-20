// MCP Streamable HTTP transport handler (stateless).
//
// Built on the v2 SDK's `createMcpHandler`, which serves the 2026-07-28 protocol revision
// (per-request `_meta` envelope, `server/discover`, `resultType`) and falls back to
// stateless 2025-era serving for clients that still `initialize`. The SDK owns the
// protocol-level checks: `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name` header validation
// on 2026-07-28 requests (400 / -32020), the request-body cap (413), Content-Type (415), and
// the per-tool `insufficient_scope` 403 challenge (via each tool's `scopeChallenge`, see
// registry.ts). The kit re-checks `Mcp-Method`/`Mcp-Name` against the body for claim-less
// requests too, since the SDK's legacy fallback doesn't (see `headerMismatch`).
//
// The kit also keeps what's specific to it, in front of the SDK: exact-match Origin validation,
// Bearer verification against its own authorization server (with the default-scope hint in
// the 401 challenge), and per-user rate limiting.
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import type { OAuthProvider } from "./oauth/provider.js";
import type { RateLimiter } from "./rate-limit.js";
import type { KvLike } from "./storage/types.js";
import type { ToolContext, ToolDef, MutatingToolDef, ObservabilityHooks } from "./config.js";
import { registerTools } from "./tools/registry.js";
import { MAX_BODY_BYTES, readCappedBody } from "./http/body-limit.js";
import { secondsUntilHourWindowResets, type WaitUntil } from "./http/wait-until.js";

/** JSON-RPC error codes used by the transport layer. */
export const JSON_RPC_ERROR = {
  METHOD_NOT_ALLOWED: -32000,
  AUTH_REQUIRED: -32001,
  RATE_LIMITED: -32002,
  ORIGIN_NOT_ALLOWED: -32003,
  HEADER_MISMATCH: -32020, // spec HeaderMismatch — same code the SDK uses on the modern path
  INTERNAL: -32603,
} as const;

/** Build a JSON-RPC error envelope (id: null — no request id at the transport boundary). */
export function jsonRpcError(code: number, message: string) {
  return { jsonrpc: "2.0" as const, id: null, error: { code, message } };
}

/**
 * True when a present `Mcp-Method` (or, for `tools/call`, `Mcp-Name`) header doesn't match
 * the JSON-RPC body — guards against an edge proxy routing/authorizing on the header while
 * the server executes the body. The SDK enforces this only for 2026-07-28 (envelope)
 * requests, so the kit keeps it for claim-less ones too. Unparseable bodies, non-objects and
 * batches return false and are left to the SDK.
 */
function headerMismatch(req: Request, body: string): boolean {
  const mcpMethod = req.headers.get("Mcp-Method");
  const mcpName = req.headers.get("Mcp-Name");
  let parsed: { method?: unknown; params?: { name?: unknown } } | null;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
  if (mcpMethod !== null && parsed.method !== mcpMethod) return true;
  return mcpName !== null && parsed.method === "tools/call" && parsed.params?.name !== mcpName;
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
  /**
   * The runtime's `waitUntil` (Workers/edge), so fire-and-forget hooks (`onToolCall`,
   * `onToolError`) aren't cancelled once the response is sent. Omit on Node.
   */
  waitUntil?: WaitUntil;
}

/** Hand each fire-and-forget hook's promise to `waitUntil` (`onMutation` is awaited already). */
function withWaitUntil(hooks: ObservabilityHooks, waitUntil?: WaitUntil): ObservabilityHooks {
  if (!waitUntil) return hooks;
  const keepAlive = <E>(fn?: (event: E) => Promise<void>) =>
    fn &&
    ((event: E) => {
      const p = Promise.resolve().then(() => fn(event));
      waitUntil(p.catch(() => {}));
      return p;
    });
  return {
    ...hooks,
    onToolCall: keepAlive(hooks.onToolCall?.bind(hooks)),
    onToolError: keepAlive(hooks.onToolError?.bind(hooks)),
  };
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
  let auth: Awaited<ReturnType<OAuthProvider["verifyAccessToken"]>>;
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
      // Fixed hourly window: the bucket only refills when the hour rolls over.
      headers: { "Retry-After": String(secondsUntilHourWindowResets()) },
    });
  }

  // Only requests carrying the headers pay for reading a (capped) copy of the body.
  if (req.headers.has("Mcp-Method") || req.headers.has("Mcp-Name")) {
    const body = await readCappedBody(req.clone());
    if (body instanceof Response) return body;
    if (headerMismatch(req, body)) {
      return Response.json(
        jsonRpcError(
          JSON_RPC_ERROR.HEADER_MISMATCH,
          "Mcp-Method/Mcp-Name header does not match request body",
        ),
        { status: 400 },
      );
    }
  }

  // Build the per-request tool context.
  const ctx: ToolContext = {
    userId: auth.userId,
    scopes: auth.scopes,
    storage: deps.storage,
    env: deps.env,
    hooks: withWaitUntil(deps.hooks, deps.waitUntil),
  };

  // ponytail: a handler per request (the factory closes over this request's ctx). Cheap —
  // no subscriptions are served — but hoist it into createMcpServer if profiling says so.
  const handler = createMcpHandler(
    () => {
      const server = new McpServer({ name: deps.serverName, version: deps.serverVersion });
      registerTools(server, deps.tools, ctx, auth.scopes);
      return server;
    },
    { maxRequestBodySize: MAX_BODY_BYTES },
  );
  try {
    return await handler.fetch(req, {
      authInfo: {
        token,
        clientId: auth.clientId,
        scopes: auth.scopes,
        // Lets the SDK's insufficient_scope challenge point clients at discovery (RFC 9728).
        resourceMetadataUrl,
        extra: { userId: auth.userId },
      },
    });
  } finally {
    await handler.close();
  }
}
