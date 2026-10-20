import { z } from "zod";
import type { KvLike } from "./storage/types.js";
import type { TokenTtlConfig } from "./oauth/provider.js";
import type { WaitUntil } from "./http/wait-until.js";

/** A single OAuth scope the server advertises. */
export interface ScopeConfig {
  name: string;
  description?: string;
  /** Whether this scope is granted by default when none are requested. */
  default?: boolean;
}

/** A single field shown on the built-in identity login form. */
export interface IdentityField {
  /** HTML input name / key in the submitted record. */
  name: string;
  /** Human-readable label. */
  label: string;
  /** HTML input type (e.g. "text", "password", "email"). */
  type?: string;
  required?: boolean;
}

/** Logo / colour branding for the built-in login UI. */
export interface Branding {
  /** App name shown in the UI heading. */
  appName: string;
  /** URL to a logo image (optional). */
  logoUrl?: string;
  /** Hex accent colour (e.g. "#3b82f6"). */
  accentColor?: string;
}

/** Built-in identity provider config (username/password-style form). */
export interface IdentityConfig {
  fields: IdentityField[];
  branding?: Branding;
  /**
   * Validate submitted field values. Return a stable userId string on
   * success, or null to reject the credentials. Every field value is a string (missing
   * fields arrive as `""`); non-password fields are trimmed.
   *
   * `context` carries the raw request and the trusted client IP (from `ipExtractor`). The
   * kit only rate-limits per IP — use these to add per-account lockout for short codes.
   */
  verify(
    fields: Record<string, string>,
    context: { request: Request; ip: string },
  ): Promise<string | null>;
}

/** Optional async observability callbacks. */
export interface ObservabilityHooks {
  /**
   * Called when a tool is invoked (concurrently with the handler). Fire-and-forget — errors are swallowed
   * so a throwing hook never fails the request.
   */
  onToolCall?(event: {
    userId: string;
    toolName: string;
    channel: "mcp";
    input?: unknown;
  }): Promise<void>;
  /**
   * Called on OAuth lifecycle events (client_registered, token_issued,
   * token_refreshed, token_revoked). Fire-and-forget — errors are swallowed.
   */
  onAudit?(event: {
    event: "client_registered" | "token_issued" | "token_refreshed" | "token_revoked";
    userId?: string;
    clientId?: string;
  }): Promise<void>;
  /**
   * Called after a mutating tool's execute phase succeeds. Awaited by the
   * confirm flow (durable side-effect, e.g. an audit-ledger write). Not called for an
   * idempotent replay — only when `execute` actually ran.
   */
  onMutation?(event: {
    userId: string;
    toolName: string;
    /** The preview's summary — the same text the client saw before confirming. */
    summary: string;
    /** The preview's `data`, as passed to `execute` (after a JSON round-trip). */
    data: unknown;
    /** The tool result returned to the client. */
    result: unknown;
    /** The client's idempotency key for this confirmation. */
    idempotencyKey: string;
  }): Promise<void>;
  /**
   * Called when a tool handler, mutating `preview`, or mutating `execute` throws (or returns
   * a value that can't be serialized), or a storage call in the mutating flow fails. The
   * client only sees a generic message (or a `ToolError`'s message), so this is where the
   * real error surfaces. Fire-and-forget. `phase: "storage"` after `execute` means the side
   * effect DID happen but its result couldn't be cached for idempotent replay.
   */
  onToolError?(event: {
    userId: string;
    toolName: string;
    phase: ToolErrorPhase;
    error: unknown;
    /**
     * True when `error` is a `ToolError` — a deliberate rejection (e.g. "insufficient
     * funds") whose message the client saw, not a failure. Filter on it to keep business
     * rejections out of error alerting.
     */
    expected: boolean;
  }): Promise<void>;
}

/** Where a tool failure happened, as reported to `onToolError`. */
export type ToolErrorPhase = "handler" | "preview" | "execute" | "storage";

/** Global-registry brand, so a ToolError from a duplicate copy of this package still matches. */
export const TOOL_ERROR_BRAND = Symbol.for("mcp-oauth-kit.ToolError");

/**
 * Throw from a handler, `preview`, or `execute` to reject with a message the client sees
 * verbatim (e.g. "09:00 is already booked"). Any other thrown error is replaced with a
 * generic message so internals never leak.
 */
export class ToolError extends Error {
  override name = "ToolError";
  readonly [TOOL_ERROR_BRAND] = true;
}

/**
 * What calling a mutating tool returns (as `structuredContent`, and as JSON text): pass
 * `confirmationToken` to `confirm_request` with a fresh `idempotencyKey` to execute it.
 */
export interface PreviewResult {
  status: "preview";
  summary: string;
  confirmationToken: string;
}

/** Handler input type. `unknown` (not zod 3's `any`) when the schema type isn't known. */
type Input<S extends z.ZodTypeAny> = unknown extends z.infer<S> ? unknown : z.infer<S>;

/** Runtime context passed to every tool handler. */
export interface ToolContext {
  userId: string;
  scopes: string[];
  storage: KvLike;
  /**
   * The Hono request's `c.env` — Cloudflare Worker bindings when deployed there, or
   * whatever your Hono adapter supplies for other runtimes (often `undefined`/empty on
   * Node, Lambda, Vercel unless you've typed your own Hono `Env` generic). Cast to your
   * own type.
   */
  env: unknown;
  hooks: ObservabilityHooks;
  /**
   * The runtime's `waitUntil` on Cloudflare Workers / edge runtimes (undefined on Node): hand
   * it a promise to keep background work alive after the response is sent.
   */
  waitUntil?: WaitUntil;
}

/** A standard (read / non-mutating) tool definition. Wrap in `defineTool` for typed `input`. */
export interface ToolDef<S extends z.ZodTypeAny = z.ZodTypeAny> {
  name: string;
  description: string;
  /**
   * Must be a `z.object(...)` — the MCP tool input schema is always a JSON object. Under zod 4
   * `.refine()` on it is allowed and runs; wrappers like `.transform()` are rejected.
   */
  inputSchema: S;
  /** OAuth scope required to call this tool (omit = no scope check). */
  scope?: string;
  annotations?: Record<string, unknown>;
  /**
   * Return a string (→ one text block), an MCP CallToolResult (`{ content: [...] }`, passed
   * through), or any other JSON-serializable value (→ one JSON text block).
   */
  handler(input: Input<S>, ctx: ToolContext): Promise<unknown>;
}

/** A mutating tool definition using the two-phase preview → execute pattern. */
export interface MutatingToolDef<S extends z.ZodTypeAny = z.ZodTypeAny, D = unknown> {
  name: string;
  description: string;
  /**
   * Must be a `z.object(...)` — the MCP tool input schema is always a JSON object. Under zod 4
   * `.refine()` on it is allowed and runs; wrappers like `.transform()` are rejected.
   */
  inputSchema: S;
  scope?: string;
  annotations?: Record<string, unknown>;
  mutating: {
    /**
     * Phase 1: validate input and return a human-readable preview. `summary` is shown to the
     * client before it confirms and is passed to `onMutation` after — phrase it so it reads
     * either way ("Send $25 to bob"). `data` is stored as JSON: it must be JSON-serializable
     * (no Date/Map/BigInt).
     */
    preview(input: Input<S>, ctx: ToolContext): Promise<{ summary: string; data: D }>;
    /**
     * Phase 2: carry out the side effect using the preview data. Returns like `handler`.
     * Runs up to 5 minutes after `preview` — re-check anything that may have changed since
     * (balances, availability) rather than trusting the preview's checks.
     */
    execute(data: D, ctx: ToolContext): Promise<unknown>;
  };
}

/**
 * Identity helper that infers `input` (from `inputSchema`) and mutating `data` (from
 * `preview`'s return) so handlers need no casts. Same role as FastMCP's `addTool`.
 */
export function defineTool<S extends z.ZodTypeAny>(tool: ToolDef<S>): ToolDef<S>;
export function defineTool<S extends z.ZodTypeAny, D>(
  tool: MutatingToolDef<S, D>,
): MutatingToolDef<S, D>;
export function defineTool(tool: ToolDef | MutatingToolDef) {
  return tool;
}

/** Type guard: true when `t` is a MutatingToolDef. */
export function isMutating(t: ToolDef | MutatingToolDef): t is MutatingToolDef {
  return "mutating" in t;
}

/**
 * Rate-limit thresholds for the three KV buckets.
 * All limits are per-hour. Omit a field to use the default.
 */
export interface RateLimitConfig {
  /**
   * Max authenticated `POST /mcp` requests per user per hour — every request counts
   * (`tools/list`, `server/discover`, and calls refused for scope), not just tool calls.
   * Default: 50.
   */
  userPerHour?: number;
  /** Max OAuth authorize attempts per IP per hour (brute-force guard). Default: 10. */
  ipAuthorizePerHour?: number;
  /** Max token-endpoint requests per IP per hour. Default: 30. */
  ipTokenPerHour?: number;
}

/** Top-level configuration passed to the MCP server factory. */
export interface McpServerConfig {
  /** Public base URL of this server (used to build OAuth redirect URIs). */
  baseUrl: string;
  /** Server name reported to MCP clients in `initialize`. Default: "mcp-oauth-kit". */
  name?: string;
  /** Server version reported to MCP clients in `initialize`. Default: the kit's version. */
  version?: string;
  storage: KvLike;
  scopes: ScopeConfig[];
  identity?: IdentityConfig;
  tools: Array<ToolDef | MutatingToolDef>;
  rateLimits?: RateLimitConfig;
  hooks?: ObservabilityHooks;
  /**
   * Override how the trusted client IP is extracted for per-IP rate limiting.
   * Defaults to CF-Connecting-IP → first hop of X-Forwarded-For. Set this when NOT
   * deployed behind Cloudflare so an attacker can't spoof a header to reset buckets.
   * `env` is the Hono `c.env`; on `@hono/node-server` the peer address is
   * `(env as HttpBindings).incoming.socket.remoteAddress`.
   */
  ipExtractor?: (req: Request, env: unknown) => string;
  /** Override access/refresh token lifetimes (defaults: 1 hour / 90 days). */
  tokenTtl?: TokenTtlConfig;
  /**
   * Resolve unregistered HTTPS client_ids as OAuth Client ID Metadata Documents instead of
   * requiring Dynamic Client Registration (MCP 2026-07-28; DCR is now deprecated in the spec
   * but still fully supported here). Off by default.
   */
  allowClientIdMetadataDocuments?: boolean;
  /**
   * Origins allowed to send `POST /mcp` requests carrying a browser `Origin` header
   * (DNS-rebinding protection, MCP 2026-07-28 streamable-http spec). Requests with NO
   * Origin header (the common case — most MCP clients aren't browsers) are always
   * allowed. A request WITH an Origin header is rejected with 403 unless it exactly
   * matches an entry here — including when this option is omitted entirely, since an
   * unconfigured server has no way to know which origins are legitimate.
   *
   * Entries are compared by exact string match — a configured `https://claude.ai` will
   * NOT match an incoming `Origin: https://claude.ai/` (trailing slash) or a
   * different-cased host. Copy the origin value exactly as the browser sends it.
   */
  allowedOrigins?: string[];
}
