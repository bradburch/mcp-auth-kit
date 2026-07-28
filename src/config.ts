import { z } from "zod";
import type { KvLike } from "./storage/types.js";

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
   * success, or null to reject the credentials.
   */
  verify(fields: Record<string, string>): Promise<string | null>;
}

/** Optional async observability callbacks. */
export interface ObservabilityHooks {
  /**
   * Called after every tool invocation. Fire-and-forget — errors are swallowed
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
   * confirm flow (durable side-effect, e.g. an audit-ledger write).
   */
  onMutation?(event: { userId: string; toolName: string; summary: string }): Promise<void>;
}

/** Runtime context passed to every tool handler. */
export interface ToolContext {
  userId: string;
  scopes: string[];
  storage: KvLike;
  /** The Cloudflare Worker env bindings (adopter casts to their own type). */
  env: unknown;
  hooks: ObservabilityHooks;
}

/** A standard (read / non-mutating) tool definition. */
export interface ToolDef {
  name: string;
  description: string;
  inputSchema: z.ZodTypeAny;
  /** OAuth scope required to call this tool (omit = no scope check). */
  scope?: string;
  annotations?: Record<string, unknown>;
  handler(input: unknown, ctx: ToolContext): Promise<unknown>;
}

/** A mutating tool definition using the two-phase preview → execute pattern. */
export interface MutatingToolDef {
  name: string;
  description: string;
  inputSchema: z.ZodTypeAny;
  scope?: string;
  annotations?: Record<string, unknown>;
  mutating: {
    /** Phase 1: validate input and return a human-readable preview. */
    preview(input: unknown, ctx: ToolContext): Promise<{ summary: string; data: unknown }>;
    /** Phase 2: carry out the side effect using the preview data. */
    execute(data: unknown, ctx: ToolContext): Promise<unknown>;
  };
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
  /** Max MCP tool calls per user per hour. Default: 50. */
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
   */
  ipExtractor?: (req: Request) => string;
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
   */
  allowedOrigins?: string[];
}
