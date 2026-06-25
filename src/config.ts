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
  /** Called after every tool invocation with outcome metadata. */
  onAudit?(event: {
    userId: string;
    tool: string;
    success: boolean;
    durationMs: number;
  }): Promise<void>;
  /** Called before a tool handler runs. */
  onToolCall?(event: {
    userId: string;
    tool: string;
    input: unknown;
  }): Promise<void>;
  /** Called before a mutating tool's execute phase runs. */
  onMutation?(event: {
    userId: string;
    tool: string;
    preview: { summary: string; data: unknown };
  }): Promise<void>;
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
    preview(
      input: unknown,
      ctx: ToolContext,
    ): Promise<{ summary: string; data: unknown }>;
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
}
