// Public API surface for mcp-oauth-kit.

// ─── Primary API ─────────────────────────────────────────────────────────────
// Use these for building a standard MCP server with OAuth out of the box.

export { createMcpServer } from "./server.js";

// Storage adapters.
export { createMemoryStorage } from "./storage/memory.js";
export { createCloudflareKvStorage } from "./storage/kv-cloudflare.js";
export type { KVNamespaceLike } from "./storage/kv-cloudflare.js";
export type { KvLike } from "./storage/types.js";

// Two-phase preview/confirm helpers.
export { registerMutatingTool, registerConfirmTool } from "./two-phase.js";

// Built-in identity authorize page.
export { renderAuthorizePage } from "./identity/page.js";
export type { AuthorizePageParams } from "./identity/page.js";

// Config types + helpers.
export { isMutating } from "./config.js";
export type {
  McpServerConfig,
  ScopeConfig,
  IdentityField,
  IdentityConfig,
  Branding,
  ObservabilityHooks,
  ToolContext,
  ToolDef,
  MutatingToolDef,
  RateLimitConfig,
} from "./config.js";

// ─── Advanced / low-level API ─────────────────────────────────────────────────
// For adopters who need to compose their own Hono app (custom middleware,
// sub-path mounting, etc.) rather than using createMcpServer directly.

export { createOAuthProvider } from "./oauth/provider.js";
export type { OAuthProvider, OAuthProviderConfig, TokenPair } from "./oauth/provider.js";

export { mountOAuthRoutes } from "./oauth/routes.js";
export type { OAuthRouteDeps } from "./oauth/routes.js";

export { mountDiscovery } from "./oauth/discovery.js";
export type { DiscoveryDeps } from "./oauth/discovery.js";

export { createRateLimiter } from "./rate-limit.js";
export type { RateLimiter } from "./rate-limit.js";

export { handleMcpRequest } from "./transport.js";
export type { McpRequestDeps } from "./transport.js";
