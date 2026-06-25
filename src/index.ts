// Public API surface for mcp-server-kit.
export const version = "0.0.0";

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
