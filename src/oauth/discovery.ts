// OAuth discovery endpoints.
// RFC 8414 — Authorization Server Metadata
// RFC 9728 — Protected Resource Metadata
import type { Hono } from "hono";
import type { ScopeConfig } from "../config.js";

export interface DiscoveryDeps {
  baseUrl: string;
  scopes: ScopeConfig[];
}

/**
 * Mount OAuth discovery routes at the well-known paths.
 * Must be called on the root Hono app (or one whose base is the domain root),
 * not on a sub-app mounted under a prefix, because RFC 8414 requires
 * /.well-known/oauth-authorization-server at the domain root.
 */
export function mountDiscovery(
  app: Hono,
  { baseUrl, scopes }: DiscoveryDeps,
): void {
  // RFC 8414 — Authorization Server Metadata
  app.get("/.well-known/oauth-authorization-server", (c) => {
    return c.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      revocation_endpoint: `${baseUrl}/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: scopes.map((s) => s.name),
      resource: `${baseUrl}/mcp`,
    });
  });

  // RFC 9728 — Protected Resource Metadata
  app.get("/.well-known/oauth-protected-resource", (c) => {
    return c.json({
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      bearer_methods_supported: ["header"],
    });
  });
}
