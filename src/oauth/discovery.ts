// OAuth discovery endpoints.
// RFC 8414 — Authorization Server Metadata
// RFC 9728 — Protected Resource Metadata
import type { Context, Hono } from "hono";
import type { ScopeConfig } from "../config.js";

export interface DiscoveryDeps {
  baseUrl: string;
  scopes: ScopeConfig[];
  /** Advertise support for OAuth Client ID Metadata Documents (MCP 2026-07-28). */
  clientIdMetadataDocumentsSupported?: boolean;
}

/**
 * Mount OAuth discovery routes at the well-known paths.
 * Must be called on the root Hono app (or one whose base is the domain root),
 * not on a sub-app mounted under a prefix, because RFC 8414 requires
 * /.well-known/oauth-authorization-server at the domain root.
 */
export function mountDiscovery(
  app: Hono,
  { baseUrl, scopes, clientIdMetadataDocumentsSupported = false }: DiscoveryDeps,
): void {
  const scopeNames = scopes.map((s) => s.name);

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
      scopes_supported: scopeNames,
      // RFC 9207 §2.3: MUST advertise this since we unconditionally emit `iss` on the
      // authorization redirect (see routes.ts) — otherwise a compliant client's own
      // decision table treats "flag absent" as "proceed without validating iss."
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: clientIdMetadataDocumentsSupported,
    });
  });

  // RFC 9728 — Protected Resource Metadata. Served at both the root well-known path and
  // the /mcp sub-path: RFC 9728 ties `resource` to the URI the document is served at, and
  // the MCP spec's client discovery flow probes the sub-path form first.
  const protectedResourceMetadata = (c: Context) =>
    c.json({
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: scopeNames,
    });
  app.get("/.well-known/oauth-protected-resource", protectedResourceMetadata);
  app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadata);
}
