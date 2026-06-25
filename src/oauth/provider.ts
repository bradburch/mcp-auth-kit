import type { KvLike } from "../storage/types.js";
import type { ScopeConfig } from "../config.js";
import {
  clientKey,
  authCodeKey,
  accessTokenKey,
  refreshTokenKey,
} from "../storage/keys.js";
import { sha256Hex } from "../crypto.js";

/** TTL constants in seconds (identical to the brad-paws reference). */
const TTL = {
  CLIENT: 30 * 24 * 60 * 60, // 30 days
  AUTH_CODE: 5 * 60, // 5 minutes
  ACCESS_TOKEN: 60 * 60, // 1 hour
  REFRESH_TOKEN: 90 * 24 * 60 * 60, // 90 days
} as const;

/** An access + refresh token pair returned to the client. */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  /** Access-token lifetime in seconds. */
  expiresIn: number;
  scope: string[];
}

/** Stored client record. */
interface ClientData {
  clientId: string;
  redirectUris: string[];
  clientName?: string;
  // NOTE: no `scope` field. Scope normalization is server-driven (single-tenant
  // consent model): the server's supported-scope set constrains every grant, not a
  // per-client allowlist. See issueAuthCode → normalizeScopes.
  createdAt: number;
}

/** Stored authorization-code record. */
interface AuthCodeData {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  scope: string[];
}

/** Stored access/refresh token record. */
interface TokenData {
  userId: string;
  clientId: string;
  resource: string;
  scope: string[];
  createdAt: number;
  /** Hash of the paired token (refresh ↔ access) for paired revocation. */
  pairHash?: string;
}

export interface OAuthProviderConfig {
  storage: KvLike;
  scopes: ScopeConfig[];
  baseUrl: string;
  /** Injectable clock for deterministic TTL/expiry in tests. */
  now?: () => number;
}

export interface OAuthProvider {
  registerClient(input: {
    redirectUris: string[];
    clientName?: string;
  }): Promise<{ clientId: string; redirectUris: string[]; createdAt: number }>;
  issueAuthCode(input: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    scope: string[];
    userId: string;
    resource: string;
  }): Promise<{ code: string }>;
  exchangeCode(input: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier: string;
    resource: string;
  }): Promise<TokenPair>;
  verifyAccessToken(
    token: string,
  ): Promise<{ userId: string; scopes: string[] } | null>;
  refresh(input: {
    refreshToken: string;
    clientId: string;
  }): Promise<TokenPair>;
  revoke(input: { token: string; clientId: string }): Promise<void>;
  normalizeScopes(requested: string[]): string[];
}

/** Recompute base64url(SHA-256(verifier)) and compare to the stored challenge (PKCE S256 only). */
async function verifyPkceS256(
  codeVerifier: string,
  codeChallenge: string,
): Promise<boolean> {
  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64url = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return base64url === codeChallenge;
}

export function createOAuthProvider(
  config: OAuthProviderConfig,
): OAuthProvider {
  const { storage, scopes, baseUrl } = config;
  const now = config.now ?? (() => Date.now());

  const supportedScopes = scopes.map((s) => s.name);
  const defaultScopes = scopes.filter((s) => s.default).map((s) => s.name);
  /** The single resource this server is bound to (RFC 8707). */
  const expectedResource = `${baseUrl}/mcp`;

  /**
   * Drop requested scopes that aren't supported; if nothing remains, fall back
   * to the configured default scopes. Preserves the supported-scope ordering so
   * the result is deterministic regardless of request order.
   */
  function normalizeScopes(requested: string[]): string[] {
    const wanted = new Set(requested);
    const allowed = supportedScopes.filter((s) => wanted.has(s));
    return allowed.length > 0 ? allowed : [...defaultScopes];
  }

  /** Reject when a resource was supplied and it isn't this server's resource (RFC 8707 audit fix). */
  function assertResource(resource: string): void {
    if (resource && resource !== expectedResource) {
      throw new Error("Resource mismatch");
    }
  }

  /** Issue + persist a fresh access/refresh token pair, hashing both before storage. */
  async function issueTokenPair(
    userId: string,
    clientId: string,
    resource: string,
    scope: string[],
  ): Promise<TokenPair> {
    const accessToken = crypto.randomUUID();
    const refreshToken = crypto.randomUUID();
    const createdAt = now();

    const [accessHash, refreshHash] = await Promise.all([
      sha256Hex(accessToken),
      sha256Hex(refreshToken),
    ]);

    const accessData: TokenData = {
      userId,
      clientId,
      resource,
      scope,
      createdAt,
      pairHash: refreshHash,
    };
    const refreshData: TokenData = {
      userId,
      clientId,
      resource,
      scope,
      createdAt,
      pairHash: accessHash,
    };

    await Promise.all([
      storage.put(accessTokenKey(accessHash), JSON.stringify(accessData), {
        ttlSeconds: TTL.ACCESS_TOKEN,
      }),
      storage.put(refreshTokenKey(refreshHash), JSON.stringify(refreshData), {
        ttlSeconds: TTL.REFRESH_TOKEN,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: TTL.ACCESS_TOKEN,
      scope,
    };
  }

  return {
    normalizeScopes,

    async registerClient(input) {
      const clientId = crypto.randomUUID();
      const createdAt = now();
      const redirectUris = input.redirectUris.map((u) => u.toString());
      const clientData: ClientData = {
        clientId,
        redirectUris,
        clientName: input.clientName,
        createdAt,
      };
      await storage.put(clientKey(clientId), JSON.stringify(clientData), {
        ttlSeconds: TTL.CLIENT,
      });
      return { clientId, redirectUris, createdAt };
    },

    async issueAuthCode(input) {
      // RFC 8707 resource validation (audit fix) — reject a mismatched resource at authorize time.
      assertResource(input.resource);

      const raw = await storage.get(clientKey(input.clientId));
      if (!raw) {
        throw new Error("Unknown client");
      }
      const client = JSON.parse(raw) as ClientData;

      // RFC 6749 §3.1.2.3: the redirect_uri must match one the client registered.
      if (!client.redirectUris.includes(input.redirectUri)) {
        throw new Error("Redirect URI mismatch");
      }

      const code = crypto.randomUUID();
      const codeData: AuthCodeData = {
        userId: input.userId,
        clientId: input.clientId,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        resource: input.resource,
        scope: normalizeScopes(input.scope),
      };
      await storage.put(authCodeKey(code), JSON.stringify(codeData), {
        ttlSeconds: TTL.AUTH_CODE,
      });
      return { code };
    },

    async exchangeCode(input) {
      // RFC 8707 resource validation (audit fix).
      assertResource(input.resource);

      const raw = await storage.get(authCodeKey(input.code));
      if (!raw) {
        throw new Error("Invalid or expired authorization code");
      }
      const codeData = JSON.parse(raw) as AuthCodeData;

      if (codeData.clientId !== input.clientId) {
        throw new Error("Client ID mismatch");
      }

      // RFC 6749 §4.1.3: redirect_uri is required and must match the authorization request.
      if (!input.redirectUri) {
        throw new Error("redirect_uri is required");
      }
      if (codeData.redirectUri !== input.redirectUri) {
        throw new Error("Redirect URI mismatch");
      }

      // RFC 8707: only enforce when the code was resource-bound at authorize time.
      if (codeData.resource && input.resource !== codeData.resource) {
        throw new Error("Resource mismatch");
      }

      // PKCE S256 — recompute and compare.
      const valid = await verifyPkceS256(
        input.codeVerifier,
        codeData.codeChallenge,
      );
      if (!valid) {
        throw new Error("PKCE verification failed");
      }

      // Single-use: delete the code before issuing tokens.
      await storage.delete(authCodeKey(input.code));

      // Always bind to the resource authorized at auth time — no escalation.
      return issueTokenPair(
        codeData.userId,
        codeData.clientId,
        codeData.resource,
        codeData.scope,
      );
    },

    async verifyAccessToken(token) {
      const tokenHash = await sha256Hex(token);
      const raw = await storage.get(accessTokenKey(tokenHash));
      if (!raw) {
        return null;
      }
      const tokenData = JSON.parse(raw) as TokenData;
      return { userId: tokenData.userId, scopes: tokenData.scope };
    },

    async refresh(input) {
      const refreshHash = await sha256Hex(input.refreshToken);
      const raw = await storage.get(refreshTokenKey(refreshHash));
      if (!raw) {
        throw new Error("Invalid or expired refresh token");
      }
      const tokenData = JSON.parse(raw) as TokenData;

      if (tokenData.clientId !== input.clientId) {
        throw new Error("Client ID mismatch");
      }

      // Issue the new pair first, then delete the old refresh token (rotation).
      // Order matters: if issuance fails, the old token remains valid.
      const tokens = await issueTokenPair(
        tokenData.userId,
        tokenData.clientId,
        tokenData.resource,
        tokenData.scope,
      );
      await storage.delete(refreshTokenKey(refreshHash));
      return tokens;
    },

    async revoke(input) {
      // RFC 7009 §2.1: search across both token types; refuse if the token
      // belongs to a different client.
      const tokenHash = await sha256Hex(input.token);
      const [accessRaw, refreshRaw] = await Promise.all([
        storage.get(accessTokenKey(tokenHash)),
        storage.get(refreshTokenKey(tokenHash)),
      ]);

      const accessData = accessRaw
        ? (JSON.parse(accessRaw) as TokenData)
        : null;
      const refreshData = refreshRaw
        ? (JSON.parse(refreshRaw) as TokenData)
        : null;

      if (accessData && accessData.clientId !== input.clientId) {
        throw new Error("Token was not issued to this client");
      }
      if (refreshData && refreshData.clientId !== input.clientId) {
        throw new Error("Token was not issued to this client");
      }

      const deletes: Promise<void>[] = [];
      if (accessData) deletes.push(storage.delete(accessTokenKey(tokenHash)));
      if (refreshData) deletes.push(storage.delete(refreshTokenKey(tokenHash)));
      if (deletes.length > 0) await Promise.all(deletes);

      // Revoke the paired token too (RFC 7009 §2.1 SHOULD).
      if (accessData?.pairHash) {
        await storage.delete(refreshTokenKey(accessData.pairHash));
      }
      if (refreshData?.pairHash) {
        await storage.delete(accessTokenKey(refreshData.pairHash));
      }
    },
  };
}
