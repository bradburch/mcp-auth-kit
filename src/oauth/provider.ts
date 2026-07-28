import type { KvLike } from "../storage/types.js";
import type { ScopeConfig } from "../config.js";
import {
  clientKey,
  authCodeKey,
  accessTokenKey,
  refreshTokenKey,
  tokenFamilyKey,
  cimdKey,
} from "../storage/keys.js";
import { sha256Hex, randomToken } from "../crypto.js";
import { fetchClientIdMetadata } from "./cimd.js";

/** TTL constants in seconds. */
const TTL = {
  CLIENT: 30 * 24 * 60 * 60, // 30 days
  AUTH_CODE: 5 * 60, // 5 minutes
  ACCESS_TOKEN: 60 * 60, // 1 hour
  REFRESH_TOKEN: 90 * 24 * 60 * 60, // 90 days
  CIMD_CACHE: 60 * 60, // 1 hour — bounds staleness without needing to parse Cache-Control
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
  applicationType?: "web" | "native";
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
  /** Issue time (ms) — defense-in-depth expiry check independent of the KV TTL. */
  createdAt: number;
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
  /** Shared lineage id linking every token rotated from one authorization. */
  familyId?: string;
}

/**
 * Token-family record — tracks the currently-active access/refresh pair so a
 * superseded (replayed) refresh token can be detected and the family revoked
 * (RFC 9700 refresh-token reuse detection).
 */
interface TokenFamily {
  accessHash: string;
  refreshHash: string;
}

export interface OAuthProviderConfig {
  storage: KvLike;
  scopes: ScopeConfig[];
  baseUrl: string;
  /** Injectable clock for deterministic TTL/expiry in tests. */
  now?: () => number;
  /**
   * Resolve unregistered HTTPS client_ids as OAuth Client ID Metadata Documents
   * (MCP 2026-07-28, deprecating Dynamic Client Registration). Off by default —
   * enabling it makes this server fetch an operator-uncontrolled URL during
   * authorization; only turn it on once you're comfortable with that outbound
   * request surface.
   */
  allowClientIdMetadataDocuments?: boolean;
}

export interface OAuthProvider {
  registerClient(input: {
    redirectUris: string[];
    clientName?: string;
    applicationType?: "web" | "native";
  }): Promise<{
    clientId: string;
    redirectUris: string[];
    createdAt: number;
    applicationType?: "web" | "native";
  }>;
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
  verifyAccessToken(token: string): Promise<{ userId: string; scopes: string[] } | null>;
  refresh(input: { refreshToken: string; clientId: string }): Promise<TokenPair>;
  revoke(input: { token: string; clientId: string }): Promise<void>;
  /**
   * Cheap check that `clientId` is registered and `redirectUri` is one it registered.
   * Lets the authorize route validate the client BEFORE running identity.verify, so a
   * bogus client_id can't be used as a credential-validity oracle.
   */
  validateClientRedirect(clientId: string, redirectUri: string): Promise<boolean>;
  normalizeScopes(requested: string[]): string[];
}

/** Recompute base64url(SHA-256(verifier)) and compare to the stored challenge (PKCE S256 only). */
async function verifyPkceS256(codeVerifier: string, codeChallenge: string): Promise<boolean> {
  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64url = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return base64url === codeChallenge;
}

export function createOAuthProvider(config: OAuthProviderConfig): OAuthProvider {
  const { storage, scopes, baseUrl, allowClientIdMetadataDocuments = false } = config;
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

  /**
   * Resolve the redirect URIs a client_id is allowed to use — from a stored
   * (pre-registered / DCR) record first, falling back to a cached Client ID Metadata
   * Document fetch when `allowClientIdMetadataDocuments` is enabled and the client_id
   * looks like an https URL not already registered.
   */
  async function resolveClientRedirectUris(clientId: string): Promise<string[] | null> {
    const raw = await storage.get(clientKey(clientId));
    if (raw) return (JSON.parse(raw) as ClientData).redirectUris;

    if (!allowClientIdMetadataDocuments || !clientId.startsWith("https://")) return null;

    const cacheKey = cimdKey(await sha256Hex(clientId));
    const cached = await storage.get(cacheKey);
    // Loose equality: a third-party KvLike adapter could return undefined instead of null;
    // JSON.parse(undefined) would throw uncaught outside this function's try/catch.
    if (cached != null) return JSON.parse(cached) as string[];

    const doc = await fetchClientIdMetadata(clientId);
    // "[]" is the cached "fetched but invalid/unreachable" sentinel — JSON.parse("[]") is
    // naturally an empty array, and [].includes(anything) is false, so no special-case
    // branch is needed to read it back.
    await storage.put(cacheKey, doc ? JSON.stringify(doc.redirectUris) : "[]", {
      ttlSeconds: TTL.CIMD_CACHE,
    });
    return doc?.redirectUris ?? null;
  }

  /**
   * Defense-in-depth expiry: don't trust the KV backend to honour `ttlSeconds`.
   * A KvLike that ignores TTL would otherwise leave tokens/codes valid forever.
   */
  function isExpired(createdAt: number, ttlSeconds: number): boolean {
    return now() - createdAt > ttlSeconds * 1000;
  }

  /**
   * Issue + persist a fresh access/refresh token pair (hashing both before storage)
   * and update the family record to point at the new pair. `familyId` links every
   * pair rotated from a single authorization so reuse can be detected.
   */
  async function issueTokenPair(
    userId: string,
    clientId: string,
    resource: string,
    scope: string[],
    familyId: string,
  ): Promise<TokenPair> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
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
      familyId,
    };
    const refreshData: TokenData = {
      userId,
      clientId,
      resource,
      scope,
      createdAt,
      pairHash: accessHash,
      familyId,
    };
    const family: TokenFamily = { accessHash, refreshHash };

    await Promise.all([
      storage.put(accessTokenKey(accessHash), JSON.stringify(accessData), {
        ttlSeconds: TTL.ACCESS_TOKEN,
      }),
      storage.put(refreshTokenKey(refreshHash), JSON.stringify(refreshData), {
        ttlSeconds: TTL.REFRESH_TOKEN,
      }),
      // The family record outlives the access token, so it tracks the live refresh token.
      storage.put(tokenFamilyKey(familyId), JSON.stringify(family), {
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
        applicationType: input.applicationType,
        createdAt,
      };
      await storage.put(clientKey(clientId), JSON.stringify(clientData), {
        ttlSeconds: TTL.CLIENT,
      });
      return { clientId, redirectUris, createdAt, applicationType: input.applicationType };
    },

    async issueAuthCode(input) {
      // RFC 8707 resource validation (audit fix) — reject a mismatched resource at authorize time.
      assertResource(input.resource);

      const redirectUris = await resolveClientRedirectUris(input.clientId);
      if (!redirectUris) {
        throw new Error("Unknown client");
      }

      // RFC 6749 §3.1.2.3: the redirect_uri must match one the client registered.
      if (!redirectUris.includes(input.redirectUri)) {
        throw new Error("Redirect URI mismatch");
      }

      const code = randomToken();
      const codeData: AuthCodeData = {
        userId: input.userId,
        clientId: input.clientId,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        resource: input.resource,
        scope: normalizeScopes(input.scope),
        createdAt: now(),
      };
      await storage.put(authCodeKey(code), JSON.stringify(codeData), {
        ttlSeconds: TTL.AUTH_CODE,
      });
      return { code };
    },

    async validateClientRedirect(clientId, redirectUri) {
      if (!clientId || !redirectUri) return false;
      const redirectUris = await resolveClientRedirectUris(clientId);
      return redirectUris?.includes(redirectUri) ?? false;
    },

    async exchangeCode(input) {
      // RFC 8707 resource validation (audit fix).
      assertResource(input.resource);

      const raw = await storage.get(authCodeKey(input.code));
      if (!raw) {
        throw new Error("Invalid or expired authorization code");
      }
      const codeData = JSON.parse(raw) as AuthCodeData;

      // Defense-in-depth expiry (independent of KV TTL); consume the stale code.
      if (isExpired(codeData.createdAt, TTL.AUTH_CODE)) {
        await storage.delete(authCodeKey(input.code));
        throw new Error("Invalid or expired authorization code");
      }

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
      const valid = await verifyPkceS256(input.codeVerifier, codeData.codeChallenge);
      if (!valid) {
        throw new Error("PKCE verification failed");
      }

      // Single-use: delete the code before issuing tokens.
      await storage.delete(authCodeKey(input.code));

      // Fresh family for a fresh authorization. Always bind to the resource
      // authorized at auth time — no escalation.
      return issueTokenPair(
        codeData.userId,
        codeData.clientId,
        codeData.resource,
        codeData.scope,
        crypto.randomUUID(),
      );
    },

    async verifyAccessToken(token) {
      const tokenHash = await sha256Hex(token);
      const raw = await storage.get(accessTokenKey(tokenHash));
      if (!raw) {
        return null;
      }
      const tokenData = JSON.parse(raw) as TokenData;
      // Defense-in-depth expiry — never honour a token past its TTL even if KV did.
      if (isExpired(tokenData.createdAt, TTL.ACCESS_TOKEN)) {
        return null;
      }
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
      if (isExpired(tokenData.createdAt, TTL.REFRESH_TOKEN)) {
        throw new Error("Invalid or expired refresh token");
      }

      // Refresh-token reuse detection (RFC 9700). The family record is the source of
      // truth for which refresh token is live. A presented token whose hash no longer
      // matches the family's active hash is a replay of a rotated-out token → revoke
      // the entire family (active access + refresh) so a stolen token is contained.
      const familyId = tokenData.familyId;
      const familyRaw = familyId ? await storage.get(tokenFamilyKey(familyId)) : null;
      if (!familyId || !familyRaw) {
        // Family already revoked, or a legacy token with no family — refuse.
        throw new Error("Invalid or expired refresh token");
      }
      const family = JSON.parse(familyRaw) as TokenFamily;
      if (family.refreshHash !== refreshHash) {
        await Promise.all([
          storage.delete(accessTokenKey(family.accessHash)),
          storage.delete(refreshTokenKey(family.refreshHash)),
          storage.delete(tokenFamilyKey(familyId)),
        ]);
        throw new Error("Invalid or expired refresh token (reuse detected)");
      }

      // Valid current refresh token — rotate within the same family. issueTokenPair
      // overwrites the family record to point at the new pair; the old refresh-token
      // record is intentionally retained so a later replay of it is still detectable.
      return issueTokenPair(
        tokenData.userId,
        tokenData.clientId,
        tokenData.resource,
        tokenData.scope,
        familyId,
      );
    },

    async revoke(input) {
      // RFC 7009 §2.1: search across both token types; refuse if the token
      // belongs to a different client.
      const tokenHash = await sha256Hex(input.token);
      const [accessRaw, refreshRaw] = await Promise.all([
        storage.get(accessTokenKey(tokenHash)),
        storage.get(refreshTokenKey(tokenHash)),
      ]);

      const accessData = accessRaw ? (JSON.parse(accessRaw) as TokenData) : null;
      const refreshData = refreshRaw ? (JSON.parse(refreshRaw) as TokenData) : null;

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

      // Tear down the family record so the lineage can't be rotated after revocation.
      const familyId = accessData?.familyId ?? refreshData?.familyId;
      if (familyId) {
        await storage.delete(tokenFamilyKey(familyId));
      }
    },
  };
}
