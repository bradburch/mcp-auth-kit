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

/** TTL constants in seconds. Access/refresh lifetimes are defaults — see `tokenTtl`. */
const TTL = {
  CLIENT: 30 * 24 * 60 * 60, // 30 days
  AUTH_CODE: 5 * 60, // 5 minutes
  ACCESS_TOKEN: 60 * 60, // 1 hour
  REFRESH_TOKEN: 90 * 24 * 60 * 60, // 90 days
  CIMD_CACHE: 60 * 60, // 1 hour — fallback used only when the fetched document sends no
  // `Cache-Control: max-age` of its own; when it does, that (clamped) value wins instead
  // (see cimd.ts's parseMaxAge / MIN_CACHE_SECONDS / MAX_CACHE_SECONDS).
} as const;

/** An access + refresh token pair returned to the client. */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  /** Access-token lifetime in seconds. */
  expiresIn: number;
  scope: string[];
  /** The user the pair was issued to (for audit hooks — never sent to the client). */
  userId: string;
}

/** Access/refresh token lifetimes. Omit a field to keep its default. */
export interface TokenTtlConfig {
  /** Access-token lifetime in seconds. Default: 3600 (1 hour). */
  accessTokenSeconds?: number;
  /** Refresh-token (and token-family) lifetime in seconds. Default: 7776000 (90 days). */
  refreshTokenSeconds?: number;
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

/**
 * What a redeemed code's record is replaced with: a replay of the code (RFC 6749 §4.1.2:
 * "SHOULD revoke … all tokens previously issued based on that authorization code") finds
 * this marker and revokes the family it minted.
 */
interface UsedAuthCode {
  usedFamilyId: string;
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
  /** Override the access/refresh token lifetimes. */
  tokenTtl?: TokenTtlConfig;
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
  verifyAccessToken(
    token: string,
  ): Promise<{ userId: string; clientId: string; scopes: string[] } | null>;
  refresh(input: { refreshToken: string; clientId: string }): Promise<TokenPair>;
  /** Resolves with the revoked token's userId, or `{}` when the token was unknown. */
  revoke(input: { token: string; clientId: string }): Promise<{ userId?: string }>;
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
  const accessTtl = config.tokenTtl?.accessTokenSeconds ?? TTL.ACCESS_TOKEN;
  const refreshTtl = config.tokenTtl?.refreshTokenSeconds ?? TTL.REFRESH_TOKEN;
  // The family record gates every access token (verifyAccessToken), so it must outlive both.
  const familyTtl = Math.max(accessTtl, refreshTtl);

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
      ttlSeconds: doc?.maxAgeSeconds ?? TTL.CIMD_CACHE,
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
        ttlSeconds: accessTtl,
      }),
      storage.put(refreshTokenKey(refreshHash), JSON.stringify(refreshData), {
        ttlSeconds: refreshTtl,
      }),
      // The family record outlives both tokens: it tracks the live refresh token, and its
      // absence revokes every access token in the lineage (see verifyAccessToken).
      storage.put(tokenFamilyKey(familyId), JSON.stringify(family), {
        ttlSeconds: familyTtl,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: accessTtl,
      scope,
      userId,
    };
  }

  /**
   * Revoke a whole token lineage. Deleting the family record is what matters —
   * verifyAccessToken rejects any access token whose family is gone, including older
   * generations that are still inside their own TTL. The live pair is deleted too.
   */
  async function revokeFamily(familyId: string): Promise<void> {
    const familyRaw = await storage.get(tokenFamilyKey(familyId));
    const family = familyRaw ? (JSON.parse(familyRaw) as TokenFamily) : null;
    await Promise.all([
      storage.delete(tokenFamilyKey(familyId)),
      ...(family
        ? [
            storage.delete(accessTokenKey(family.accessHash)),
            storage.delete(refreshTokenKey(family.refreshHash)),
          ]
        : []),
    ]);
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
      const codeHash = await sha256Hex(code);
      const codeData: AuthCodeData = {
        userId: input.userId,
        clientId: input.clientId,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        resource: input.resource,
        scope: normalizeScopes(input.scope),
        createdAt: now(),
      };
      await storage.put(authCodeKey(codeHash), JSON.stringify(codeData), {
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

      const codeKey = authCodeKey(await sha256Hex(input.code));
      const raw = await storage.get(codeKey);
      if (!raw) {
        throw new Error("Invalid or expired authorization code");
      }
      const stored = JSON.parse(raw) as AuthCodeData | UsedAuthCode;

      // A replay of an already-redeemed code: revoke what it minted (RFC 6749 §4.1.2).
      if ("usedFamilyId" in stored) {
        await revokeFamily(stored.usedFamilyId);
        await storage.delete(codeKey);
        throw new Error("Invalid or expired authorization code");
      }
      const codeData = stored;

      // Any failed redemption consumes the code — an attacker holding a stolen code gets
      // one guess at the verifier/client, not five minutes of them.
      const reject = async (message: string): Promise<never> => {
        await storage.delete(codeKey);
        throw new Error(message);
      };

      // Defense-in-depth expiry (independent of KV TTL).
      if (isExpired(codeData.createdAt, TTL.AUTH_CODE)) {
        return reject("Invalid or expired authorization code");
      }

      if (codeData.clientId !== input.clientId) {
        return reject("Client ID mismatch");
      }

      // RFC 6749 §4.1.3: redirect_uri is required and must match the authorization request.
      if (!input.redirectUri) {
        return reject("redirect_uri is required");
      }
      if (codeData.redirectUri !== input.redirectUri) {
        return reject("Redirect URI mismatch");
      }

      // RFC 8707: only enforce when the code was resource-bound at authorize time.
      if (codeData.resource && input.resource !== codeData.resource) {
        return reject("Resource mismatch");
      }

      // PKCE S256 — recompute and compare.
      const valid = await verifyPkceS256(input.codeVerifier, codeData.codeChallenge);
      if (!valid) {
        return reject("PKCE verification failed");
      }

      // Single-use: swap the code for a used-marker before issuing tokens, so a replay is
      // detectable for the rest of the code's lifetime.
      const familyId = crypto.randomUUID();
      const used: UsedAuthCode = { usedFamilyId: familyId, createdAt: codeData.createdAt };
      await storage.put(codeKey, JSON.stringify(used), { ttlSeconds: TTL.AUTH_CODE });

      // Always bind to this server's resource — a code authorized without an explicit
      // `resource` still yields audience-bound tokens.
      return issueTokenPair(
        codeData.userId,
        codeData.clientId,
        codeData.resource || expectedResource,
        codeData.scope,
        familyId,
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
      if (isExpired(tokenData.createdAt, accessTtl)) {
        return null;
      }
      // Defense-in-depth audience check (RFC 8707 §2) — redundant with issue-time binding
      // under normal operation, but guards against a KV namespace ever being shared across
      // two servers built with this kit.
      if (tokenData.resource !== expectedResource) {
        return null;
      }
      // A revoked lineage (reuse detection, /revoke, code replay) deletes the family record;
      // that must kill every access token in it, not just the newest one.
      if (!tokenData.familyId || (await storage.get(tokenFamilyKey(tokenData.familyId))) === null) {
        return null;
      }
      return { userId: tokenData.userId, clientId: tokenData.clientId, scopes: tokenData.scope };
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
      if (isExpired(tokenData.createdAt, refreshTtl)) {
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
        await revokeFamily(familyId);
        throw new Error("Invalid or expired refresh token (reuse detected)");
      }

      // Valid current refresh token — rotate within the same family. issueTokenPair
      // overwrites the family record to point at the new pair; the old refresh-token
      // record is intentionally retained so a later replay of it is still detectable.
      return issueTokenPair(
        tokenData.userId,
        tokenData.clientId,
        tokenData.resource || expectedResource,
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

      // Tear down the family record: the lineage can't be rotated, and every access token
      // in it — older generations included — fails verifyAccessToken from now on.
      const familyId = accessData?.familyId ?? refreshData?.familyId;
      if (familyId) {
        await storage.delete(tokenFamilyKey(familyId));
      }
      return { userId: accessData?.userId ?? refreshData?.userId };
    },
  };
}
