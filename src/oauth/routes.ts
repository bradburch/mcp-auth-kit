// OAuth HTTP route handlers (RFC 6749 / RFC 7009 / RFC 8414).
// Provides mountOAuthRoutes(app, deps) for wiring POST /register, GET+POST /authorize,
// POST /token, POST /revoke onto a Hono app.
import type { Context, Hono } from "hono";
import type { OAuthProvider } from "./provider.js";
import type { IdentityConfig, ObservabilityHooks } from "../config.js";
import { renderAuthorizePage, type AuthorizePageParams } from "../identity/page.js";

import type { RateLimiter } from "../rate-limit.js";
import { extractClientIp } from "../http/client-ip.js";
import { readCappedBody } from "../http/body-limit.js";

// ─── Security header constants ───────────────────────────────────────────────

/** RFC 6749 §5.1 — token responses MUST NOT be cached. */
const TOKEN_CACHE_HEADERS = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
} as const;

/** CSP for the authorize form page. img-src https: allows https logo images. */
const AUTHORIZE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; img-src https:";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function oauthError(
  error: string,
  description?: string,
): { error: string; error_description?: string } {
  return description ? { error, error_description: description } : { error };
}

function hasFragment(uri: string): boolean {
  try {
    return new URL(uri).hash !== "";
  } catch {
    return false;
  }
}

/**
 * Read the (capped) request body and parse it — urlencoded, multipart, or JSON — into a
 * flat string map. Returns a 413 Response when the body exceeds the cap. Non-string
 * (File) multipart values are coerced to "" since OAuth fields are always text.
 */
async function readBodyParsed(req: Request): Promise<Record<string, string> | Response> {
  const capped = await readCappedBody(req);
  if (capped instanceof Response) return capped;

  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("multipart/form-data")) {
    try {
      const form = await new Response(capped, { headers: { "content-type": ct } }).formData();
      const result: Record<string, string> = {};
      for (const [k, v] of form.entries()) result[k] = typeof v === "string" ? v : "";
      return result;
    } catch {
      // Malformed multipart — treat as empty so callers return a clean 400, not a 500.
      return {};
    }
  }
  if (ct.includes("application/x-www-form-urlencoded")) {
    const result: Record<string, string> = {};
    for (const [k, v] of new URLSearchParams(capped).entries()) result[k] = v;
    return result;
  }
  try {
    const parsed = JSON.parse(capped) as unknown;
    // Only an object yields fields; a bare null/array/scalar becomes an empty map so
    // downstream `body.foo` access can't throw.
    return parsed && typeof parsed === "object" ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

/**
 * Build the AuthorizePageParams shared by the GET (initial render) and POST (error
 * re-render) paths from a flat OAuth-param map, optionally with an error + prefill.
 */
function authorizePageParams(
  oauthParams: Record<string, string>,
  extra?: { error?: string; prefill?: Record<string, string> },
): AuthorizePageParams {
  return {
    response_type: oauthParams.response_type ?? "code",
    client_id: oauthParams.client_id ?? "",
    redirect_uri: oauthParams.redirect_uri ?? "",
    code_challenge: oauthParams.code_challenge ?? "",
    code_challenge_method: oauthParams.code_challenge_method ?? "S256",
    state: oauthParams.state ?? "",
    resource: oauthParams.resource ?? "",
    scope: oauthParams.scope ?? "",
    error: extra?.error,
    prefill: extra?.prefill,
  };
}

/**
 * Extract the 8 standard OAuth params from a flat string map (query string or form body).
 * Shared by GET /authorize (query params) and POST /authorize (form body).
 */
function extractOAuthParams(source: Record<string, string>): Record<string, string> {
  return {
    response_type: source.response_type ?? "",
    client_id: source.client_id ?? "",
    redirect_uri: source.redirect_uri ?? "",
    code_challenge: source.code_challenge ?? "",
    code_challenge_method: source.code_challenge_method || "S256",
    state: source.state ?? "",
    resource: source.resource ?? "",
    scope: source.scope ?? "",
  };
}

// ─── Route mounting ───────────────────────────────────────────────────────────

export interface OAuthRouteDeps {
  provider: OAuthProvider;
  identity?: IdentityConfig;
  baseUrl: string;
  hooks?: ObservabilityHooks;
  rateLimiter?: RateLimiter;
  /**
   * Extract the trusted client IP for per-IP rate limiting. Defaults to
   * {@link extractClientIp} (CF-Connecting-IP → X-Forwarded-For first hop).
   * Override this off-Cloudflare so a spoofable header can't reset rate-limit buckets.
   */
  ipExtractor?: (req: Request) => string;
}

/**
 * Fire an onAudit event (fire-and-forget — errors are swallowed so a misbehaving
 * hook never fails the OAuth request).
 */
async function fireAudit(
  hooks: ObservabilityHooks | undefined,
  event: Parameters<NonNullable<ObservabilityHooks["onAudit"]>>[0],
): Promise<void> {
  try {
    await hooks?.onAudit?.(event);
  } catch {
    // Intentionally swallowed — hook errors must not surface to the client.
  }
}

/**
 * Wire OAuth endpoints onto `app`:
 *   POST /register   — Dynamic Client Registration (RFC 7591)
 *   GET  /authorize  — Render login form
 *   POST /authorize  — Process login, issue auth code, 302 redirect
 *   POST /token      — Token exchange (authorization_code + refresh_token)
 *   POST /revoke     — Token revocation (RFC 7009)
 */
export function mountOAuthRoutes(
  app: Hono,
  { provider, identity, hooks, rateLimiter, ipExtractor }: OAuthRouteDeps,
): void {
  const clientIp = ipExtractor ?? extractClientIp;

  /**
   * Apply a per-IP rate-limit bucket. Returns a 429 Response when the limit is exhausted,
   * or null to proceed. No-op when no rate limiter is configured.
   */
  const ipRateLimited = async (
    c: Context,
    bucket: (rl: RateLimiter, ip: string) => Promise<boolean>,
  ): Promise<Response | null> => {
    if (!rateLimiter) return null;
    const ok = await bucket(rateLimiter, clientIp(c.req.raw));
    return ok ? null : c.json(oauthError("temporarily_unavailable", "rate limit exceeded"), 429);
  };

  // ── POST /register ─────────────────────────────────────────────────────────

  app.post("/register", async (c) => {
    // Per-IP rate limit: unauthenticated DCR is a storage-exhaustion DoS vector.
    const limited = await ipRateLimited(c, (rl, ip) => rl.checkIpToken(ip));
    if (limited) return limited;

    const capped = await readCappedBody(c.req.raw);
    if (capped instanceof Response) return capped;

    let body: Record<string, unknown>;
    try {
      body = JSON.parse(capped);
    } catch {
      return c.json(oauthError("invalid_client_metadata", "Request body must be JSON"), 400);
    }

    const redirectUris = body.redirect_uris;
    if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
      return c.json(oauthError("invalid_client_metadata", "redirect_uris required"), 400);
    }

    if ((redirectUris as string[]).some((u: string) => hasFragment(u))) {
      return c.json(
        oauthError("invalid_redirect_uri", "redirect_uris must not contain fragments"),
        400,
      );
    }

    // Validate URI schemes: https required (http only for localhost dev).
    let parsedUris: string[];
    try {
      parsedUris = (redirectUris as string[]).map((u: string) => {
        const url = new URL(u);
        const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
        if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
          throw new Error(`Invalid redirect URI scheme: ${url.protocol}`);
        }
        return url.toString();
      });
    } catch (e) {
      return c.json(
        oauthError(
          "invalid_redirect_uri",
          e instanceof Error ? e.message : "Invalid redirect_uris",
        ),
        400,
      );
    }

    try {
      const result = await provider.registerClient({
        redirectUris: parsedUris,
        clientName: typeof body.client_name === "string" ? body.client_name : undefined,
      });
      void fireAudit(hooks, {
        event: "client_registered",
        clientId: result.clientId,
      });
      // RFC 7591 §3.2.1: echo client_id, redirect_uris, client_id_issued_at,
      // and token_endpoint_auth_method in the registration response.
      return c.json(
        {
          client_id: result.clientId,
          client_id_issued_at: Math.floor(result.createdAt / 1000),
          redirect_uris: result.redirectUris,
          token_endpoint_auth_method: "none",
        },
        201,
      );
    } catch (e) {
      return c.json(
        oauthError(
          "invalid_client_metadata",
          e instanceof Error ? e.message : "Registration failed",
        ),
        400,
      );
    }
  });

  // ── GET /authorize ─────────────────────────────────────────────────────────

  app.get("/authorize", (c) => {
    c.header("Content-Security-Policy", AUTHORIZE_CSP);

    const oauthParams = extractOAuthParams(
      Object.fromEntries(new URL(c.req.url).searchParams.entries()) as Record<string, string>,
    );
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      response_type: responseType,
      code_challenge_method: codeChallengeMethod,
    } = oauthParams;

    if (!clientId || !redirectUri || !codeChallenge) {
      return c.text("Missing required OAuth parameters", 400);
    }
    if (responseType !== "code") {
      return c.text('Unsupported response_type. Only "code" is supported.', 400);
    }
    if (codeChallengeMethod !== "S256") {
      return c.text("Unsupported code_challenge_method. Only S256 is supported.", 400);
    }

    if (!identity) {
      return c.text("No identity provider configured", 400);
    }
    return c.html(renderAuthorizePage(identity, authorizePageParams(oauthParams)));
  });

  // ── POST /authorize ────────────────────────────────────────────────────────

  app.post("/authorize", async (c) => {
    c.header("Content-Security-Policy", AUTHORIZE_CSP);

    // Per-IP rate limit: brute-force guard on credential submissions.
    const limited = await ipRateLimited(c, (rl, ip) => rl.checkIpAuthorize(ip));
    if (limited) return limited;

    const formData = await readBodyParsed(c.req.raw);
    if (formData instanceof Response) return formData;
    const getString = (key: string) => String(formData[key] ?? "").trim();

    const oauthParams = extractOAuthParams(
      Object.fromEntries(Object.keys(formData).map((k) => [k, getString(k)])),
    );
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      resource,
      scope,
    } = oauthParams;

    // Mirror GET /authorize: reject a missing code_challenge before doing any
    // identity work — otherwise a malicious POST could mint an un-redeemable code.
    if (!clientId || !redirectUri || !codeChallenge) {
      return c.json(oauthError("invalid_request", "Missing required OAuth parameters"), 400);
    }
    if (codeChallengeMethod !== "S256") {
      return c.text("Unsupported code_challenge_method. Only S256 is supported.", 400);
    }

    // Collect identity field values from form body.
    const fields = identity?.fields ?? [];
    const identityFields: Record<string, string> = {};
    for (const f of fields) {
      identityFields[f.name] = getString(f.name);
    }

    function renderError(error: string) {
      if (!identity) {
        return c.json(oauthError("access_denied", "No identity provider configured"), 400);
      }
      return c.html(
        renderAuthorizePage(
          identity,
          authorizePageParams(oauthParams, { error, prefill: identityFields }),
        ),
        401,
      );
    }

    // Verify identity if an identity provider is configured.
    if (!identity) {
      // No identity provider — reject (can't issue code without a userId).
      return c.json(oauthError("access_denied", "No identity provider configured"), 400);
    }

    // Validate the client BEFORE checking credentials, and return the SAME error for a
    // bad client as for bad credentials. Otherwise a bogus client_id (no registration
    // needed) yields a different response for valid vs invalid credentials — a
    // credential-validity / user-enumeration oracle.
    const INVALID = "Invalid credentials. Please try again.";
    const clientOk = await provider.validateClientRedirect(clientId, redirectUri);
    if (!clientOk) {
      return renderError(INVALID);
    }

    const userId = await identity.verify(identityFields);
    if (userId === null) {
      return renderError(INVALID);
    }

    // Issue auth code via provider (validates client + redirectUri internally).
    try {
      const normalizedScopes = provider.normalizeScopes(scope ? scope.split(" ") : []);
      const { code } = await provider.issueAuthCode({
        clientId,
        redirectUri,
        codeChallenge,
        scope: normalizedScopes,
        userId,
        resource,
      });

      // 302 redirect back to client with code (and state if provided).
      const location = new URL(redirectUri);
      location.searchParams.set("code", code);
      if (state) location.searchParams.set("state", state);

      return c.redirect(location.toString(), 302);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Authorization failed";
      return renderError(msg);
    }
  });

  // ── POST /token ────────────────────────────────────────────────────────────

  app.post("/token", async (c) => {
    // RFC 6749 §5.1: token responses MUST NOT be cached.
    c.header("Cache-Control", TOKEN_CACHE_HEADERS["Cache-Control"]);
    c.header("Pragma", TOKEN_CACHE_HEADERS["Pragma"]);

    // Per-IP rate limit on the token endpoint.
    const limited = await ipRateLimited(c, (rl, ip) => rl.checkIpToken(ip));
    if (limited) return limited;

    const body = await readBodyParsed(c.req.raw);
    if (body instanceof Response) return body;

    const grantType = body.grant_type ?? "";
    const clientId = body.client_id ?? "";

    try {
      if (grantType === "authorization_code") {
        const code = body.code ?? "";
        const codeVerifier = body.code_verifier ?? "";
        const redirectUri = body.redirect_uri ?? "";
        const resource = body.resource ?? "";

        if (!code || !codeVerifier || !clientId || !redirectUri) {
          return c.json(oauthError("invalid_request", "Missing required parameters"), 400);
        }

        const tokens = await provider.exchangeCode({
          code,
          clientId,
          redirectUri,
          codeVerifier,
          resource,
        });

        void fireAudit(hooks, { event: "token_issued", clientId });
        return c.json(tokenPairToResponse(tokens));
      } else if (grantType === "refresh_token") {
        const refreshToken = body.refresh_token ?? "";

        if (!refreshToken || !clientId) {
          return c.json(oauthError("invalid_request", "Missing required parameters"), 400);
        }

        const tokens = await provider.refresh({ refreshToken, clientId });
        void fireAudit(hooks, { event: "token_refreshed", clientId });
        return c.json(tokenPairToResponse(tokens));
      } else {
        return c.json(
          oauthError("unsupported_grant_type", `grant_type "${grantType}" is not supported`),
          400,
        );
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Token exchange failed";
      // Map error messages to OAuth error codes + HTTP status.
      if (msg.includes("Invalid or expired") || msg.includes("PKCE")) {
        return c.json(oauthError("invalid_grant", msg), 400);
      }
      if (msg.includes("invalid_client") || msg.includes("Client ID mismatch")) {
        return c.json(oauthError("invalid_client", msg), 401);
      }
      if (msg.includes("Resource mismatch")) {
        return c.json(oauthError("invalid_target", msg), 400);
      }
      return c.json(oauthError("invalid_grant", msg), 400);
    }
  });

  // ── POST /revoke ───────────────────────────────────────────────────────────

  app.post("/revoke", async (c) => {
    // Per-IP rate limit: unauthenticated endpoint, guard against abuse.
    const limited = await ipRateLimited(c, (rl, ip) => rl.checkIpToken(ip));
    if (limited) return limited;

    const body = await readBodyParsed(c.req.raw);
    if (body instanceof Response) return body;
    const token = body.token ?? "";
    const clientId = body.client_id ?? "";

    if (!token) {
      return c.json(oauthError("invalid_request", "token is required"), 400);
    }

    try {
      await provider.revoke({ token, clientId });
      void fireAudit(hooks, { event: "token_revoked", clientId });
      // RFC 7009 §2.2: successful revocation always returns 200.
      return c.body(null, 200);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      // RFC 7009 §2.2.1: token belonging to a different client → 401.
      if (msg.includes("Token was not issued to this client")) {
        return c.json(
          oauthError("unauthorized_client", "Token was issued to a different client"),
          401,
        );
      }
      // RFC 7009 §2.2: all other errors (unknown token, etc.) → 200.
      return c.body(null, 200);
    }
  });
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

import type { TokenPair } from "./provider.js";

/** Map the internal TokenPair to the standard OAuth JSON response shape. */
function tokenPairToResponse(tokens: TokenPair) {
  return {
    access_token: tokens.accessToken,
    refresh_token: tokens.refreshToken,
    token_type: "Bearer" as const,
    expires_in: tokens.expiresIn,
    scope: tokens.scope.join(" "),
  };
}
