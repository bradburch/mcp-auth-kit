// test/security-fixes.test.ts — coverage for the production-hardening security fixes:
// credential oracle, refresh-token reuse detection, expiry defense-in-depth,
// /register + /revoke rate limiting, OAuth-route body cap, confirm-token user binding,
// and accentColor CSS-injection hardening.
import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";
import { createOAuthProvider } from "../src/oauth/provider.js";
import { createRateLimiter } from "../src/rate-limit.js";
import { mountOAuthRoutes } from "../src/oauth/routes.js";
import { renderAuthorizePage } from "../src/identity/page.js";
import { pkce, callTool, getToken } from "./helpers.js";
import type { IdentityConfig } from "../src/config.js";

const BASE_URL = "https://example.test";
const RESOURCE = `${BASE_URL}/mcp`;
const SCOPES = [
  { name: "account:read", default: true },
  { name: "write", default: true },
];

/** Drive register → authorize → exchange directly against a provider; return the pair. */
async function issueViaProvider(p: ReturnType<typeof createOAuthProvider>) {
  const { clientId } = await p.registerClient({ redirectUris: ["https://app/cb"] });
  const { challenge, verifier } = await pkce();
  const { code } = await p.issueAuthCode({
    clientId,
    redirectUri: "https://app/cb",
    codeChallenge: challenge,
    scope: ["account:read"],
    userId: "user-1",
    resource: RESOURCE,
  });
  const tokens = await p.exchangeCode({
    code,
    clientId,
    redirectUri: "https://app/cb",
    codeVerifier: verifier,
    resource: RESOURCE,
  });
  return { tokens, clientId };
}

// ─── Credential-validity oracle on POST /authorize ────────────────────────────

describe("credential oracle — POST /authorize validates the client before credentials", () => {
  function app() {
    const a = new Hono();
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes: SCOPES,
      baseUrl: BASE_URL,
    });
    const identity: IdentityConfig = {
      fields: [{ name: "email", label: "Email" }],
      // Always "valid" — so any leak of client-validity would distinguish from bad creds.
      verify: async () => "user-1",
    };
    mountOAuthRoutes(a, { provider, identity, baseUrl: BASE_URL });
    return a;
  }

  function authorize(a: Hono, clientId: string) {
    return a.request("/authorize", {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: "https://app/cb",
        code_challenge: "abc",
        code_challenge_method: "S256",
        email: "a@b.c",
      }).toString(),
    });
  }

  it("an unknown client_id with valid credentials returns the generic invalid-credentials error (no oracle)", async () => {
    const res = await authorize(app(), "bogus-unregistered-client");
    expect(res.status).toBe(401);
    expect(res.headers.get("location")).toBeNull(); // no auth code issued
    const html = await res.text();
    expect(html).toContain("Invalid credentials");
    expect(html).not.toContain("Unknown client");
    expect(html).not.toContain("Redirect URI mismatch");
  });
});

// ─── Refresh-token reuse detection (RFC 9700) ─────────────────────────────────

describe("refresh-token reuse detection", () => {
  it("replaying a rotated-out refresh token revokes the whole family", async () => {
    const p = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes: SCOPES,
      baseUrl: BASE_URL,
    });
    const { tokens: t1, clientId } = await issueViaProvider(p);

    // Legit rotation t1 → t2.
    const t2 = await p.refresh({ refreshToken: t1.refreshToken, clientId });
    expect(t2.refreshToken).not.toBe(t1.refreshToken);

    // Replay the now-superseded t1 — detected as reuse.
    await expect(p.refresh({ refreshToken: t1.refreshToken, clientId })).rejects.toThrow();

    // Family is revoked: t2's refresh + access are now dead too.
    await expect(p.refresh({ refreshToken: t2.refreshToken, clientId })).rejects.toThrow();
    expect(await p.verifyAccessToken(t2.accessToken)).toBeNull();
  });
});

// ─── Defense-in-depth expiry (independent of storage TTL) ─────────────────────

describe("token/code expiry is enforced in-code even when storage ignores TTL", () => {
  it("verifyAccessToken returns null past the access-token TTL", async () => {
    let clock = 0;
    // Storage clock frozen at 0 → it never expires records on its own; only the
    // provider's in-code check should reject the stale token.
    const storage = createMemoryStorage(() => 0);
    const p = createOAuthProvider({ storage, scopes: SCOPES, baseUrl: BASE_URL, now: () => clock });
    const { tokens } = await issueViaProvider(p);

    expect(await p.verifyAccessToken(tokens.accessToken)).not.toBeNull();

    clock = 60 * 60 * 1000 + 1; // 1 hour + 1 ms
    expect(await p.verifyAccessToken(tokens.accessToken)).toBeNull();
  });
});

// ─── Rate limiting on /register and /revoke ───────────────────────────────────

describe("per-IP rate limiting on /register", () => {
  it("returns 429 after the limit is exhausted", async () => {
    const a = new Hono();
    const storage = createMemoryStorage();
    const provider = createOAuthProvider({ storage, scopes: SCOPES, baseUrl: BASE_URL });
    const rateLimiter = createRateLimiter({ storage, now: () => 0, config: { ipTokenPerHour: 2 } });
    mountOAuthRoutes(a, { provider, baseUrl: BASE_URL, rateLimiter });

    const register = () =>
      a.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json", "CF-Connecting-IP": "10.0.0.9" },
        body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
      });

    expect((await register()).status).toBe(201);
    expect((await register()).status).toBe(201);
    const third = await register();
    expect(third.status).toBe(429);
  });
});

// ─── Body cap enforced post-read on OAuth routes (no Content-Length) ──────────

describe("OAuth-route body cap is enforced after reading (not just via Content-Length)", () => {
  it("returns 413 for an oversized streamed /register body with no Content-Length", async () => {
    const a = new Hono();
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes: SCOPES,
      baseUrl: BASE_URL,
    });
    mountOAuthRoutes(a, { provider, baseUrl: BASE_URL });

    const big = "x".repeat(1_000_001);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(big));
        controller.close();
      },
    });
    // A streamed body has no Content-Length → only the post-read check can catch it.
    const req = new Request("http://localhost/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: stream,
      // @ts-expect-error duplex is required for a streaming request body in undici
      duplex: "half",
    });

    const res = await a.request(req);
    expect(res.status).toBe(413);
  });
});

// ─── POST /authorize still accepts multipart/form-data (no regression) ────────

describe("POST /authorize accepts multipart/form-data submissions", () => {
  it("parses multipart fields and issues an auth code", async () => {
    const a = new Hono();
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes: SCOPES,
      baseUrl: BASE_URL,
    });
    const identity: IdentityConfig = {
      fields: [{ name: "email", label: "Email" }],
      verify: async () => "user-1",
    };
    mountOAuthRoutes(a, { provider, identity, baseUrl: BASE_URL });

    const { clientId } = await provider.registerClient({ redirectUris: ["https://app/cb"] });
    const { challenge } = await pkce();

    // A FormData body makes the runtime send multipart/form-data with a boundary.
    const form = new FormData();
    form.set("response_type", "code");
    form.set("client_id", clientId);
    form.set("redirect_uri", "https://app/cb");
    form.set("code_challenge", challenge);
    form.set("code_challenge_method", "S256");
    form.set("resource", RESOURCE);
    form.set("email", "a@b.c");

    const req = new Request("http://localhost/authorize", { method: "POST", body: form });
    const res = await a.request(req, { redirect: "manual" });

    expect(res.status).toBe(302);
    const location = res.headers.get("location")!;
    expect(new URL(location).searchParams.get("code")).toBeTruthy();
  });

  it("treats a malformed multipart body as empty (clean 400, not a 500)", async () => {
    const a = new Hono();
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes: SCOPES,
      baseUrl: BASE_URL,
    });
    mountOAuthRoutes(a, {
      provider,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
      baseUrl: BASE_URL,
    });

    const res = await a.request("/authorize", {
      method: "POST",
      headers: { "content-type": "multipart/form-data; boundary=x" },
      body: "garbage-not-valid-multipart",
    });
    expect(res.status).toBe(400);
  });
});

// ─── Confirm-token is bound to the previewing user ────────────────────────────

describe("two-phase confirm token is bound to the user who previewed it", () => {
  let executed = 0;
  function makeApp(userId: string, storage = createMemoryStorage()) {
    return createMcpServer({
      baseUrl: BASE_URL,
      storage,
      scopes: SCOPES,
      identity: { fields: [{ name: "email", label: "Email" }], verify: async () => userId },
      tools: [
        {
          name: "book",
          description: "books a thing",
          scope: "write",
          inputSchema: z.object({ slot: z.string() }),
          mutating: {
            preview: async (input: unknown) => {
              const { slot } = input as { slot: string };
              return { summary: `book ${slot}`, data: { slot } };
            },
            execute: async () => {
              executed += 1;
              return { content: [{ type: "text", text: "booked" }] };
            },
          },
        },
      ],
    });
  }

  it("rejects a confirm from a different user and does not execute", async () => {
    executed = 0;
    const storage = createMemoryStorage(); // shared so userB's server can read userA's confirm token
    const appA = makeApp("user-A", storage);
    const appB = makeApp("user-B", storage);

    const tokenA = await getToken(appA);
    const tokenB = await getToken(appB);

    const preview = await callTool(appA, tokenA, "book", { slot: "A" });
    const confirmationToken = /"confirmationToken":"([^"]+)"/.exec(JSON.stringify(preview))![1];

    const result = await callTool(appB, tokenB, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-x",
    });
    expect(JSON.stringify(result)).toContain("expired or was already used");
    expect(executed).toBe(0);

    // The rightful user can still confirm it.
    const ok = await callTool(appA, tokenA, "confirm_request", {
      confirmationToken,
      idempotencyKey: "idem-a",
    });
    expect(JSON.stringify(ok)).toContain("booked");
    expect(executed).toBe(1);
  });
});

// ─── accentColor CSS-injection hardening ──────────────────────────────────────

describe("renderAuthorizePage hardens branding.accentColor against CSS injection", () => {
  const baseParams = {
    response_type: "code",
    client_id: "c",
    redirect_uri: "https://app/cb",
    code_challenge: "abc",
    code_challenge_method: "S256",
    state: "",
    resource: "",
    scope: "",
  };

  it("falls back to the default for a non-hex accentColor", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: { appName: "X", accentColor: "red; } body { display: none } .x {" },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).not.toContain("display: none");
    expect(html).toContain("#3b82f6");
  });

  it("passes through a valid hex accentColor", () => {
    const identity: IdentityConfig = {
      fields: [],
      branding: { appName: "X", accentColor: "#abcdef" },
      verify: async () => null,
    };
    const html = renderAuthorizePage(identity, baseParams);
    expect(html).toContain("#abcdef");
  });
});
