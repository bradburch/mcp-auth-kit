// test/consumer-findings.test.ts — fixes for issues found by building real projects on the kit:
// password echo on the login page, idempotency-key/confirmation binding, whole-family token
// revocation, code-replay revocation, resource binding, hashed codes/confirmations, storage-key
// collisions, accurate Retry-After, configurable token TTLs, richer hooks, and waitUntil.
import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  createMcpServer,
  createMemoryStorage,
  createOAuthProvider,
  defineTool,
  ToolError,
  type KvLike,
  type McpServerConfig,
} from "../src/index.js";
import { idempotencyKey, userRateKey } from "../src/storage/keys.js";
import { createRateLimiter } from "../src/rate-limit.js";
import {
  callTool,
  getToken,
  getTokenPair,
  issueViaProvider,
  mcpRequest,
  toolText as text,
} from "./helpers.js";

const BASE_URL = "https://example.test";
const RESOURCE = `${BASE_URL}/mcp`;
const SCOPES = [
  { name: "read", default: true, description: "See your stuff" },
  { name: "pay", description: "Move money" },
];

const passwordIdentity = {
  fields: [
    { name: "email", label: "Email", type: "email" },
    { name: "password", label: "Password", type: "password" },
  ],
  verify: async (f: Record<string, string>) =>
    f.email === "a@b.c" && f.password === "right" ? "user-1" : null,
};

function makeApp(extra: Partial<McpServerConfig> = {}) {
  return createMcpServer({
    baseUrl: BASE_URL,
    storage: createMemoryStorage(),
    scopes: SCOPES,
    identity: { fields: [{ name: "email", label: "Email" }], verify: async () => "user-1" },
    tools: [],
    ...extra,
  });
}

async function register(app: ReturnType<typeof makeApp>): Promise<string> {
  const res = await app.request("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
  });
  return ((await res.json()) as { client_id: string }).client_id;
}

function postAuthorize(
  app: ReturnType<typeof makeApp>,
  fields: Record<string, string>,
  ...rest: [env?: unknown]
) {
  return app.request(
    "/authorize",
    {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        response_type: "code",
        redirect_uri: "https://app/cb",
        code_challenge_method: "S256",
        resource: RESOURCE,
        ...fields,
      }).toString(),
    },
    ...(rest as [unknown]),
  );
}

/** Wrap a store so every key written is recorded. */
function recordingStorage(): KvLike & { keys: string[]; values: string[] } {
  const inner = createMemoryStorage();
  const keys: string[] = [];
  const values: string[] = [];
  return {
    keys,
    values,
    get: inner.get,
    delete: inner.delete,
    put: async (k, v, o) => {
      keys.push(k);
      values.push(v);
      return inner.put(k, v, o);
    },
  };
}

// ─── Login page ───────────────────────────────────────────────────────────────

describe("login page", () => {
  it("never echoes a submitted password back into the failed-login page", async () => {
    const app = makeApp({ identity: passwordIdentity });
    const clientId = await register(app);
    const res = await postAuthorize(app, {
      client_id: clientId,
      code_challenge: "abc",
      email: "a@b.c",
      password: "MySecretTypo",
    });
    expect(res.status).toBe(401);
    const html = await res.text();
    expect(html).not.toContain("MySecretTypo");
    expect(html).toContain('value="a@b.c"'); // non-secret fields are still refilled
  });

  it("passes passwords to verify untrimmed", async () => {
    let seen = "";
    const app = makeApp({
      identity: {
        ...passwordIdentity,
        verify: async (f) => ((seen = f.password!), null),
      },
    });
    const clientId = await register(app);
    await postAuthorize(app, {
      client_id: clientId,
      code_challenge: "abc",
      email: " a@b.c ",
      password: "  spaced  ",
    });
    expect(seen).toBe("  spaced  ");
  });

  it("lists the scopes being granted, with descriptions", async () => {
    const app = makeApp();
    const clientId = await register(app);
    const q = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://app/cb",
      code_challenge: "abc",
      scope: "read pay",
    });
    const html = await (await app.request(`/authorize?${q}`)).text();
    expect(html).toContain("<code>read</code> — See your stuff");
    expect(html).toContain("<code>pay</code> — Move money");
  });

  it("GET /authorize never fetches a client metadata document (that route isn't rate limited)", async () => {
    const realFetch = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = (async () => {
      fetched++;
      return new Response("{}");
    }) as typeof fetch;
    try {
      const app = makeApp({ allowClientIdMetadataDocuments: true });
      const q = new URLSearchParams({
        response_type: "code",
        client_id: "https://client.example/meta.json",
        redirect_uri: "https://client.example/cb",
        code_challenge: "abc",
      });
      expect((await app.request(`/authorize?${q}`)).status).toBe(200);
      expect(fetched).toBe(0);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("GET /authorize refuses to render for an unregistered client or redirect", async () => {
    const app = makeApp();
    const clientId = await register(app);
    const q = (client_id: string, redirect_uri: string) =>
      new URLSearchParams({
        response_type: "code",
        client_id,
        redirect_uri,
        code_challenge: "abc",
      });
    expect((await app.request(`/authorize?${q(clientId, "https://app/cb")}`)).status).toBe(200);
    expect((await app.request(`/authorize?${q("bogus", "https://app/cb")}`)).status).toBe(400);
    expect((await app.request(`/authorize?${q(clientId, "https://evil/cb")}`)).status).toBe(400);
  });

  it("POST /authorize rejects a response_type other than code", async () => {
    const app = makeApp();
    const clientId = await register(app);
    const ok = await postAuthorize(app, { client_id: clientId, code_challenge: "abc" });
    expect(ok.status).toBe(302);
    const bad = await postAuthorize(app, {
      client_id: clientId,
      code_challenge: "abc",
      response_type: "token",
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "unsupported_response_type" });
  });

  it("gives verify the request and the trusted IP, and ipExtractor the env", async () => {
    let ctxSeen: { request: Request; ip: string } | undefined;
    let envSeen: unknown;
    const app = makeApp({
      ipExtractor: (_req, env) => ((envSeen = env), "203.0.113.7"),
      identity: {
        fields: [{ name: "email", label: "Email" }],
        verify: async (_f, ctx) => ((ctxSeen = ctx), "user-1"),
      },
    });
    const clientId = await register(app);
    const env = { incoming: { socket: { remoteAddress: "203.0.113.7" } } };
    await postAuthorize(app, { client_id: clientId, code_challenge: "abc" }, env);
    expect(ctxSeen?.ip).toBe("203.0.113.7");
    expect(ctxSeen?.request).toBeInstanceOf(Request);
    expect(envSeen).toBe(env);
  });
});

// ─── Token lineage ────────────────────────────────────────────────────────────

describe("token family revocation", () => {
  const provider = () =>
    createOAuthProvider({ storage: createMemoryStorage(), scopes: SCOPES, baseUrl: BASE_URL });

  it("normal rotation leaves the previous access token valid until it expires", async () => {
    const p = provider();
    const { clientId, exchange } = await issueViaProvider(p);
    const t1 = await exchange();
    await p.refresh({ refreshToken: t1.refreshToken, clientId });
    expect(await p.verifyAccessToken(t1.accessToken)).not.toBeNull();
  });

  it("refresh reuse kills older-generation access tokens too", async () => {
    const p = provider();
    const { clientId, exchange } = await issueViaProvider(p);
    const t1 = await exchange();
    const t2 = await p.refresh({ refreshToken: t1.refreshToken, clientId });
    await expect(p.refresh({ refreshToken: t1.refreshToken, clientId })).rejects.toThrow(/reuse/);
    expect(await p.verifyAccessToken(t1.accessToken)).toBeNull();
    expect(await p.verifyAccessToken(t2.accessToken)).toBeNull();
  });

  it("/revoke kills older-generation access tokens too", async () => {
    const p = provider();
    const { clientId, exchange } = await issueViaProvider(p);
    const t1 = await exchange();
    const t2 = await p.refresh({ refreshToken: t1.refreshToken, clientId });
    expect(await p.revoke({ token: t2.refreshToken, clientId })).toEqual({ userId: "user-1" });
    expect(await p.verifyAccessToken(t1.accessToken)).toBeNull();
    expect(await p.verifyAccessToken(t2.accessToken)).toBeNull();
  });

  it("replaying a redeemed code fails and revokes the tokens it minted", async () => {
    const p = provider();
    const { exchange } = await issueViaProvider(p);
    const t1 = await exchange();
    expect(await p.verifyAccessToken(t1.accessToken)).not.toBeNull();
    await expect(exchange()).rejects.toThrow(/Invalid or expired/);
    expect(await p.verifyAccessToken(t1.accessToken)).toBeNull();
  });

  it("a replay from a different client_id is refused without revoking the session", async () => {
    const p = provider();
    const { code, exchange } = await issueViaProvider(p);
    const t1 = await exchange();
    await expect(
      p.exchangeCode({
        code,
        clientId: "someone-else",
        redirectUri: "https://app/cb",
        codeVerifier: "x",
        resource: RESOURCE,
      }),
    ).rejects.toThrow();
    expect(await p.verifyAccessToken(t1.accessToken)).not.toBeNull();
  });

  it("a client_id mismatch does not consume the code", async () => {
    const p = provider();
    const { code, exchange } = await issueViaProvider(p);
    await expect(
      p.exchangeCode({
        code,
        clientId: "someone-else",
        redirectUri: "https://app/cb",
        codeVerifier: "x",
        resource: RESOURCE,
      }),
    ).rejects.toThrow(/Client ID mismatch/);
    expect(await exchange()).toMatchObject({ userId: "user-1" });
  });

  it("a failed redemption (wrong PKCE verifier) consumes the code", async () => {
    const p = provider();
    const { exchange } = await issueViaProvider(p);
    await expect(exchange("wrong-verifier-wrong-verifier-wrong-verifier")).rejects.toThrow(/PKCE/);
    await expect(exchange()).rejects.toThrow(/Invalid or expired/);
  });

  it("binds tokens to this server even when authorize omitted resource", async () => {
    const storage = createMemoryStorage();
    const a = createOAuthProvider({ storage, scopes: SCOPES, baseUrl: BASE_URL });
    const b = createOAuthProvider({ storage, scopes: SCOPES, baseUrl: "https://other.test" });
    const t = await (await issueViaProvider(a, { resource: "" })).exchange();
    expect(await a.verifyAccessToken(t.accessToken)).not.toBeNull();
    // Same KV namespace, different server: the audience check must not be skipped.
    expect(await b.verifyAccessToken(t.accessToken)).toBeNull();
  });

  it("honours tokenTtl for access-token lifetime", async () => {
    let clock = 0;
    const p = createOAuthProvider({
      storage: createMemoryStorage(() => 0),
      scopes: SCOPES,
      baseUrl: BASE_URL,
      now: () => clock,
      tokenTtl: { accessTokenSeconds: 60 },
    });
    const t = await (await issueViaProvider(p)).exchange();
    expect(t.expiresIn).toBe(60);
    clock = 59_000;
    expect(await p.verifyAccessToken(t.accessToken)).not.toBeNull();
    clock = 61_000;
    expect(await p.verifyAccessToken(t.accessToken)).toBeNull();
  });

  it("createMcpServer passes tokenTtl through to /token", async () => {
    const app = makeApp({ tokenTtl: { accessTokenSeconds: 120 } });
    expect((await getTokenPair(app)).expiresIn).toBe(120);
  });
});

// ─── Storage ──────────────────────────────────────────────────────────────────

describe("storage", () => {
  it("stores authorization codes and confirmation tokens only as hashes", async () => {
    const storage = recordingStorage();
    const app = makeApp({
      storage,
      tools: [
        defineTool({
          name: "pay",
          description: "p",
          inputSchema: z.object({}),
          mutating: { preview: async () => ({ summary: "p", data: 1 }), execute: async () => "ok" },
        }),
      ],
    });
    const clientId = await register(app);
    const auth = await postAuthorize(app, { client_id: clientId, code_challenge: "abc" });
    const code = new URL(auth.headers.get("location")!).searchParams.get("code")!;
    const token = await getToken(app);
    const preview = (await callTool(app, token, "pay", {})) as {
      structuredContent: { confirmationToken: string };
    };
    const secrets = [code, preview.structuredContent.confirmationToken];
    for (const s of secrets) {
      expect(storage.keys.some((k) => k.includes(s))).toBe(false);
      expect(storage.values.some((v) => v.includes(s))).toBe(false);
    }
  });

  it("keeps user ids containing ':' from colliding with another user's keys", () => {
    expect(idempotencyKey("bob:x", "y")).not.toBe(idempotencyKey("bob", "x:y"));
    expect(userRateKey("a:1", 2)).not.toBe(userRateKey("a", 1));
  });
});

// ─── Two-phase confirm ────────────────────────────────────────────────────────

describe("confirm_request", () => {
  function payApp(hooks: McpServerConfig["hooks"] = {}) {
    const sent: number[] = [];
    const app = makeApp({
      hooks,
      tools: [
        defineTool({
          name: "send",
          description: "send money",
          inputSchema: z.object({ cents: z.number() }),
          mutating: {
            preview: async ({ cents }) => {
              if (cents > 1000) throw new ToolError("Insufficient funds");
              return { summary: `Send ${cents}`, data: { cents } };
            },
            execute: async ({ cents }) => {
              sent.push(cents);
              return `sent ${cents}`;
            },
          },
        }),
      ],
    });
    const preview = async (token: string, cents: number) =>
      (
        (await callTool(app, token, "send", { cents })) as {
          structuredContent: { confirmationToken: string };
        }
      ).structuredContent.confirmationToken;
    return { app, sent, preview };
  }

  it("refuses an idempotencyKey reused for a different confirmation instead of replaying", async () => {
    const { app, sent, preview } = payApp();
    const token = await getToken(app);
    const first = await preview(token, 25);
    const second = await preview(token, 400);
    const confirm = (confirmationToken: string, idempotencyKey: string) =>
      callTool(app, token, "confirm_request", { confirmationToken, idempotencyKey });

    expect(text(await confirm(first, "k"))).toBe("sent 25");
    // Same key, same token: a genuine retry still replays the cached result.
    expect(text(await confirm(first, "k"))).toBe("sent 25");

    const conflict = await confirm(second, "k");
    expect(conflict).toMatchObject({ isError: true });
    expect(text(conflict)).toMatch(/different confirmation/);
    expect(sent).toEqual([25]); // no false "executed", and the $400 didn't silently vanish…

    // …its token is still redeemable under a fresh key.
    expect(text(await confirm(second, "k2"))).toBe("sent 400");
    expect(sent).toEqual([25, 400]);
  });

  it("lets a retry with the same token and key re-run after execute throws", async () => {
    let attempts = 0;
    const app = makeApp({
      tools: [
        defineTool({
          name: "flaky",
          description: "f",
          inputSchema: z.object({}),
          mutating: {
            preview: async () => ({ summary: "f", data: null }),
            execute: async () => {
              if (++attempts === 1) throw new Error("transient");
              return "done";
            },
          },
        }),
      ],
    });
    const token = await getToken(app);
    const ct = (
      (await callTool(app, token, "flaky", {})) as {
        structuredContent: { confirmationToken: string };
      }
    ).structuredContent.confirmationToken;
    const args = { confirmationToken: ct, idempotencyKey: "retry" };
    expect(await callTool(app, token, "confirm_request", args)).toMatchObject({ isError: true });
    expect(text(await callTool(app, token, "confirm_request", args))).toBe("done");
    expect(attempts).toBe(2);
  });

  it("previews a tool whose parsed input isn't JSON-serializable (only data is stored)", async () => {
    const app = makeApp({
      tools: [
        defineTool({
          name: "big",
          description: "b",
          inputSchema: z.object({ n: z.coerce.bigint() }),
          mutating: {
            preview: async ({ n }) => ({ summary: `n=${n}`, data: { n: String(n) } }),
            execute: async ({ n }) => `got ${n}`,
          },
        }),
      ],
    });
    const token = await getToken(app);
    const res = await callTool(app, token, "big", { n: "12345678901234567890" });
    expect(res).not.toMatchObject({ isError: true });
    expect(res).toMatchObject({ structuredContent: { status: "preview" } });
  });

  it("flags every refused confirm as isError", async () => {
    const { app, preview } = payApp();
    const token = await getToken(app);
    const ct = await preview(token, 5);
    await callTool(app, token, "confirm_request", { confirmationToken: ct, idempotencyKey: "a" });
    const reused = await callTool(app, token, "confirm_request", {
      confirmationToken: ct,
      idempotencyKey: "b",
    });
    expect(reused).toMatchObject({ isError: true });
    expect(JSON.parse(text(reused))).toEqual({
      success: false,
      error: "This confirmation has expired or was already used.",
    });
  });

  it("gives onMutation the data, result and idempotency key — once", async () => {
    const events: unknown[] = [];
    const { app, preview } = payApp({ onMutation: async (e) => void events.push(e) });
    const token = await getToken(app);
    const ct = await preview(token, 7);
    const args = { confirmationToken: ct, idempotencyKey: "m1" };
    await callTool(app, token, "confirm_request", args);
    await callTool(app, token, "confirm_request", args); // replay
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      userId: "user-1",
      toolName: "send",
      summary: "Send 7",
      data: { cents: 7 },
      result: { content: [{ type: "text", text: "sent 7" }] },
      idempotencyKey: "m1",
    });
  });

  it("marks ToolError rejections as expected in onToolError, raw throws as not", async () => {
    const events: Array<{ expected: boolean; phase: string }> = [];
    const app = makeApp({
      hooks: { onToolError: async (e) => void events.push(e) },
      tools: [
        defineTool({
          name: "reject",
          description: "r",
          inputSchema: z.object({}),
          handler: async () => {
            throw new ToolError("nope");
          },
        }),
        defineTool({
          name: "crash",
          description: "c",
          inputSchema: z.object({}),
          handler: async () => {
            throw new Error("db down");
          },
        }),
      ],
    });
    const token = await getToken(app);
    await callTool(app, token, "reject", {});
    await callTool(app, token, "crash", {});
    await new Promise((r) => setTimeout(r, 0));
    expect(events.map((e) => e.expected)).toEqual([true, false]);
  });
});

// ─── Hooks & runtime ──────────────────────────────────────────────────────────

describe("audit hooks", () => {
  it("includes userId on token_issued, token_refreshed and token_revoked", async () => {
    const events: Array<{ event: string; userId?: string }> = [];
    const app = makeApp({ hooks: { onAudit: async (e) => void events.push(e) } });
    const { clientId, refreshToken: refresh_token } = await getTokenPair(app);
    const refreshed = (await (
      await app.request("/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token,
          client_id: clientId,
        }).toString(),
      })
    ).json()) as { refresh_token: string };
    await app.request("/revoke", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshed.refresh_token, client_id: clientId }).toString(),
    });
    await new Promise((r) => setTimeout(r, 0));
    const byEvent = Object.fromEntries(events.map((e) => [e.event, e.userId]));
    expect(byEvent).toMatchObject({
      token_issued: "user-1",
      token_refreshed: "user-1",
      token_revoked: "user-1",
    });
  });
});

describe("waitUntil", () => {
  it("hands fire-and-forget hooks to the runtime's waitUntil", async () => {
    const kept: Promise<unknown>[] = [];
    const executionCtx = {
      waitUntil: (p: Promise<unknown>) => void kept.push(p),
      passThroughOnException: () => {},
      props: {},
    };
    let called = 0;
    const app = makeApp({
      hooks: {
        onToolCall: async () => void called++,
        onAudit: async () => void called++,
      },
      tools: [
        defineTool({
          name: "hi",
          description: "h",
          inputSchema: z.object({}),
          handler: async () => "hi",
        }),
      ],
    });
    const reg = await app.request(
      "/register",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
      },
      {},
      executionCtx,
    );
    expect(reg.status).toBe(201);
    expect(kept).toHaveLength(1); // onAudit(client_registered)

    const token = await getToken(app);
    const res = await app.request(
      "/mcp",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "hi", arguments: {} },
        }),
      },
      {},
      executionCtx,
    );
    expect(res.status).toBe(200);
    await res.text();
    expect(kept).toHaveLength(2); // + onToolCall
    await Promise.all(kept);
    expect(called).toBeGreaterThanOrEqual(2);
  });
});

describe("waitUntil guard", () => {
  it("ignores an execution context without a callable waitUntil", async () => {
    const app = makeApp({ hooks: { onAudit: async () => {} } });
    const { clientId } = await getTokenPair(app);
    expect(clientId).toBeTruthy();
    const res = await app.request(
      "/register",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
      },
      {},
      { waitUntil: undefined, passThroughOnException: () => {}, props: {} } as never,
    );
    expect(res.status).toBe(201);
  });
});

describe("Retry-After", () => {
  it("is the time until the hourly window resets", () => {
    let clock = 0;
    const rl = createRateLimiter({ storage: createMemoryStorage(), now: () => clock });
    expect(rl.secondsUntilReset?.()).toBe(3600);
    clock = 3_599_000;
    expect(rl.secondsUntilReset?.()).toBe(1);
    clock = 3_600_000 + 600_000;
    expect(rl.secondsUntilReset?.()).toBe(3000);
  });

  it("is sent on OAuth-endpoint 429s and on /mcp 429s", async () => {
    const inRange = (r: Response) => {
      expect(r.status).toBe(429);
      const ra = Number(r.headers.get("retry-after"));
      expect(ra).toBeGreaterThan(0);
      expect(ra).toBeLessThanOrEqual(3600);
    };
    const oauth = makeApp({ rateLimits: { ipTokenPerHour: 0 } });
    inRange(
      await oauth.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
    );
    const mcp = makeApp({ rateLimits: { userPerHour: 0 } });
    inRange(await mcpRequest(mcp, await getToken(mcp), "tools/list"));
  });
});
