// test/oauth/revoke.test.ts — RFC 7009 revocation coverage
import { describe, it, expect } from "vitest";
import { createMcpServer } from "../../src/server.js";
import { createMemoryStorage } from "../../src/storage/memory.js";
import { pkce } from "../helpers.js";
import { z } from "zod";

function makeApp() {
  return createMcpServer({
    baseUrl: "https://example.test",
    storage: createMemoryStorage(),
    scopes: [{ name: "account:read", default: true }],
    identity: {
      fields: [{ name: "email", label: "Email" }],
      verify: async () => "user-1",
    },
    tools: [
      {
        name: "echo",
        description: "echoes input",
        inputSchema: z.object({ msg: z.string() }),
        handler: async (input: any) => ({
          content: [{ type: "text", text: input.msg }],
        }),
      },
    ],
  });
}

/** Register a client and return the full OAuth token response (access + refresh). */
async function getTokenPair(
  app: ReturnType<typeof makeApp>,
): Promise<{ accessToken: string; refreshToken: string; clientId: string }> {
  const reg = await (
    await app.request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
    })
  ).json();
  const clientId = reg.client_id as string;
  const { challenge, verifier } = await pkce();
  const authRes = await app.request("/authorize", {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://app/cb",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: "https://example.test/mcp",
      email: "a@b.c",
    }).toString(),
  });
  const location = authRes.headers.get("location")!;
  const code = new URL(location).searchParams.get("code")!;
  const tok = await (
    await app.request("/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: "https://app/cb",
        code_verifier: verifier,
        resource: "https://example.test/mcp",
      }).toString(),
    })
  ).json();
  return {
    accessToken: tok.access_token as string,
    refreshToken: tok.refresh_token as string,
    clientId,
  };
}

/** POST /revoke helper */
async function revoke(app: ReturnType<typeof makeApp>, token: string, clientId: string) {
  return app.request("/revoke", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token, client_id: clientId }).toString(),
  });
}

/** GET a tools/list response status from /mcp with the given Bearer token. */
async function mcpStatus(app: ReturnType<typeof makeApp>, token: string): Promise<number> {
  const res = await app.request("/mcp", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    }),
  });
  return res.status;
}

describe("POST /revoke (RFC 7009)", () => {
  it("revoking a valid access token causes subsequent /mcp calls to fail with 401", async () => {
    const app = makeApp();
    const { accessToken, clientId } = await getTokenPair(app);

    // Token works before revocation.
    expect(await mcpStatus(app, accessToken)).toBe(200);

    const res = await revoke(app, accessToken, clientId);
    expect(res.status).toBe(200);

    // Token is dead after revocation.
    expect(await mcpStatus(app, accessToken)).toBe(401);
  });

  it("returns 200 for an unknown token (RFC 7009 §2.2 — no error for unknown tokens)", async () => {
    const app = makeApp();
    const { clientId } = await getTokenPair(app);
    const res = await revoke(app, "totally-unknown-token", clientId);
    expect(res.status).toBe(200);
  });

  it("refuses to revoke a token owned by a different client (returns 401)", async () => {
    const app = makeApp();
    const { accessToken } = await getTokenPair(app);

    // Register a second, independent client.
    const reg2 = await (
      await app.request("/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://other/cb"] }),
      })
    ).json();
    const otherClientId = reg2.client_id as string;

    // Attempt revocation as the other client — must be rejected.
    const res = await revoke(app, accessToken, otherClientId);
    expect(res.status).toBe(401);

    // Token must still be valid (revocation was refused).
    expect(await mcpStatus(app, accessToken)).toBe(200);
  });

  it("revoking an access token also revokes the paired refresh token", async () => {
    const app = makeApp();
    const { accessToken, refreshToken, clientId } = await getTokenPair(app);

    await revoke(app, accessToken, clientId);

    // Attempt to use the paired refresh token — must fail.
    const res = await app.request("/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: clientId,
      }).toString(),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_grant");
  });
});
