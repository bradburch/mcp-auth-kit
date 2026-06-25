import { describe, it, expect } from "vitest";
import { z } from "zod";
import { createMcpServer } from "../src/server.js";
import { createMemoryStorage } from "../src/storage/memory.js";

async function pkce() {
  const verifier = "verifier-fixed-string-1234567890-abcdefghij";
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return { verifier, challenge };
}

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
        annotations: { readOnlyHint: true },
        handler: async (input: any) => ({
          content: [{ type: "text", text: input.msg }],
        }),
      },
    ],
  });
}

// Helper: drive register → authorize(verify) → token, return access token.
async function getToken(app: ReturnType<typeof makeApp>) {
  const reg = await (
    await app.request("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://app/cb"] }),
    })
  ).json();
  const { challenge, verifier } = await pkce();
  const authRes = await app.request("/authorize", {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code",
      client_id: reg.client_id,
      redirect_uri: "https://app/cb",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "s",
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
        client_id: reg.client_id,
        redirect_uri: "https://app/cb",
        code_verifier: verifier,
        resource: "https://example.test/mcp",
      }).toString(),
    })
  ).json();
  return tok.access_token as string;
}

describe("createMcpServer read tools", () => {
  it("lists the echo tool for an authenticated caller", async () => {
    const app = makeApp();
    const token = await getToken(app);
    const res = await app.request("/", {
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
    expect(res.status).toBe(200);
    const body = await res.json();
    const names = body.result.tools.map((t: any) => t.name);
    expect(names).toContain("echo");
  });

  it("rejects an unauthenticated tool call with 401", async () => {
    const res = await makeApp().request("/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      }),
    });
    expect(res.status).toBe(401);
  });
});
