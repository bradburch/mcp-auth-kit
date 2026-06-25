// Shared test helpers for driving the kit's MCP server as a Hono app.
import type { Hono } from "hono";

/** Compute an S256 PKCE challenge from a fixed verifier (deterministic for tests). */
export async function pkce() {
  const verifier = "verifier-fixed-string-1234567890-abcdefghij";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return { verifier, challenge };
}

/** Drive register → authorize(verify) → token; return the issued access token. */
export async function getToken(app: Hono): Promise<string> {
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

/**
 * POST a `tools/call` JSON-RPC request for `name` with `args` and return the parsed
 * JSON-RPC result payload (i.e. `body.result` — the tool's `{ content, isError? }`).
 */
export async function callTool(
  app: Hono,
  token: string,
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
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
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
  const body = await res.json();
  return body.result;
}
