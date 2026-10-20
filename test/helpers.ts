// Shared test helpers for driving the kit's MCP server as a Hono app.
import type { Hono } from "hono";
import { pkceS256Challenge } from "../src/crypto.js";
import type { OAuthProvider } from "../src/oauth/provider.js";

/** Compute an S256 PKCE challenge from a fixed verifier (deterministic for tests). */
export async function pkce() {
  const verifier = "verifier-fixed-string-1234567890-abcdefghij";
  return { verifier, challenge: await pkceS256Challenge(verifier) };
}

/**
 * Drive register → authorize(verify) → token over HTTP; return the issued pair and client.
 * `scope` is sent on the authorize request when given (omitted = the default scopes).
 */
export async function getTokenPair(
  app: Hono,
  { scope }: { scope?: string } = {},
): Promise<{ accessToken: string; refreshToken: string; clientId: string; expiresIn: number }> {
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
      ...(scope !== undefined && { scope }),
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
  return {
    accessToken: tok.access_token,
    refreshToken: tok.refresh_token,
    clientId: reg.client_id,
    expiresIn: tok.expires_in,
  };
}

/** Drive register → authorize(verify) → token; return the issued access token. */
export async function getToken(app: Hono): Promise<string> {
  return (await getTokenPair(app)).accessToken;
}

/**
 * Drive register → issueAuthCode → (deferred) exchangeCode directly against a provider for
 * `https://app/cb` / user-1. `exchange` redeems the code; pass a verifier to override PKCE.
 */
export async function issueViaProvider(
  p: OAuthProvider,
  { resource = "https://example.test/mcp", scope = ["account:read"] } = {},
) {
  const { clientId } = await p.registerClient({ redirectUris: ["https://app/cb"] });
  const { challenge, verifier } = await pkce();
  const { code } = await p.issueAuthCode({
    clientId,
    redirectUri: "https://app/cb",
    codeChallenge: challenge,
    scope,
    userId: "user-1",
    resource,
  });
  const exchange = (codeVerifier = verifier) =>
    p.exchangeCode({ code, clientId, redirectUri: "https://app/cb", codeVerifier, resource });
  return { clientId, code, exchange };
}

/** The first text block of a tool result. */
export const toolText = (result: unknown) =>
  (result as { content: Array<{ text: string }> }).content[0]!.text;

/** The per-request `_meta` envelope a 2026-07-28 client attaches to every request. */
export const MODERN_META = {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { name: "test-client", version: "1.0.0" },
  "io.modelcontextprotocol/clientCapabilities": {},
};

/**
 * POST a 2026-07-28 (modern) JSON-RPC request to /mcp: `_meta` envelope in params plus the
 * required `MCP-Protocol-Version` / `Mcp-Method` (and, for tools/call, `Mcp-Name`) headers.
 */
export function mcpRequest(
  app: Hono,
  token: string | null,
  method: string,
  params: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Promise<Response> {
  const name: Record<string, string> =
    method === "tools/call" ? { "mcp-name": String(params.name) } : {};
  return Promise.resolve(
    app.request("/mcp", {
      method: "POST",
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : ({} as Record<string, string>)),
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": method,
        ...name,
        ...headers,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method,
        params: { ...params, _meta: MODERN_META },
      }),
    }),
  );
}

/** Parse a JSON-RPC response body served either as JSON or as a single-event SSE stream
 *  (the SDK's 2025-era stateless fallback always answers over SSE). */
export async function readRpc(res: Response): Promise<any> {
  const text = await res.text();
  if (!res.headers.get("content-type")?.includes("text/event-stream")) return JSON.parse(text);
  const data = text.split("\n").find((l) => l.startsWith("data: "));
  return JSON.parse(data!.slice("data: ".length));
}

/**
 * POST a `tools/call` request for `name` with `args` and return the parsed JSON-RPC result
 * payload (i.e. `body.result` — the tool's `{ content, isError? }`), minus the wire-only
 * `_meta` / `resultType` fields the SDK adds to every 2026-07-28 result.
 */
export async function callTool(
  app: Hono,
  token: string,
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const res = await mcpRequest(app, token, "tools/call", { name, arguments: args });
  const body = await readRpc(res);
  if (!body.result) return body.result;
  const { _meta, resultType, ...result } = body.result;
  return result;
}
