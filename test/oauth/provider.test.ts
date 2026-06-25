import { describe, it, expect } from "vitest";
import { createMemoryStorage } from "../../src/storage/memory.js";
import { createOAuthProvider } from "../../src/oauth/provider.js";

const scopes = [
  { name: "account:read", default: true },
  { name: "booking:write", default: true },
];
const baseUrl = "https://example.test";
const resource = `${baseUrl}/mcp`;

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

function provider() {
  return createOAuthProvider({
    storage: createMemoryStorage(),
    scopes,
    baseUrl,
  });
}

describe("oauth provider", () => {
  it("completes register → authorize → token → verify", async () => {
    const p = provider();
    const { clientId } = await p.registerClient({
      redirectUris: ["https://app/cb"],
    });
    const { challenge, verifier } = await pkce();
    const { code } = await p.issueAuthCode({
      clientId,
      redirectUri: "https://app/cb",
      codeChallenge: challenge,
      scope: ["account:read"],
      userId: "user-1",
      resource,
    });
    const tokens = await p.exchangeCode({
      code,
      clientId,
      redirectUri: "https://app/cb",
      codeVerifier: verifier,
      resource,
    });
    expect(tokens.accessToken).toBeTruthy();
    const verified = await p.verifyAccessToken(tokens.accessToken);
    expect(verified).toEqual({ userId: "user-1", scopes: ["account:read"] });
  });

  it("rejects a wrong PKCE verifier", async () => {
    const p = provider();
    const { clientId } = await p.registerClient({
      redirectUris: ["https://app/cb"],
    });
    const { challenge } = await pkce();
    const { code } = await p.issueAuthCode({
      clientId,
      redirectUri: "https://app/cb",
      codeChallenge: challenge,
      scope: ["account:read"],
      userId: "user-1",
      resource,
    });
    await expect(
      p.exchangeCode({
        code,
        clientId,
        redirectUri: "https://app/cb",
        codeVerifier: "wrong",
        resource,
      }),
    ).rejects.toThrow();
  });

  it("rejects a resource mismatch at exchange", async () => {
    const p = provider();
    const { clientId } = await p.registerClient({
      redirectUris: ["https://app/cb"],
    });
    const { challenge, verifier } = await pkce();
    const { code } = await p.issueAuthCode({
      clientId,
      redirectUri: "https://app/cb",
      codeChallenge: challenge,
      scope: ["account:read"],
      userId: "user-1",
      resource,
    });
    await expect(
      p.exchangeCode({
        code,
        clientId,
        redirectUri: "https://app/cb",
        codeVerifier: verifier,
        resource: "https://evil.test",
      }),
    ).rejects.toThrow();
  });

  it("rotates refresh tokens (old one stops working)", async () => {
    const p = provider();
    const { clientId } = await p.registerClient({
      redirectUris: ["https://app/cb"],
    });
    const { challenge, verifier } = await pkce();
    const { code } = await p.issueAuthCode({
      clientId,
      redirectUri: "https://app/cb",
      codeChallenge: challenge,
      scope: ["account:read"],
      userId: "user-1",
      resource,
    });
    const t1 = await p.exchangeCode({
      code,
      clientId,
      redirectUri: "https://app/cb",
      codeVerifier: verifier,
      resource,
    });
    const t2 = await p.refresh({ refreshToken: t1.refreshToken, clientId });
    expect(t2.accessToken).not.toBe(t1.accessToken);
    await expect(
      p.refresh({ refreshToken: t1.refreshToken, clientId }),
    ).rejects.toThrow();
  });

  it("drops unsupported scopes and falls back to defaults", () => {
    const p = provider();
    expect(p.normalizeScopes(["bogus"])).toEqual([
      "account:read",
      "booking:write",
    ]);
    expect(p.normalizeScopes(["account:read"])).toEqual(["account:read"]);
  });
});
