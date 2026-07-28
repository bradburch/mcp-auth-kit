import { describe, it, expect, vi, afterEach } from "vitest";
import { createMemoryStorage } from "../../src/storage/memory.js";
import { createOAuthProvider } from "../../src/oauth/provider.js";
import { pkce } from "../helpers.js";

const scopes = [
  { name: "account:read", default: true },
  { name: "booking:write", default: true },
];
const baseUrl = "https://example.test";
const resource = `${baseUrl}/mcp`;

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
    await expect(p.refresh({ refreshToken: t1.refreshToken, clientId })).rejects.toThrow();
  });

  it("drops unsupported scopes and falls back to defaults", () => {
    const p = provider();
    expect(p.normalizeScopes(["bogus"])).toEqual(["account:read", "booking:write"]);
    expect(p.normalizeScopes(["account:read"])).toEqual(["account:read"]);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Client ID Metadata Document resolution", () => {
  const cimdClientId = "https://app.example.com/oauth/client.json";

  function stubCimdDocument(redirectUris: string[]) {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ client_id: cimdClientId, redirect_uris: redirectUris }), {
            status: 200,
          }),
      ),
    );
  }

  it("resolves an unregistered https client_id via CIMD when enabled", async () => {
    stubCimdDocument(["https://app.example.com/callback"]);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    const ok = await provider.validateClientRedirect(
      cimdClientId,
      "https://app.example.com/callback",
    );
    expect(ok).toBe(true);
  });

  it("rejects a redirect_uri not listed in the CIMD document", async () => {
    stubCimdDocument(["https://app.example.com/callback"]);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    expect(
      await provider.validateClientRedirect(cimdClientId, "https://app.example.com/other"),
    ).toBe(false);
  });

  it("does not attempt CIMD resolution when disabled (default)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const provider = createOAuthProvider({ storage: createMemoryStorage(), scopes, baseUrl });

    expect(
      await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback"),
    ).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("caches the CIMD result so a second lookup doesn't re-fetch", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            client_id: cimdClientId,
            redirect_uris: ["https://app.example.com/callback"],
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback");
    await provider.validateClientRedirect(cimdClientId, "https://app.example.com/callback");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("caches a failed CIMD fetch so a second lookup doesn't re-fetch", async () => {
    const fetchMock = vi.fn(async () => new Response("not found", { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);
    const provider = createOAuthProvider({
      storage: createMemoryStorage(),
      scopes,
      baseUrl,
      allowClientIdMetadataDocuments: true,
    });

    const first = await provider.validateClientRedirect(
      cimdClientId,
      "https://app.example.com/callback",
    );
    const second = await provider.validateClientRedirect(
      cimdClientId,
      "https://app.example.com/callback",
    );
    expect(first).toBe(false);
    expect(second).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
