import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchClientIdMetadata } from "../../src/oauth/cimd.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchClientIdMetadata", () => {
  it("returns the parsed metadata for a valid document", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    const doc = {
      client_id: clientId,
      client_name: "Example Client",
      redirect_uris: ["https://app.example.com/callback"],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(doc), { status: 200 })),
    );

    expect(await fetchClientIdMetadata(clientId)).toEqual({
      clientId,
      clientName: "Example Client",
      redirectUris: ["https://app.example.com/callback"],
    });
  });

  it("rejects a document whose client_id doesn't match the fetch URL", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              client_id: "https://evil.example.com/client.json",
              redirect_uris: ["https://app.example.com/callback"],
            }),
            { status: 200 },
          ),
      ),
    );

    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });

  it("refuses a non-https client_id without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("http://app.example.com/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a client_id with no path component", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("https://app.example.com")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks loopback and private-range hosts without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    expect(await fetchClientIdMetadata("https://127.0.0.1/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://192.168.1.5/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://10.0.0.1/client.json")).toBeNull();
    expect(await fetchClientIdMetadata("https://localhost/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects a document larger than the size cap", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    const huge = "x".repeat(20_000);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(huge, { status: 200 })),
    );
    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });

  it("rejects a document missing redirect_uris", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ client_id: clientId }), { status: 200 })),
    );
    expect(await fetchClientIdMetadata(clientId)).toBeNull();
  });
});
