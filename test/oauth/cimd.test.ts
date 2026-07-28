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

  it("blocks IPv6 loopback [::1] without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("https://[::1]/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks IPv4-mapped IPv6 private ranges without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    // ::ffff:192.168.1.1 is an IPv4-mapped IPv6 form pointing to private range
    expect(await fetchClientIdMetadata("https://[::ffff:192.168.1.1]/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks IPv6 link-local without making a request", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    expect(await fetchClientIdMetadata("https://[fe80::1]/client.json")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("times out a slow-loris body-read attack", async () => {
    const clientId = "https://app.example.com/oauth/client.json";
    let readerAbortCalled = false;

    // Create a mock stream that never resolves (simulates slow-loris on body).
    const mockStream = new ReadableStream({
      start(controller) {
        // Immediately enqueue a small chunk to avoid early EOF.
        controller.enqueue(new TextEncoder().encode("{"));
        // Then hang indefinitely — no more chunks, no close.
      },
      cancel() {
        readerAbortCalled = true;
      },
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(mockStream, { status: 200 }) as Response,
      ),
    );

    // Should timeout after 3000ms and return null without hanging forever.
    const result = await Promise.race([
      fetchClientIdMetadata(clientId),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Test timeout: fetchClientIdMetadata hung")), 5000),
      ),
    ]);

    expect(result).toBeNull();
    // The abort controller should have cancelled the reader.
    expect(readerAbortCalled).toBe(true);
  });

  it("does not throw even if reader.cancel() rejects on an errored stream", async () => {
    const clientId = "https://app.example.com/oauth/client.json";

    // Simulate a real errored stream where cancel() itself rejects (happens when the stream
    // is already errored by the abort signal on real fetch implementations).
    const mockStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{"));
      },
      cancel() {
        // Simulate an already-errored stream where cancel() rejects (as in real fetch).
        throw new Error("AbortError: This operation was aborted");
      },
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(mockStream, { status: 200 }) as Response,
      ),
    );

    // Should timeout after 3000ms and return null, NOT throw.
    const result = await Promise.race([
      fetchClientIdMetadata(clientId),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Test timeout")), 5000),
      ),
    ]);

    // Despite cancel() rejecting, the function should still resolve to null.
    expect(result).toBeNull();
  });
});
