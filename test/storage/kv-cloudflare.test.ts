import { describe, it, expect } from "vitest";
import { createCloudflareKvStorage } from "../../src/storage/kv-cloudflare.js";

function fakeKv() {
  const calls: any[] = [];
  const map = new Map<string, string>();
  return {
    calls,
    get: async (k: string) => map.get(k) ?? null,
    put: async (k: string, v: string, opts?: { expirationTtl?: number }) => {
      calls.push({ k, v, opts });
      map.set(k, v);
    },
    delete: async (k: string) => void map.delete(k),
  };
}

describe("cloudflare kv adapter", () => {
  it("maps ttlSeconds to expirationTtl", async () => {
    const kv = fakeKv();
    const storage = createCloudflareKvStorage(kv);
    await storage.put("k", "v", { ttlSeconds: 90 });
    expect(kv.calls[0].opts).toEqual({ expirationTtl: 90 });
    expect(await storage.get("k")).toBe("v");
  });

  it("omits expiration when no ttl given", async () => {
    const kv = fakeKv();
    const storage = createCloudflareKvStorage(kv);
    await storage.put("k", "v");
    expect(kv.calls[0].opts).toBeUndefined();
  });
});
