import { describe, it, expect } from "vitest";
import { createMemoryStorage } from "../../src/storage/memory.js";

describe("memory storage", () => {
  it("round-trips a value", async () => {
    const kv = createMemoryStorage();
    await kv.put("k", "v");
    expect(await kv.get("k")).toBe("v");
  });

  it("returns null for missing keys", async () => {
    const kv = createMemoryStorage();
    expect(await kv.get("nope")).toBeNull();
  });

  it("deletes keys", async () => {
    const kv = createMemoryStorage();
    await kv.put("k", "v");
    await kv.delete("k");
    expect(await kv.get("k")).toBeNull();
  });

  it("expires values after ttlSeconds", async () => {
    let t = 1_000_000;
    const kv = createMemoryStorage(() => t);
    await kv.put("k", "v", { ttlSeconds: 60 });
    t += 59_000;
    expect(await kv.get("k")).toBe("v");
    t += 2_000;
    expect(await kv.get("k")).toBeNull();
  });
});
