// test/rate-limit.test.ts
import { describe, it, expect } from "vitest";
import { createMemoryStorage } from "../src/storage/memory.js";
import { createRateLimiter } from "../src/rate-limit.js";

describe("rate limiter", () => {
  it("allows up to the per-user limit then blocks", async () => {
    const limiter = createRateLimiter({
      storage: createMemoryStorage(),
      now: () => 0,
      config: { userPerHour: 3 },
    });
    expect(await limiter.checkUser("u")).toBe(true);
    expect(await limiter.checkUser("u")).toBe(true);
    expect(await limiter.checkUser("u")).toBe(true);
    expect(await limiter.checkUser("u")).toBe(false);
  });
});
