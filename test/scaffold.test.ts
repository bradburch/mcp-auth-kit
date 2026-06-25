import { describe, it, expect } from "vitest";
import { version } from "../src/index.js";

describe("scaffold", () => {
  it("exposes a version string", () => {
    expect(typeof version).toBe("string");
  });
});
