import { describe, it, expect } from "vitest";
import { sha256Hex } from "../src/crypto.js";

describe("sha256Hex", () => {
  it('produces the known SHA-256 of "abc"', async () => {
    expect(await sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});
