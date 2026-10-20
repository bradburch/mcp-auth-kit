import type { Context } from "hono";

/** Keeps a fire-and-forget promise alive after the response is sent. */
export type WaitUntil = (promise: Promise<unknown>) => void;

/**
 * The runtime's `waitUntil` (Cloudflare Workers, edge runtimes) so fire-and-forget hooks
 * aren't cut off once the response is returned. Hono's `c.executionCtx` throws where the
 * runtime has none (Node, Bun) — there the promise simply runs to completion on its own.
 */
export function waitUntilFor(c: Context): WaitUntil | undefined {
  try {
    const ec = c.executionCtx;
    return (p) => ec.waitUntil(p);
  } catch {
    return undefined;
  }
}

/** Seconds until the current fixed one-hour rate-limit window resets (for `Retry-After`). */
export function secondsUntilHourWindowResets(now = Date.now()): number {
  return 3600 - (Math.floor(now / 1000) % 3600);
}
