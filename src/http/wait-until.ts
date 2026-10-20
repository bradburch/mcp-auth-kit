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
    if (typeof ec?.waitUntil !== "function") return undefined;
    return (p) => ec.waitUntil(p);
  } catch {
    return undefined;
  }
}

/**
 * Run a hook without awaiting it: errors are swallowed (a misbehaving hook never fails the
 * request) and the promise is handed to `waitUntil` when the runtime has one. Never throws.
 */
export function fireAndForget(fn: () => unknown, waitUntil: WaitUntil | undefined): void {
  const p = Promise.resolve()
    .then(fn)
    .catch(() => {});
  try {
    waitUntil?.(p);
  } catch {
    // A broken waitUntil must not turn a completed request into an error.
  }
}
