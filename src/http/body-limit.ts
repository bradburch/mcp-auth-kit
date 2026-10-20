/** Maximum request body size (1 MB). Requests larger than this are rejected with HTTP 413. */
export const MAX_BODY_BYTES = 1_000_000;

/** The 413 response returned whenever the body cap is exceeded. */
function tooLargeResponse(): Response {
  return new Response("Request body too large", { status: 413 });
}

/**
 * Cheap pre-check: reject when an honest `Content-Length` header already exceeds the cap,
 * before reading a single byte. Returns a 413 Response, or null to proceed to a full read.
 */
function bodyTooLarge(req: Request): Response | null {
  const contentLength = req.headers.get("Content-Length");
  if (contentLength !== null) {
    const len = Number.parseInt(contentLength, 10);
    if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
      return tooLargeResponse();
    }
  }
  return null;
}

/**
 * Read a request body with the 1 MB cap enforced WHILE streaming: bytes are accumulated
 * chunk by chunk and the read is aborted the instant the running total exceeds the cap, so a
 * request that omits or lies about `Content-Length` (e.g. chunked transfer-encoding) cannot
 * buffer an unbounded body into memory. Returns the decoded body text, or a 413 Response.
 */
export async function readCappedBody(req: Request): Promise<string | Response> {
  const pre = bodyTooLarge(req);
  if (pre) return pre;

  return (await readStreamCapped(req.body, MAX_BODY_BYTES)) ?? tooLargeResponse();
}

/**
 * Decode a byte stream as text, cancelling the read the moment it exceeds `maxBytes` (→ null).
 * With a `signal`, an abort also cancels the read and rejects. Stream errors propagate.
 */
export async function readStreamCapped(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<string | null> {
  if (!body) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const aborted =
    signal &&
    new Promise<never>((_, reject) =>
      signal.addEventListener("abort", () => reject(new Error("abort"))),
    );
  let total = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await (aborted
        ? Promise.race([reader.read(), aborted])
        : reader.read());
      if (done) return text + decoder.decode();
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
  } catch (e) {
    // An errored stream (e.g. after abort) may reject cancel() too — that's expected.
    await reader.cancel().catch(() => {});
    throw e;
  }
}
