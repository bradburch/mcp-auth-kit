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
export function bodyTooLarge(req: Request): Response | null {
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

  const body = req.body;
  if (!body) return "";

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return tooLargeResponse();
    }
    chunks.push(value);
  }

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(buf);
}
