/** Maximum request body size (1 MB). Requests larger than this are rejected with HTTP 413. */
export const MAX_BODY_BYTES = 1_000_000;

/**
 * Check whether a request exceeds the body size cap.
 *
 * Returns an HTTP 413 Response if:
 *  - The Content-Length header is present and exceeds MAX_BODY_BYTES, OR
 *  - The already-read body string's byte length exceeds MAX_BODY_BYTES.
 *
 * Returns null when the body is within the allowed size.
 */
export function bodyTooLarge(req: Request): Response | null {
  const contentLength = req.headers.get("Content-Length");
  if (contentLength !== null) {
    const len = Number.parseInt(contentLength, 10);
    if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
      return new Response("Request body too large", { status: 413 });
    }
  }
  return null;
}

/**
 * Check whether an already-read body string exceeds the byte cap.
 * Returns an HTTP 413 Response if too large, null otherwise.
 */
export function readBodyTooLarge(body: string): Response | null {
  const byteLen = new TextEncoder().encode(body).byteLength;
  if (byteLen > MAX_BODY_BYTES) {
    return new Response("Request body too large", { status: 413 });
  }
  return null;
}
