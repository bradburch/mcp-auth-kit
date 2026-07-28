// OAuth Client ID Metadata Documents (CIMD) — draft-ietf-oauth-client-id-metadata-document-00.
// MCP 2026-07-28 deprecates Dynamic Client Registration in favor of this: the client_id IS
// an HTTPS URL pointing at a JSON document describing the client (see the MCP spec's
// "Client ID Metadata Documents" section, deprecating RFC 7591 DCR per changelog item 4).

/** Response body cap for a metadata document fetch — these are small JSON files. */
const MAX_DOCUMENT_BYTES = 16 * 1024;

/** Abort a metadata fetch that hangs (e.g. a slow-loris endpoint). */
const FETCH_TIMEOUT_MS = 3000;

/** A validated Client ID Metadata Document, narrowed to the fields MCP needs. */
export interface ClientIdMetadata {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
}

/**
 * Hostnames/IP literals that must never be fetched — loopback, link-local, and RFC1918
 * private ranges. Best-effort SSRF guard: it blocks the obvious literal forms, but does NOT
 * resolve DNS and pin the connection, so it cannot stop DNS-rebinding against a public
 * hostname that later resolves to a private address. Deployments with strict SSRF
 * requirements should also enforce network-level egress controls (e.g. an egress proxy
 * that resolves and filters at connect time).
 */
function isBlockedHost(hostname: string): boolean {
  let h = hostname.toLowerCase();

  // Strip IPv6 brackets if present (WHATWG URL returns '[::1]', not '::1').
  if (h.startsWith("[") && h.endsWith("]")) {
    h = h.slice(1, -1);
  }

  // IPv6 loopback and link-local ranges.
  if (h === "::1" || h === "0.0.0.0" || h === "localhost") return true;

  // IPv6 link-local (fe80::/10).
  if (/^fe80:/i.test(h)) return true;

  // IPv4-mapped IPv6: ::ffff:a.b.c.d (dotted form) or ::ffff:XXXX:XXXX (hex form normalized by WHATWG URL).
  const ipv4MappedDottedMatch = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (ipv4MappedDottedMatch) {
    const quad = ipv4MappedDottedMatch[1];
    if (/^127\./.test(quad)) return true;
    if (/^10\./.test(quad)) return true;
    if (/^192\.168\./.test(quad)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(quad)) return true;
    if (/^169\.254\./.test(quad)) return true;
  }

  // IPv4-mapped IPv6 in hex form (WHATWG normalization): ::ffff:XXXX:XXXX.
  const ipv4MappedHexMatch = h.match(/^::ffff:([0-9a-f]+):([0-9a-f]+)$/i);
  if (ipv4MappedHexMatch) {
    const hex1 = parseInt(ipv4MappedHexMatch[1], 16);
    const hex2 = parseInt(ipv4MappedHexMatch[2], 16);
    const a = (hex1 >> 8) & 0xff;
    const b = hex1 & 0xff;
    const c = (hex2 >> 8) & 0xff;
    const d = hex2 & 0xff;
    const quad = `${a}.${b}.${c}.${d}`;
    if (/^127\./.test(quad)) return true;
    if (/^10\./.test(quad)) return true;
    if (/^192\.168\./.test(quad)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(quad)) return true;
    if (/^169\.254\./.test(quad)) return true;
  }

  // IPv4 loopback, private, and link-local ranges.
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;

  return false;
}

/** Read a Response body with a byte cap enforced while streaming. Returns null if exceeded or aborted. */
async function readCappedText(
  res: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<string | null> {
  const body = res.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  // Create a promise that rejects if the abort signal fires, allowing us to race it against reader.read().
  const abortPromise = new Promise<never>((_, reject) =>
    signal.addEventListener("abort", () => reject(new Error("abort")))
  );

  try {
    for (;;) {
      // Race the read against abort — if abort fires, Promise.race will reject with the abortPromise.
      const { done, value } = await Promise.race([
        reader.read(),
        abortPromise,
      ]);
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    // Abort signal fired or other error; cancel reader and return null.
    await reader.cancel();
    return null;
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(buf);
}

/**
 * Fetch and validate a Client ID Metadata Document. Returns null (never throws) on any
 * validation failure — an invalid/unreachable document means "not a CIMD client," not a
 * server error, so callers fall back to other registration mechanisms.
 */
export async function fetchClientIdMetadata(
  clientIdUrl: string,
): Promise<ClientIdMetadata | null> {
  let url: URL;
  try {
    url = new URL(clientIdUrl);
  } catch {
    return null;
  }
  // Spec: client_id MUST use "https" and contain a path component.
  if (url.protocol !== "https:" || url.pathname === "" || url.pathname === "/") return null;
  if (isBlockedHost(url.hostname)) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    let res: Response;
    try {
      res = await fetch(url, { redirect: "error", signal: controller.signal });
    } catch {
      return null;
    }
    if (!res.ok) return null;

    const text = await readCappedText(res, MAX_DOCUMENT_BYTES, controller.signal);
    if (text === null) return null;

    let doc: unknown;
    try {
      doc = JSON.parse(text);
    } catch {
      return null;
    }
    if (!doc || typeof doc !== "object") return null;
    const d = doc as Record<string, unknown>;

    // MUST match the fetch URL exactly (prevents a document claiming someone else's client_id).
    if (d.client_id !== clientIdUrl) return null;
    if (!Array.isArray(d.redirect_uris) || d.redirect_uris.length === 0) return null;
    if (!d.redirect_uris.every((u) => typeof u === "string")) return null;

    return {
      clientId: clientIdUrl,
      clientName: typeof d.client_name === "string" ? d.client_name : undefined,
      redirectUris: d.redirect_uris as string[],
    };
  } finally {
    clearTimeout(timeout);
  }
}
