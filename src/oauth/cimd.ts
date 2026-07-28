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
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "0.0.0.0" || h === "::1") return true;
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  return false;
}

/** Read a Response body with a byte cap enforced while streaming. Returns null if exceeded. */
async function readCappedText(res: Response, maxBytes: number): Promise<string | null> {
  const body = res.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
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
  let res: Response;
  try {
    res = await fetch(url, { redirect: "error", signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
  if (!res.ok) return null;

  const text = await readCappedText(res, MAX_DOCUMENT_BYTES);
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
}
