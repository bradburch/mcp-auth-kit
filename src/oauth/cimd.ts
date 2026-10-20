// OAuth Client ID Metadata Documents (CIMD) — draft-ietf-oauth-client-id-metadata-document-00.
// MCP 2026-07-28 deprecates Dynamic Client Registration in favor of this: the client_id IS
// an HTTPS URL pointing at a JSON document describing the client (see the MCP spec's
// "Client ID Metadata Documents" section, deprecating RFC 7591 DCR per changelog item 4).
import { isValidRedirectUri } from "./redirect-uri.js";
import { readStreamCapped } from "../http/body-limit.js";

/** Response body cap for a metadata document fetch — these are small JSON files. */
const MAX_DOCUMENT_BYTES = 16 * 1024;

/** Abort a metadata fetch that hangs (e.g. a slow-loris endpoint). */
const FETCH_TIMEOUT_MS = 3000;

/** Bounds for a CIMD document's own Cache-Control max-age, so a document can't force an
 *  unbounded cache lifetime (stale redirect_uris survive too long) or an effectively-zero
 *  one (reopening the repeated-outbound-fetch/SSRF-adjacent concern the cache exists to bound). */
const MIN_CACHE_SECONDS = 60;
const MAX_CACHE_SECONDS = 24 * 60 * 60;

/** A validated Client ID Metadata Document, narrowed to the fields MCP needs. */
export interface ClientIdMetadata {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  /** Clamped `max-age` from the response's Cache-Control header, if present. */
  maxAgeSeconds?: number;
}

/**
 * IPv4 loopback, RFC 1918 private, CGNAT (RFC 6598), and link-local ranges. Shared by the
 * raw-IPv4 check below and the IPv4-mapped/compatible IPv6 check, so the range list lives
 * in exactly one place.
 */
const PRIVATE_IPV4 = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./,
  /^0\./, // 0.0.0.0/8
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT
];

function isPrivateIPv4(quad: string): boolean {
  return PRIVATE_IPV4.some((r) => r.test(quad));
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

  // IPv6 loopback and the unspecified address (connects to loopback on Linux/macOS).
  if (h === "::1" || h === "::" || h === "localhost") return true;

  // IPv6 link-local (fe80::/10).
  if (/^fe80:/i.test(h)) return true;

  // IPv6 unique-local addresses (fc00::/7) — the IPv6 equivalent of RFC 1918, used by real
  // internal networks.
  if (/^f[cd][0-9a-f]{2}:/i.test(h)) return true;

  // IPv4-mapped/compatible IPv6, hex-normalized form only (WHATWG always serializes this way —
  // e.g. ::ffff:127.0.0.1 becomes ::ffff:7f00:1, and ::127.0.0.1 becomes ::7f00:1; the dotted
  // form never appears in a URL's hostname, so there is no separate branch for it).
  const v4MappedMatch = h.match(/^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (v4MappedMatch) {
    const hi = Number.parseInt(v4MappedMatch[1], 16);
    const lo = Number.parseInt(v4MappedMatch[2], 16);
    const a = (hi >> 8) & 0xff;
    const b = hi & 0xff;
    const c = (lo >> 8) & 0xff;
    const d = lo & 0xff;
    if (isPrivateIPv4(`${a}.${b}.${c}.${d}`)) return true;
  }

  // IPv4 loopback, private, CGNAT, and link-local ranges.
  if (isPrivateIPv4(h)) return true;

  return false;
}

/** Parse and clamp `max-age` from a Cache-Control header, if present and well-formed. */
function parseMaxAge(cacheControl: string | null): number | undefined {
  if (!cacheControl) return undefined;
  const match = /max-age=(\d+)/i.exec(cacheControl);
  if (!match) return undefined;
  const raw = Number.parseInt(match[1], 10);
  return Math.min(Math.max(raw, MIN_CACHE_SECONDS), MAX_CACHE_SECONDS);
}

/**
 * Fetch and validate a Client ID Metadata Document. Returns null (never throws) on any
 * validation failure — an invalid/unreachable document means "not a CIMD client," not a
 * server error, so callers fall back to other registration mechanisms.
 */
export async function fetchClientIdMetadata(clientIdUrl: string): Promise<ClientIdMetadata | null> {
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

    const maxAgeSeconds = parseMaxAge(res.headers.get("cache-control"));

    // A body over the cap, an abort (timeout), or a stream error all mean "not a CIMD client".
    const text = await readStreamCapped(res.body, MAX_DOCUMENT_BYTES, controller.signal).catch(
      () => null,
    );
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
    const redirectUris = d.redirect_uris as string[];
    // Same rules DCR enforces on POST /register (no fragments, https-only except
    // localhost/127.0.0.1 http): a CIMD document must not be able to smuggle in a redirect
    // URI that DCR would have rejected. Any one bad entry invalidates the whole document,
    // consistent with this function's all-or-nothing "invalid → null" contract.
    if (!redirectUris.every(isValidRedirectUri)) return null;

    return {
      clientId: clientIdUrl,
      clientName: typeof d.client_name === "string" ? d.client_name : undefined,
      redirectUris,
      maxAgeSeconds,
    };
  } finally {
    clearTimeout(timeout);
  }
}
