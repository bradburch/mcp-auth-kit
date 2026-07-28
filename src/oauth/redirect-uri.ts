// Shared redirect_uri validation rules, applied identically to both registration paths:
// Dynamic Client Registration (routes.ts, POST /register) and Client ID Metadata Document
// resolution (cimd.ts). Keeping this logic in one place means a CIMD-sourced redirect_uri
// can't bypass rules that DCR enforces (fragment-bearing URIs, non-https/non-localhost
// schemes) just because it arrived via a different registration mechanism.

/** True if the URI has a fragment component — redirect_uris must not (RFC 6749 §3.1.2). */
export function hasFragment(uri: string): boolean {
  try {
    return new URL(uri).hash !== "";
  } catch {
    return false;
  }
}

/**
 * True if `uri` uses an allowed redirect scheme: https always, or http restricted to
 * localhost/127.0.0.1 for local development.
 */
export function isAllowedRedirectUriScheme(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  return url.protocol === "https:" || (url.protocol === "http:" && isLocal);
}

/** True if `uri` is well-formed, fragment-free, and uses an allowed scheme. */
export function isValidRedirectUri(uri: string): boolean {
  return !hasFragment(uri) && isAllowedRedirectUriScheme(uri);
}
