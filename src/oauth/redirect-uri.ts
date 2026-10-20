// Shared redirect_uri validation rules, applied identically to both registration paths:
// Dynamic Client Registration (routes.ts, POST /register) and Client ID Metadata Document
// resolution (cimd.ts). Keeping this logic in one place means a CIMD-sourced redirect_uri
// can't bypass rules that DCR enforces (fragment-bearing URIs, non-https/non-localhost
// schemes) just because it arrived via a different registration mechanism.

/** The hosts where plain http is allowed, for local development (redirect URIs and `baseUrl`). */
export function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1";
}

/** Why `uri` can't be a redirect_uri, or null when it's fine. */
export function redirectUriProblem(uri: string): "malformed" | "fragment" | "scheme" | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return "malformed";
  }
  // RFC 6749 §3.1.2: redirect_uris must not have a fragment.
  if (url.hash !== "") return "fragment";
  const ok =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname));
  return ok ? null : "scheme";
}

/** True if `uri` is well-formed, fragment-free, and uses an allowed scheme. */
export function isValidRedirectUri(uri: string): boolean {
  return redirectUriProblem(uri) === null;
}
