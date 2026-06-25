/**
 * Extract the client IP from a request.
 *
 * Priority:
 *  1. CF-Connecting-IP  — set by Cloudflare; authoritative on CF Workers.
 *  2. X-Forwarded-For (first hop) — fallback behind other trusted proxies.
 *  3. "unknown"         — no header available.
 *
 * NOTE: Adopters NOT on Cloudflare must adapt the trusted source. X-Forwarded-For is
 * trivially spoofable by clients when not stripped/overwritten by a trusted proxy.
 */
export function extractClientIp(req: Request): string {
  const cf = req.headers.get("CF-Connecting-IP");
  if (cf) return cf.trim();

  const xff = req.headers.get("X-Forwarded-For");
  if (xff) {
    const first = xff.split(",")[0];
    if (first) return first.trim();
  }

  return "unknown";
}
