const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

export async function sha256Hex(input: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)),
  );
  let hex = "";
  for (const b of digest) hex += HEX[b];
  return hex;
}

/** Unpadded base64url (RFC 4648 §5) — the encoding of tokens and PKCE challenges. */
export function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** The PKCE S256 code challenge for `verifier`: base64url(SHA-256(verifier)) (RFC 7636 §4.2). */
export async function pkceS256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/**
 * Generate a high-entropy, URL-safe opaque token: 32 random bytes (256 bits)
 * encoded as base64url. Used for access/refresh tokens, authorization codes, and confirmation
 * tokens — all stored only as their SHA-256 hash, so the wire format is free.
 */
export function randomToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}
