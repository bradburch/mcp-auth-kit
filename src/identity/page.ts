// Built-in OAuth authorize page renderer.
//
// Generalised from brad-paws `oauth-pages.ts`: instead of hard-coded name/phone fields and
// fixed branding, the form is built from `identity.fields` (label + typed input) plus optional
// `identity.branding` (app name heading, logo, accent colour). The OAuth parameters are carried
// through as hidden inputs and the form POSTs back to the same `/authorize` path.
//
// Every interpolated value is HTML-escaped to prevent injection via attacker-controlled
// OAuth params (client_id, redirect_uri, state, …) or field/branding config.
import type { IdentityConfig } from "../config.js";

/** OAuth parameters threaded through the form as hidden inputs. */
export interface AuthorizePageParams {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  state: string;
  resource: string;
  scope?: string;
  /** Optional error banner shown above the form. */
  error?: string;
  /** Previously submitted field values, re-populated on an error re-render. */
  prefill?: Record<string, string>;
}

const DEFAULT_ACCENT = "#3b82f6";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Build a `<input type="hidden">` for an OAuth param (value escaped). */
function hidden(name: string, value: string): string {
  return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(
    value,
  )}" />`;
}

/**
 * Render the built-in authorize/login form for the given identity config and OAuth params.
 * The returned HTML is a complete document; POSTs back to `/authorize` (same path).
 */
export function renderAuthorizePage(
  identity: IdentityConfig,
  params: AuthorizePageParams,
): string {
  const branding = identity.branding;
  const appName = escapeHtml(branding?.appName ?? "Sign in");
  const accent = escapeHtml(branding?.accentColor ?? DEFAULT_ACCENT);
  // Only emit an <img> for https:// or http:// schemes; reject javascript:, data:, etc.
  const rawLogoUrl = branding?.logoUrl ?? "";
  const logoUrlSafe =
    rawLogoUrl.startsWith("https://") || rawLogoUrl.startsWith("http://")
      ? escapeHtml(rawLogoUrl)
      : undefined;

  // Hidden inputs carrying the OAuth parameters through the form submission.
  const oauthParams: Record<string, string> = {
    response_type: params.response_type,
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method,
    state: params.state,
    resource: params.resource,
    scope: params.scope ?? "",
  };
  const hiddenInputs = Object.entries(oauthParams)
    .map(([k, v]) => hidden(k, v))
    .join("\n      ");

  const fieldInputs = identity.fields
    .map((f) => {
      const id = escapeHtml(f.name);
      const label = escapeHtml(f.label);
      const type = escapeHtml(f.type ?? "text");
      const value = escapeHtml(params.prefill?.[f.name] ?? "");
      const required = f.required !== false ? "required" : "";
      return `      <label for="${id}">${label}</label>
      <input id="${id}" type="${type}" name="${id}" value="${value}" ${required} />`;
    })
    .join("\n");

  const errorHtml = params.error
    ? `<div class="error">${escapeHtml(params.error)}</div>`
    : "";

  const logoHtml = logoUrlSafe
    ? `<img class="logo" src="${logoUrlSafe}" alt="${appName}" />`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${appName}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8f7f4; color: #1a1a1a; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 1rem; }
    .card { background: white; border-radius: 12px; padding: 2rem; max-width: 400px; width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .logo { max-height: 48px; margin-bottom: 1rem; }
    h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
    label { display: block; font-weight: 500; margin-bottom: 0.25rem; font-size: 0.9rem; }
    input:not([type=hidden]) { width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; margin-bottom: 1rem; }
    input:focus { outline: none; border-color: ${accent}; box-shadow: 0 0 0 2px ${accent}33; }
    button { width: 100%; padding: 0.7rem; background: ${accent}; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 500; cursor: pointer; }
    button:hover { filter: brightness(0.95); }
    .error { background: #fef2f2; color: #991b1b; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    ${logoHtml}
    <h1>${appName}</h1>
    ${errorHtml}
    <form method="POST" action="/authorize">
      ${hiddenInputs}
${fieldInputs}
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;
}
