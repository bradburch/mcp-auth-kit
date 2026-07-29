# Deploying mcp-oauth-kit

`createMcpServer` returns a [Hono](https://hono.dev/) app. Mount it at the **origin root** of your deployment so that `/.well-known/*`, `/authorize`, `/token`, and `POST /mcp` all resolve at the top level — RFC 8414 requires the well-known endpoints at the domain root, and spec-compliant MCP clients POST JSON-RPC to `${baseUrl}/mcp`. Hono has first-party adapters for every major runtime — wrap the app in the adapter for your target and you're done.

## Request body limit

All request bodies — OAuth endpoints and the MCP transport — are capped at **1 MB**. Requests that exceed this limit receive HTTP 413. If your tools accept large inputs (e.g. document contents), pre-process or chunk them before sending.

## Cloudflare Workers

Use `createCloudflareKvStorage` to wrap your KV namespace binding.

```ts
// src/index.ts
import { createMcpServer, createCloudflareKvStorage } from "mcp-oauth-kit";
import { tools } from "./tools.js";

interface Env {
  KV: KVNamespace;
}

export default {
  // Bindings only arrive via this `env` parameter in an ES-module Worker — build the app
  // per-request so `createCloudflareKvStorage` gets the real KV namespace, not a
  // module-scope value that doesn't exist yet at module-evaluation time.
  fetch: (req: Request, env: Env) => {
    const app = createMcpServer({
      baseUrl: "https://mcp.example.com",
      storage: createCloudflareKvStorage(env.KV),
      scopes: [{ name: "account:read", default: true }],
      identity: {
        fields: [{ name: "email", label: "Email", type: "email", required: true }],
        verify: async (fields) => ((await isValidUser(fields.email)) ? fields.email : null),
      },
      tools,
    });
    return app.fetch(req, env);
  },
} satisfies ExportedHandler<Env>;
```

`wrangler.toml` — bind your KV namespace:

```toml
name = "my-mcp-server"
main = "src/index.ts"
compatibility_date = "2024-09-23"

[[kv_namespaces]]
binding = "KV"
id = "<your-kv-namespace-id>"
```

Storage: `createCloudflareKvStorage` — built in, no extra install.

## Node.js (`@hono/node-server`)

```bash
npm install @hono/node-server
```

Use any `KvLike` implementation. **The in-memory adapter is for local development only — even a single production process restarts, loses state, and (if ever scaled to more than one instance) won't share state across them.** Use the Redis or Postgres adapter from [docs/storage-adapters.md](storage-adapters.md) for anything beyond local dev.

**`baseUrl` must be the externally-visible `https://` URL**, even if this process itself listens on plain HTTP behind a TLS-terminating reverse proxy — `createMcpServer` throws at construction time if `baseUrl` isn't `https://` (except for `localhost`/`127.0.0.1`). Setting `BASE_URL=http://10.0.0.5:3000` for an internal address behind a proxy will hit that throw; set it to the public `https://` hostname instead.

```ts
// src/index.ts
import { serve } from "@hono/node-server";
import { createMcpServer, createMemoryStorage } from "mcp-oauth-kit";
import { tools } from "./tools.js";

const app = createMcpServer({
  baseUrl: process.env.BASE_URL ?? "http://localhost:3000",
  storage: createMemoryStorage(), // swap for Redis/Postgres adapter in production
  scopes: [{ name: "account:read", default: true }],
  identity: {
    fields: [{ name: "email", label: "Email", type: "email", required: true }],
    verify: async (fields) => ((await isValidUser(fields.email)) ? fields.email : null),
  },
  tools,
});

serve({ fetch: app.fetch, port: 3000 }, (info) => {
  console.log(`Listening on http://localhost:${info.port}`);
});
```

## AWS Lambda (`hono/aws-lambda`)

```bash
npm install hono
```

Hono's `handle` adapter converts a Lambda event to a standard `Request` and back.

```ts
// src/handler.ts
import { handle } from "hono/aws-lambda";
import { createMcpServer, createMemoryStorage } from "mcp-oauth-kit";
import { tools } from "./tools.js";

// In production, replace createMemoryStorage() with a DynamoDB or Redis adapter
// (see docs/storage-adapters.md). Lambda is stateless — in-memory storage is
// lost between cold starts.
const app = createMcpServer({
  baseUrl: process.env.BASE_URL ?? "https://mcp.example.com",
  storage: createMemoryStorage(),
  scopes: [{ name: "account:read", default: true }],
  identity: {
    fields: [{ name: "email", label: "Email", type: "email", required: true }],
    verify: async (fields) => ((await isValidUser(fields.email)) ? fields.email : null),
  },
  tools,
});

export const handler = handle(app);
```

SAM / CDK: point the function's handler at `src/handler.handler` and set the `BASE_URL` environment variable to your API Gateway or function URL.

## Vercel

Vercel supports Hono via its built-in Node.js runtime. Export `GET` and `POST` named handlers from an API route:

```ts
// app/api/[[...route]]/route.ts  (Next.js App Router)
import { handle } from "hono/vercel";
import { createMcpServer, createMemoryStorage } from "mcp-oauth-kit";
import { tools } from "@/lib/tools.js";

export const runtime = "edge"; // or "nodejs"

// In production, replace createMemoryStorage() with a persistent adapter
// (see docs/storage-adapters.md). Edge functions are stateless.
const app = createMcpServer({
  baseUrl: process.env.NEXT_PUBLIC_BASE_URL ?? "https://mcp.example.com",
  storage: createMemoryStorage(),
  scopes: [{ name: "account:read", default: true }],
  identity: {
    fields: [{ name: "email", label: "Email", type: "email", required: true }],
    verify: async (fields) => ((await isValidUser(fields.email)) ? fields.email : null),
  },
  tools,
});

export const GET = handle(app);
export const POST = handle(app);
```

Vercel Functions live under `/api` by default, which conflicts with the origin-root requirement stated above. For a Next.js project specifically, Vercel's own docs favor framework-level rewrites over `vercel.json` (framework config takes precedence when both are present), so prefer `next.config.js`'s `rewrites()` over a `vercel.json` block for a Next.js App Router app:

```js
// next.config.js
/** @type {import('next').NextConfig} */
module.exports = {
  async rewrites() {
    return [
      { source: "/.well-known/:path*", destination: "/api/:path*" },
      { source: "/authorize", destination: "/api/authorize" },
      { source: "/token", destination: "/api/token" },
      { source: "/register", destination: "/api/register" },
      { source: "/revoke", destination: "/api/revoke" },
      { source: "/mcp", destination: "/api/mcp" },
    ];
  },
};
```

> **This rewrite approach is unverified end-to-end** — in particular, whether the Hono
> catch-all handler above sees the pre-rewrite or post-rewrite path (which determines
> whether discovery requests actually reach it, or 404) hasn't been confirmed against a
> live deployment. Check the current Vercel and Next.js docs, and test the well-known
> paths against a real deployment, before relying on this in production.

For the `"nodejs"` runtime, substitute `"hono/vercel"` with `"@hono/node-server/vercel"` if the Vercel adapter requires it — check the current Hono docs for the correct import.

---

## Storage adapter summary

| Runtime                   | Recommended storage                                                        |
| ------------------------- | -------------------------------------------------------------------------- |
| Cloudflare Workers        | `createCloudflareKvStorage(env.KV)`                                        |
| Node (persistent)         | Redis or Postgres adapter (see [storage-adapters.md](storage-adapters.md)) |
| AWS Lambda (persistent)   | DynamoDB adapter (see [storage-adapters.md](storage-adapters.md))          |
| Vercel Edge (persistent)  | Redis adapter via `@upstash/redis` or similar                              |
| Any runtime (tests / dev) | `createMemoryStorage()`                                                    |
