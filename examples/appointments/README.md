# appointments example

A minimal MCP server for booking appointment slots. Demonstrates `list_slots`
(read tool) and `book_slot` (mutating tool with preview → confirm) using
in-memory storage and an email + verification-code identity.

> **Note:** This example uses `createMemoryStorage()` for demo simplicity only — it is not
> persistent and is not shared across isolates. Production deployments must use a shared store
> (e.g. `createCloudflareKvStorage(kv)`).

> **Mount at root:** This server must be bound to your domain root (not a sub-path) — RFC 8414
> requires `/.well-known/oauth-authorization-server` to resolve at the domain root. See the
> [deploy guide](../../docs/deploy.md) for details.

## Run on Node

`@hono/node-server` and a TypeScript runner (`tsx` or `ts-node`) are dev extras — not bundled
with `mcp-server-kit`. Install them first:

```bash
npm install --save-dev @hono/node-server tsx
```

Then run the included entry point:

```bash
npx tsx examples/appointments/run.ts
```

This starts the server on port 3000 (override with `PORT=<n>`).

## Discovery endpoint

```bash
curl http://localhost:3000/.well-known/oauth-authorization-server
```

## Identity

Submit `email` + `code` on the `/authorize` form. Use code `123456` to authenticate.
