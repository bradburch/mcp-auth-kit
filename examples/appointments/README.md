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

> **Import path:** `server.ts` imports from `../../src/index.js` (repo-relative) for in-repo
> development — this example is dogfooded by the kit's own test suite. A real project imports from the
> published package instead — `import { createMcpServer, ... } from "mcp-oauth-kit"` — see
> [`docs/how-to-use.md`](../../docs/how-to-use.md) for the copy-pasteable version.

## Run on Node

`@hono/node-server` and `tsx` aren't installed by the kit's repo. To try the example in-repo,
install them without saving:

```bash
npm install --no-save @hono/node-server tsx
```

In your own project `@hono/node-server` is a **runtime** dependency
(`npm install @hono/node-server`); `tsx` is optional (Node 22.18+ runs `.ts` directly, or
write plain `.js`).

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
