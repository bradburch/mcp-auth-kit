# appointments example

A minimal MCP server for booking appointment slots. Demonstrates `list_slots`
(read tool) and `book_slot` (mutating tool with preview → confirm) using
in-memory storage and an email + verification-code identity.

> **Note:** This example uses `createMemoryStorage()` for demo simplicity only — it is not
> persistent and is not shared across isolates. Production deployments must use a shared store
> (e.g. `createCloudflareKvStorage(kv)`).

## Run on Node

```bash
npm install @hono/node-server hono
node -e "
import { serve } from '@hono/node-server';
import { createAppointmentsServer } from './server.js';
serve({ fetch: createAppointmentsServer().fetch, port: 3000 });
console.log('Listening on http://localhost:3000');
"
```

## Discovery endpoint

```bash
curl http://localhost:3000/.well-known/oauth-authorization-server
```

## Identity

Submit `email` + `code` on the `/authorize` form. Use code `123456` to authenticate.
