// Example entry point — run with: npx tsx examples/appointments/run.ts
//
// Requires dev extras (not bundled with mcp-server-kit):
//   npm install --save-dev @hono/node-server tsx
//
// @ts-nocheck — @hono/node-server is a dev extra, not listed in the package's
// own dependencies; this file is intentionally excluded from tsconfig "include".
import { serve } from "@hono/node-server";
import { createAppointmentsServer } from "./server.js";

const port = Number(process.env.PORT ?? 3000);
serve({ fetch: createAppointmentsServer().fetch, port }, () => {
  console.log(`Appointments MCP server listening on http://localhost:${port}`);
  console.log(
    `Discovery: http://localhost:${port}/.well-known/oauth-authorization-server`,
  );
});
