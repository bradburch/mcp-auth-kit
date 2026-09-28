import { z } from "zod";
import { createMcpServer, createMemoryStorage, defineTool } from "../../src/index.js";

export function createAppointmentsServer(baseUrl = "https://example.test") {
  return createMcpServer({
    baseUrl,
    storage: createMemoryStorage(),
    scopes: [
      { name: "account:read", default: true },
      { name: "write", default: true },
    ],
    identity: {
      fields: [
        { name: "email", label: "Email", type: "email", required: true },
        {
          name: "code",
          label: "Verification Code",
          type: "text",
          required: true,
        },
      ],
      verify: async (fields) => {
        // Accept either the correct code or no code (empty string) for test helpers
        // that only submit email.
        if (fields.code === "123456" || fields.code === "") {
          return "user-appt";
        }
        return null;
      },
    },
    tools: [
      defineTool({
        name: "list_slots",
        description: "List available appointment slots for today.",
        inputSchema: z.object({}),
        handler: async () => "Available slots: 09:00, 10:00, 11:00, 14:00, 15:00",
      }),
      defineTool({
        name: "book_slot",
        description: "Book an appointment slot.",
        scope: "write",
        inputSchema: z.object({ slot: z.string() }),
        mutating: {
          preview: async ({ slot }) => ({ summary: `book ${slot}`, data: { slot } }),
          execute: async ({ slot }) => `Successfully booked appointment at ${slot}.`,
        },
      }),
    ],
  });
}
