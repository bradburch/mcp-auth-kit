import { describe, it, expect } from "vitest";
import { createAppointmentsServer } from "../../examples/appointments/server.js";
import { getToken, callTool } from "../helpers.js";

describe("appointments example", () => {
  it("lists slots and books one through preview→confirm", async () => {
    const app = createAppointmentsServer();
    const token = await getToken(app);
    const slots = await callTool(app, token, "list_slots", {});
    expect(JSON.stringify(slots)).toContain("09:00");
    const preview = await callTool(app, token, "book_slot", { slot: "09:00" });
    const confirmationToken = /"confirmationToken":"([^"]+)"/.exec(
      JSON.stringify(preview),
    )![1];
    const result = await callTool(app, token, "confirm_request", {
      confirmationToken,
      idempotencyKey: "k1",
    });
    expect(JSON.stringify(result)).toContain("booked");
  });
});
