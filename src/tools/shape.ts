import type { z } from "zod";

/** Extract the SDK-expected ZodRawShape from a tool's Zod object inputSchema. */
export function toShape(schema: z.ZodTypeAny): z.ZodRawShape {
  return (schema as z.ZodObject<z.ZodRawShape>).shape;
}
