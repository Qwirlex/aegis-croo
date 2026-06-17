import { saveReport } from "@/lib/store";

// Route handlers are not cached; this one writes to disk on every call.
export const dynamic = "force-dynamic";

/** Store an Aegis report and return its short id. The provider POSTs here, then
 *  hands the buyer an aegiscan.xyz/r/<id> link instead of a giant ?data= URL. */
export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid json" }, { status: 400 });
  }
  if (
    !body ||
    typeof body !== "object" ||
    !("agent" in body) ||
    !("status" in body) ||
    !("target" in body)
  ) {
    return Response.json({ error: "not an aegis report" }, { status: 422 });
  }
  const id = await saveReport(body);
  return Response.json({ id });
}
