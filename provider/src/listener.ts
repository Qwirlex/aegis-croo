import "dotenv/config";
import {
  AgentClient,
  EventType,
  DeliverableType,
  APIError,
} from "@croo-network/sdk";
import type { Event } from "@croo-network/sdk";
import { runAudit } from "./engine";
import { buildDeliverable } from "./report-link";

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------
const CROO_API_URL = process.env.CROO_API_URL ?? "https://api.croo.network";
const CROO_WS_URL =
  process.env.CROO_WS_URL ?? "wss://api.croo.network/ws";
const CROO_SDK_KEY = process.env.CROO_SDK_KEY ?? "";
const ENGINE_URL = process.env.ENGINE_URL ?? "http://127.0.0.1:8731";

if (!CROO_SDK_KEY) {
  console.error("[aegis] CROO_SDK_KEY is not set — exiting");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
const client = new AgentClient(
  { baseURL: CROO_API_URL, wsURL: CROO_WS_URL },
  CROO_SDK_KEY
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolves the buyer's contract address or Solidity source from the
 * negotiation's `requirements` field (confirmed present on `Negotiation`
 * type: `requirements: string`).
 *
 * Confirmed live (order 3cdf08e0): `negotiation.requirements` arrives
 * JSON-wrapped as `{"text": "<address-or-source>"}`, NOT as raw text. It is
 * unwrapped via `unwrapRequirements()` before classification.
 *   - We read `negotiation.requirements` (from `acceptNegotiation()` /
 *     `getNegotiation()`), falling back to `e.raw?.requirements ??
 *     e.raw?.deliverable_requirements ?? ""` if empty.
 *   - After unwrapping: "0x" + 40 hex chars → address; anything else → source.
 */
/**
 * CROO delivers `requirements` JSON-wrapped — confirmed at the first live order
 * as `{"text": "<address-or-source>"}`. Unwrap to the inner string before
 * classifying. Falls through to the raw text if it is not JSON.
 */
function unwrapRequirements(raw: string): string {
  const t = raw.trim();
  if (!t.startsWith("{") && !t.startsWith("[") && !t.startsWith('"')) return t;
  try {
    const parsed = JSON.parse(t);
    if (typeof parsed === "string") return parsed.trim();
    if (parsed && typeof parsed === "object") {
      const inner =
        parsed.text ??
        parsed.source ??
        parsed.address ??
        parsed.content ??
        parsed.input;
      if (typeof inner === "string") return inner.trim();
    }
  } catch {
    // not JSON — use the raw text as-is
  }
  return t;
}

function resolveAuditInput(
  requirements: string,
  rawFallback: Record<string, unknown>
) {
  const raw =
    requirements ||
    (rawFallback?.["requirements"] as string | undefined) ||
    (rawFallback?.["deliverable_requirements"] as string | undefined) ||
    "";

  const text = unwrapRequirements(raw);

  if (/^0x[0-9a-fA-F]{40}$/.test(text)) {
    return { address: text };
  }
  return { source: text };
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------

async function handleNegotiationCreated(e: Event): Promise<void> {
  const negId = e.negotiation_id!;
  console.log(`[aegis] NegotiationCreated  negotiation_id=${negId}`);
  try {
    const { negotiation, order } = await client.acceptNegotiation(negId);
    console.log(
      `[aegis] Accepted negotiation  negotiation_id=${negotiation.negotiationId}  order_id=${order.orderId}`
    );
  } catch (err) {
    const msg = err instanceof APIError ? `${err.code}: ${err.reason}` : String(err);
    console.error(`[aegis] Failed to accept negotiation ${negId}: ${msg}`);
  }
}

async function handleOrderPaid(e: Event): Promise<void> {
  const orderId = e.order_id!;
  console.log(`[aegis] OrderPaid  order_id=${orderId}`);

  // Fetch order + negotiation to get the buyer's requirements text.
  let requirementsText = "";
  try {
    const order = await client.getOrder(orderId);
    const negotiation = await client.getNegotiation(order.negotiationId);
    requirementsText = negotiation.requirements ?? "";
  } catch (fetchErr) {
    // Non-fatal: fall back to raw event payload.
    console.warn(
      `[aegis] Could not fetch order/negotiation details, falling back to raw: ${fetchErr}`
    );
  }

  const auditInput = resolveAuditInput(
    requirementsText,
    e.raw as Record<string, unknown>
  );
  console.log(
    `[aegis] Running audit  order_id=${orderId}  input=${JSON.stringify(auditInput)}`
  );

  let deliverableText: string;
  try {
    const report = await runAudit(ENGINE_URL, auditInput);
    deliverableText = await buildDeliverable(report);
    console.log(
      `[aegis] Audit complete  order_id=${orderId}  risk_score=${report.risk_score ?? "?"}`
    );
  } catch (auditErr) {
    const reason = String(auditErr);
    console.error(
      `[aegis] Audit failed  order_id=${orderId}  reason=${reason}`
    );
    deliverableText = JSON.stringify({
      status: "cannot_analyze",
      reason,
    });
  }

  try {
    const result = await client.deliverOrder(orderId, {
      deliverableType: DeliverableType.Text,
      deliverableText,
    });
    console.log(
      `[aegis] Delivered order  order_id=${orderId}  txHash=${result.txHash}`
    );
  } catch (deliverErr) {
    const msg =
      deliverErr instanceof APIError
        ? `${deliverErr.code}: ${deliverErr.reason}`
        : String(deliverErr);
    console.error(`[aegis] Failed to deliver order ${orderId}: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log(`[aegis] Connecting to CROO WebSocket  url=${CROO_WS_URL}`);
  const stream = await client.connectWebSocket();
  console.log("[aegis] WebSocket connected — listening for events");

  // EventStream.on() is synchronous (void handler). We wrap async handlers
  // in a fire-and-forget IIFE so TypeScript is satisfied and errors are caught.
  stream.on(EventType.NegotiationCreated, (e: Event) => {
    void handleNegotiationCreated(e).catch((err) =>
      console.error("[aegis] Unhandled error in NegotiationCreated handler:", err)
    );
  });

  stream.on(EventType.OrderPaid, (e: Event) => {
    void handleOrderPaid(e).catch((err) =>
      console.error("[aegis] Unhandled error in OrderPaid handler:", err)
    );
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log("[aegis] Shutting down — closing WebSocket stream");
    stream.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("[aegis] Fatal error:", err);
  process.exit(1);
});
