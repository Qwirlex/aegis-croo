import "dotenv/config";
import {
  AgentClient,
  EventType,
  DeliverableType,
  APIError,
} from "@croo-network/sdk";
import type { Event } from "@croo-network/sdk";
import { runAudit } from "./engine";

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
 * TODO(live): confirm requirements field at first real order.
 *   - SDK types show `Negotiation.requirements: string` — this is the natural
 *     place for the buyer to pass the contract address or source snippet.
 *   - The `AcceptNegotiationResult` returned by `acceptNegotiation()` contains
 *     `{ negotiation, order }`. We use `negotiation.requirements`.
 *   - If the field is unexpectedly empty, we fall back to
 *     `e.raw?.requirements ?? e.raw?.deliverable_requirements ?? ""`.
 *   - Text starting with "0x" and exactly 42 chars → treat as address.
 *     Anything else → treat as Solidity source.
 */
function resolveAuditInput(
  requirements: string,
  rawFallback: Record<string, unknown>
) {
  const text =
    requirements ||
    (rawFallback?.["requirements"] as string | undefined) ||
    (rawFallback?.["deliverable_requirements"] as string | undefined) ||
    "";

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
    deliverableText = JSON.stringify(report);
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
