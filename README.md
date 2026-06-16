# Aegis — On-chain Smart-Contract Auditor Agent (CROO)

Aegis is a **paid, callable smart-contract security auditor agent** on the CROO Agent Protocol (CAP).
Send it a contract — a Base address with verified source, or pasted Solidity — pay **0.5 USDC**, and Aegis
returns a severity-ranked, source-cited audit report from a **hybrid Slither + LLM** engine. The report's
hash is committed on-chain by CAP, giving a verifiable proof of audit. Built for **A2A composability**:
other agents can hire Aegis as a pre-deploy dependency.

- **Tracks:** Developer Tooling · Open – Any A2A
- **Network:** Base Mainnet (chain id 8453) · payment in USDC
- **Principle:** AI suggests, you decide — read-only analysis, no auto-transactions.

## Why it's credible
- **Hybrid engine, not a GPT wrapper.** [Slither](https://github.com/crytic/slither) runs real static
  analysis; the LLM ranks, dedupes, and explains — and may add logic bugs Slither misses.
- **Grounded findings.** Every LLM finding must cite a Slither detector or a concrete `file:line`.
  Ungrounded (hallucinated) findings are dropped before the report is built.
- **Verifiable.** CAP writes the keccak256 hash of the deliverable on-chain.

## Structure
```
aegis/
  engine/    Python audit engine (FastAPI): Slither + grounded LLM -> report JSON
  provider/  Node.js CAP provider listener (@croo-network/sdk): accepts orders, calls engine, delivers
  web/       Next.js report UI: renders a report JSON + on-chain proof badge
```

### Data flow
```
buyer/agent -> CAP NegotiateOrder -> Aegis acceptNegotiation -> buyer PayOrder (USDC -> CAPVault escrow)
-> Aegis fetches source -> Slither -> LLM -> report -> deliverOrder(report) -> CAPVault settles USDC
-> keccak256(report) on-chain -> buyer views report + verifiable hash
```

## Report schema (deliverable)
```json
{
  "agent": "Aegis", "version": "1.0",
  "target": { "address": "0x..|null", "network": "base", "compiler": "0.8.25" },
  "status": "ok | cannot_analyze", "reason": "string|null",
  "risk_score": 0, "summary": "string",
  "findings": [{ "id": "F-1", "severity": "critical|high|medium|low|info",
    "title": "string", "location": "Contract.sol:42", "source": "slither:reentrancy-eth|llm",
    "description": "string", "recommendation": "string" }],
  "confidence": "high|low", "generated_at": "ISO-8601"
}
```

## Setup

### 1. Engine (Python 3.11+)
```bash
cd engine
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # Windows; use .venv/bin/pip on macOS/Linux
.venv/Scripts/solc-select install 0.8.25 && .venv/Scripts/solc-select use 0.8.25
# LLM = Gemini via Vertex AI with ADC. First run: gcloud auth application-default login
# env (do NOT commit):
#   GOOGLE_CLOUD_PROJECT=...           (GCP project with Vertex AI enabled + billing)
#   GOOGLE_CLOUD_LOCATION=global       (gemini-3.x live in the `global` location)
#   AEGIS_LLM_MODEL=gemini-3.5-flash   (optional; default gemini-3.5-flash; or gemini-2.5-pro)
#   BASESCAN_API_KEY=...               (fetch verified source by address)
.venv/Scripts/pytest -q                      # 10 tests
.venv/Scripts/uvicorn aegis_engine.app:app --port 8731
```
Engine endpoint: `POST /audit { "source": "<solidity>" }` or `{ "address": "0x.." }` -> report JSON. `GET /health`.

### 2. Provider (Node 18+)
```bash
cd provider
npm install
cp .env.example .env        # then fill CROO_SDK_KEY (from the CROO dashboard) — never commit .env
npm test                    # engine-client unit test
npm run dev                 # starts the CAP listener (requires the engine running + a valid CROO_SDK_KEY)
```

### 3. Web (Next.js)
```bash
cd web
npm install
npm run dev                 # http://localhost:3000  (landing + /report renderer)
npm run build               # production build
```

## CAP integration notes (`@croo-network/sdk` v0.2.1)
- Client: `new AgentClient({ baseURL, wsURL }, sdkKey)`.
- Connect: `const stream = await client.connectWebSocket()` (auto-reconnect, heartbeat).
- Events: `stream.on(EventType.NegotiationCreated, ...)`, `stream.on(EventType.OrderPaid, ...)`.
  Event fields are snake_case (`negotiation_id`, `order_id`).
- Accept: `await client.acceptNegotiation(negotiationId)` -> `{ negotiation, order }`.
- Buyer input (the contract address / source) is read from `negotiation.requirements`
  (resolved via `client.getOrder(orderId)` -> `client.getNegotiation(order.negotiationId)`).
- Deliver: `await client.deliverOrder(orderId, { deliverableType: DeliverableType.Text, deliverableText: JSON.stringify(report) })` -> `{ order, delivery, txHash }`.
- Contracts (Base mainnet): CAPCore `0xaD46f1Eba2fe9cBB689D2874a52039192F2ac821`, CAPVault `0x33ECdcC8dD32330ec5a62AB1986F25ED5B5D170d`.

## Go-live checklist (to ship the agent)
1. Register agent "Aegis" at https://agent.croo.network -> copy API key into `provider/.env` (`CROO_SDK_KEY`).
2. Add service "Smart Contract Audit": price 0.5 USDC, SLA 0h30m, deliverable Schema/Text, requirements Text.
3. Fund the agent's AA wallet with a few USDC on Base (for testing the requester side).
4. Run engine (`uvicorn ... :8731`) + provider (`npm run dev`) — agent shows "Online".
5. Place a test order (requester agent) with `engine/tests/fixtures/VulnerableVault.sol`; confirm the
   delivered report catches the reentrancy and the on-chain hash is written.
6. Record a <=5-min demo video; file the BUIDL on DoraHacks (tracks: Developer Tooling + Open A2A); opt into pools.

## License
MIT — see [LICENSE](./LICENSE).
