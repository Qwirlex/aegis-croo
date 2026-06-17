import { test } from "node:test";
import assert from "node:assert/strict";
import { reportUrl, shortReportUrl, buildDeliverable } from "./report-link";

const REPORT = {
  agent: "Aegis",
  status: "ok",
  target: { address: "0xabc", network: "base", compiler: "0.8.25" },
  risk_score: 40,
  findings: [{ id: "F-1", severity: "high", title: "Reentrancy" }],
};

test("reportUrl yields a ?data= link that round-trips to the report", () => {
  const url = reportUrl(REPORT, "https://aegiscan.xyz");
  assert.ok(url.startsWith("https://aegiscan.xyz/report?data="));
  const data = decodeURIComponent(url.split("data=")[1]);
  const json = Buffer.from(data, "base64").toString("utf8");
  assert.deepEqual(JSON.parse(json), REPORT);
});

test("reportUrl percent-encodes base64 so + and / survive URLSearchParams", () => {
  const url = reportUrl(REPORT, "https://aegiscan.xyz");
  const raw = url.split("data=")[1];
  assert.ok(!raw.includes("+") && !raw.includes("/"), "must be percent-encoded");
});

test("shortReportUrl posts the report and returns a short /r/<id> link", async () => {
  let posted: unknown = null;
  const fetchFn = async (url: string | URL, init?: RequestInit) => {
    posted = JSON.parse(String(init?.body));
    assert.ok(String(url).endsWith("/api/r"));
    return new Response(JSON.stringify({ id: "abc123def456" }), { status: 200 });
  };
  const url = await shortReportUrl(REPORT, {
    baseUrl: "https://aegiscan.xyz",
    apiBase: "http://127.0.0.1:3000",
    fetchFn: fetchFn as unknown as typeof fetch,
  });
  assert.equal(url, "https://aegiscan.xyz/r/abc123def456");
  assert.deepEqual(posted, REPORT);
});

test("shortReportUrl falls back to the long ?data= link when the store is down", async () => {
  const fetchFn = async () => new Response("nope", { status: 500 });
  const url = await shortReportUrl(REPORT, {
    baseUrl: "https://aegiscan.xyz",
    fetchFn: fetchFn as unknown as typeof fetch,
  });
  assert.ok(url.startsWith("https://aegiscan.xyz/report?data="));
});

test("buildDeliverable contains the link and the raw JSON", async () => {
  const fetchFn = async () => new Response(JSON.stringify({ id: "deadbeef0001" }), { status: 200 });
  const text = await buildDeliverable(REPORT, {
    baseUrl: "https://aegiscan.xyz",
    fetchFn: fetchFn as unknown as typeof fetch,
  });
  assert.ok(text.includes("https://aegiscan.xyz/r/deadbeef0001"));
  assert.ok(text.includes('"agent":"Aegis"') || text.includes('"agent": "Aegis"'));
});
