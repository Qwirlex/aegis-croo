import { test } from "node:test";
import assert from "node:assert/strict";
import { reportUrl, buildDeliverable } from "./report-link";

const REPORT = {
  agent: "Aegis",
  status: "ok",
  target: { address: "0xabc", network: "base", compiler: "0.8.25" },
  risk_score: 40,
  findings: [{ id: "F-1", severity: "high", title: "Reentrancy" }],
};

test("reportUrl yields a ?data= link that round-trips to the report", () => {
  const url = reportUrl(REPORT, "https://aegisscan.xyz");
  assert.ok(url.startsWith("https://aegisscan.xyz/report?data="));
  const data = decodeURIComponent(url.split("data=")[1]);
  const json = Buffer.from(data, "base64").toString("utf8");
  assert.deepEqual(JSON.parse(json), REPORT);
});

test("reportUrl percent-encodes base64 so + and / survive URLSearchParams", () => {
  const url = reportUrl(REPORT, "https://aegisscan.xyz");
  const raw = url.split("data=")[1];
  assert.ok(!raw.includes("+") && !raw.includes("/"), "must be percent-encoded");
});

test("buildDeliverable contains the link and the raw JSON", () => {
  const text = buildDeliverable(REPORT, "https://aegisscan.xyz");
  assert.ok(text.includes("https://aegisscan.xyz/report?data="));
  assert.ok(text.includes('"agent":"Aegis"') || text.includes('"agent": "Aegis"'));
});
