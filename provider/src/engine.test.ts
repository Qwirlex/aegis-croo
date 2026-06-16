import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as http from "node:http";
import { runAudit } from "./engine";

/** Starts a one-shot stub HTTP server and returns its base URL. */
function startStubServer(
  responseBody: object
): Promise<{ url: string; server: http.Server }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(responseBody));
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({ url: `http://127.0.0.1:${addr.port}`, server });
    });
  });
}

test("runAudit: returns parsed JSON from stub server", async () => {
  const stubResponse = { status: "ok", risk_score: 100, findings: [] };
  const { url, server } = await startStubServer(stubResponse);

  try {
    const report = await runAudit(url, { address: "0xdeadbeef" });
    assert.equal(report.status, "ok");
    assert.equal(report.risk_score, 100);
    assert.deepEqual(report.findings, []);
  } finally {
    await new Promise<void>((res) => server.close(() => res()));
  }
});

test("runAudit: throws on non-2xx response", async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(500);
    res.end("Internal Server Error");
  });
  await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
  const addr = server.address() as { port: number };
  const url = `http://127.0.0.1:${addr.port}`;

  try {
    await assert.rejects(
      () => runAudit(url, { source: "pragma solidity ^0.8.0;" }),
      /engine 500/
    );
  } finally {
    await new Promise<void>((res) => server.close(() => res()));
  }
});
