const DEFAULT_BASE_URL = process.env.REPORT_BASE_URL ?? "https://aegiscan.xyz";

/** Stateless link to the hosted /report viewer: ?data=<percent-encoded base64(report)>. */
export function reportUrl(report: unknown, baseUrl: string = DEFAULT_BASE_URL): string {
  const json = JSON.stringify(report);
  const b64 = Buffer.from(json, "utf8").toString("base64");
  const base = baseUrl.replace(/\/$/, "");
  return `${base}/report?data=${encodeURIComponent(b64)}`;
}

/** Human-first delivery text: a clickable report link, then the raw JSON for A2A consumers. */
export function buildDeliverable(report: unknown, baseUrl: string = DEFAULT_BASE_URL): string {
  return `View your formatted audit report: ${reportUrl(report, baseUrl)}\n\n${JSON.stringify(report)}`;
}
