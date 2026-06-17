const DEFAULT_BASE_URL = process.env.REPORT_BASE_URL ?? "https://aegiscan.xyz";
// Where the provider stores the report to mint a short link. Defaults to the
// local web app so the round-trip stays on the box and never leaves via Caddy.
const DEFAULT_API_BASE = process.env.REPORT_API_BASE ?? "http://127.0.0.1:3000";

type FetchFn = typeof fetch;

export interface LinkOpts {
  baseUrl?: string;
  apiBase?: string;
  fetchFn?: FetchFn;
}

/** Stateless link to the hosted /report viewer: ?data=<percent-encoded base64(report)>.
 *  Self-contained but long; used as the fallback when the short-link store is down. */
export function reportUrl(report: unknown, baseUrl: string = DEFAULT_BASE_URL): string {
  const json = JSON.stringify(report);
  const b64 = Buffer.from(json, "utf8").toString("base64");
  const base = baseUrl.replace(/\/$/, "");
  return `${base}/report?data=${encodeURIComponent(b64)}`;
}

/** Store the report on the web app and return a short /r/<id> link.
 *  Falls back to the long, stateless ?data= link if the store is unreachable,
 *  so delivery never fails just because the short-link path is down. */
export async function shortReportUrl(report: unknown, opts: LinkOpts = {}): Promise<string> {
  const baseUrl = opts.baseUrl ?? DEFAULT_BASE_URL;
  const apiBase = (opts.apiBase ?? DEFAULT_API_BASE).replace(/\/$/, "");
  const doFetch = opts.fetchFn ?? fetch;
  try {
    const res = await doFetch(`${apiBase}/api/r`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(report),
    });
    if (!res.ok) throw new Error(`store ${res.status}`);
    const { id } = (await res.json()) as { id?: string };
    if (!id) throw new Error("store returned no id");
    return `${baseUrl.replace(/\/$/, "")}/r/${id}`;
  } catch {
    return reportUrl(report, baseUrl);
  }
}

/** Human-first delivery text: a clickable report link, then the raw JSON for A2A consumers.
 *  Prefers the short /r/<id> link, falling back to the long ?data= link. */
export async function buildDeliverable(report: unknown, opts: LinkOpts = {}): Promise<string> {
  const url = await shortReportUrl(report, opts);
  return `View your formatted audit report: ${url}\n\n${JSON.stringify(report)}`;
}
