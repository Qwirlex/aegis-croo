import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { Report } from "./report";

// Reports are content-addressed and written to disk so the audit link can be a
// short /r/<id> instead of carrying the whole report base64-encoded in the URL.
// The directory is configurable so the systemd service can point it at a stable
// writable path; it defaults to a .reports folder next to the running app.
const STORE_DIR = process.env.AEGIS_REPORT_DIR ?? path.join(process.cwd(), ".reports");

/** Short, stable id derived from the report content. Identical reports collide
 *  on purpose, so re-delivering the same audit reuses one stored file. */
function idFor(json: string): string {
  return crypto.createHash("sha256").update(json).digest("hex").slice(0, 12);
}

export async function saveReport(report: unknown): Promise<string> {
  const json = JSON.stringify(report);
  const id = idFor(json);
  await fs.mkdir(STORE_DIR, { recursive: true });
  await fs.writeFile(path.join(STORE_DIR, `${id}.json`), json, "utf8");
  return id;
}

export async function loadReport(id: string): Promise<Report | null> {
  // Guard against path traversal: ids are hex hashes, nothing else is valid.
  if (!/^[a-f0-9]{6,32}$/.test(id)) return null;
  try {
    const raw = await fs.readFile(path.join(STORE_DIR, `${id}.json`), "utf8");
    return JSON.parse(raw) as Report;
  } catch {
    return null;
  }
}
