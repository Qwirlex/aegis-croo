import { promises as fs } from "node:fs";
import path from "node:path";

// The engine writes <jobId>.json into this directory, the same one the older
// /r/<id> store uses, so a finished audit renders with no call between the two
// services. If the file is not there yet, the job is simply not done.
const STORE_DIR = process.env.AEGIS_REPORT_DIR ?? path.join(process.cwd(), ".reports");

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "critical_risk" | "high_risk" | "caution" | "looks_ok";

export interface CodeExcerpt {
  file: string;
  start_line: number;
  focus_line: number;
  lines: string[];
}

export interface AuditFinding {
  id: string;
  severity: Severity;
  title: string;
  location: string;
  category: string;
  description: string;
  impact: string;
  exploit_scenario: string;
  recommendation: string;
  provenance: string[];
  also_flagged: { category?: string; description?: string }[];
  refutation: { verdict: "kept" | "demoted" | "not_checked"; reason: string } | null;
  code_excerpt: CodeExcerpt | null;
  confidence: "high" | "medium" | "low";
}

export interface PrivilegedPower {
  function: string;
  file: string;
  line: number;
  visibility: string;
  modifiers: string[];
  capability: string;
  can_move_funds: boolean;
  confidence: "high" | "medium" | "low";
}

export interface AuditReport {
  agent: string;
  version: string;
  tier: "scan" | "audit";
  target: {
    address: string | null;
    chain: string;
    chain_id: number;
    contract_name: string;
    compiler: string;
    source_verified: boolean;
  };
  status: "ok" | "cannot_analyze" | "degraded";
  reason: string | null;
  verdict: Verdict;
  risk_score: number;
  confidence: "high" | "medium" | "low";
  summary: string;
  findings: AuditFinding[];
  privileged_powers: PrivilegedPower[];
  coverage: {
    lenses_run: string[];
    lenses_skipped: { lens: string; reason: string }[];
    dropped: { lens: string; count: number }[];
    detectors_run: number;
    not_checked: string[];
  };
  generated_at: string;
  duration_ms: number;
  report_hash: string;
  report_signature: string;
  signer: string;
}

export async function loadAudit(id: string): Promise<AuditReport | null> {
  // Job ids are twelve hex characters. Nothing else reaches the filesystem.
  if (!/^[a-f0-9]{12}$/.test(id)) return null;
  try {
    const raw = await fs.readFile(path.join(STORE_DIR, `${id}.json`), "utf8");
    return JSON.parse(raw) as AuditReport;
  } catch {
    return null;
  }
}

export function severityCounts(findings: AuditFinding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}
