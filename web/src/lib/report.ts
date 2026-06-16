export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "ok" | "cannot_analyze";
export type Confidence = "high" | "low";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  location: string;
  source: string;
  description: string;
  recommendation: string;
}

export interface ReportTarget {
  address: string | null;
  network: string;
  compiler: string;
}

export interface Report {
  agent: string;
  version: string;
  target: ReportTarget;
  status: Status;
  reason: string | null;
  risk_score: number;
  summary: string;
  findings: Finding[];
  confidence: Confidence;
  generated_at: string;
}
