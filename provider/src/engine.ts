export type AuditInput = { source?: string; address?: string };

export interface AuditReport {
  status: string;
  risk_score?: number;
  findings?: unknown[];
  [key: string]: unknown;
}

export async function runAudit(
  engineUrl: string,
  input: AuditInput
): Promise<AuditReport> {
  const res = await fetch(`${engineUrl}/audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(`engine ${res.status}`);
  return res.json() as Promise<AuditReport>;
}
