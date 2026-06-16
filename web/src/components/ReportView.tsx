"use client";

import { Report, Finding, Severity } from "@/lib/report";

// ─────────────────────────────────────────────
// Severity helpers
// ─────────────────────────────────────────────
const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_STYLES: Record<Severity, { pill: string; card: string; border: string }> = {
  critical: {
    pill: "bg-red-600 text-white",
    card: "bg-[#1a0e0e]",
    border: "border-red-700",
  },
  high: {
    pill: "bg-orange-600 text-white",
    card: "bg-[#1a1208]",
    border: "border-orange-700",
  },
  medium: {
    pill: "bg-amber-500 text-black",
    card: "bg-[#1a1600]",
    border: "border-amber-600",
  },
  low: {
    pill: "bg-slate-500 text-white",
    card: "bg-[#111620]",
    border: "border-slate-600",
  },
  info: {
    pill: "bg-gray-600 text-white",
    card: "bg-[#131313]",
    border: "border-gray-700",
  },
};

// ─────────────────────────────────────────────
// Risk score helpers
// ─────────────────────────────────────────────
function riskColor(score: number): string {
  if (score <= 20) return "#22c55e"; // green
  if (score <= 50) return "#f59e0b"; // amber
  if (score <= 80) return "#f97316"; // orange
  return "#ef4444"; // red
}

function riskLabel(score: number): string {
  if (score <= 20) return "Low Risk";
  if (score <= 50) return "Medium Risk";
  if (score <= 80) return "High Risk";
  return "Critical Risk";
}

// ─────────────────────────────────────────────
// Risk Gauge (SVG circle)
// ─────────────────────────────────────────────
function RiskGauge({ score }: { score: number }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.min(100, Math.max(0, score));
  const offset = circumference - (clampedScore / 100) * circumference;
  const color = riskColor(clampedScore);

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-[120px] h-[120px]">
        <svg
          viewBox="0 0 100 100"
          width={120}
          height={120}
          style={{ transform: "rotate(-90deg)" }}
        >
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke="#30363d"
            strokeWidth="10"
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>
            {clampedScore}
          </span>
          <span className="text-[10px] text-gray-400 uppercase tracking-widest">
            / 100
          </span>
        </div>
      </div>
      <span className="text-sm font-semibold" style={{ color }}>
        {riskLabel(clampedScore)}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────
// Finding card
// ─────────────────────────────────────────────
function FindingCard({ finding }: { finding: Finding }) {
  const styles = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES.info;

  return (
    <div
      className={`rounded-lg border ${styles.border} ${styles.card} p-5 space-y-3`}
    >
      {/* Header row */}
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-full ${styles.pill}`}
        >
          {finding.severity}
        </span>
        <span className="font-semibold text-[#e6edf3]">{finding.title}</span>
        <span className="ml-auto text-xs bg-[#0d1117] border border-[#30363d] rounded px-2 py-0.5 text-gray-400">
          {finding.source}
        </span>
      </div>

      {/* Location */}
      <div className="font-mono text-xs text-[#7ee787] bg-[#0d1117] rounded px-3 py-1.5 inline-block border border-[#21262d]">
        {finding.location}
      </div>

      {/* Description */}
      <p className="text-sm text-[#c9d1d9] leading-relaxed">{finding.description}</p>

      {/* Recommendation */}
      <div className="border-l-2 border-blue-500 bg-[#0c1a2e] rounded-r px-4 py-3">
        <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-1">
          Fix
        </p>
        <p className="text-sm text-[#c9d1d9] leading-relaxed">
          {finding.recommendation}
        </p>
      </div>

      {/* Finding ID */}
      <div className="text-right">
        <span className="text-[10px] text-gray-600 font-mono">{finding.id}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Confidence badge
// ─────────────────────────────────────────────
function ConfidenceBadge({ confidence }: { confidence: "high" | "low" }) {
  const isHigh = confidence === "high";
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border ${
        isHigh
          ? "bg-green-900/40 border-green-700 text-green-400"
          : "bg-yellow-900/40 border-yellow-700 text-yellow-400"
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${isHigh ? "bg-green-400" : "bg-yellow-400"}`}
      />
      {isHigh ? "High Confidence" : "Low Confidence"}
    </span>
  );
}

// ─────────────────────────────────────────────
// Main ReportView
// ─────────────────────────────────────────────
export interface ReportViewProps {
  report: Report;
  txHash?: string;
}

export default function ReportView({ report, txHash }: ReportViewProps) {
  const sorted = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  const targetDisplay =
    report.target.address && report.target.address.startsWith("0x")
      ? `${report.target.address.slice(0, 8)}…${report.target.address.slice(-6)}`
      : "Pasted source";

  const formattedDate = new Date(report.generated_at).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#e6edf3]">
      {/* Top bar */}
      <header className="border-b border-[#21262d] bg-[#161b22] px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            {/* Shield icon */}
            <svg
              className="w-8 h-8 text-blue-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
            <div>
              <h1 className="font-bold text-lg tracking-tight">
                {report.agent}
                <span className="ml-2 text-xs font-normal text-gray-500">
                  v{report.version}
                </span>
              </h1>
              <p className="text-xs text-gray-500">Smart Contract Security Report</p>
            </div>
          </div>
          <ConfidenceBadge confidence={report.confidence} />
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-8">
        {/* Meta card */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            {/* Left: target info */}
            <div className="space-y-4">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                  Target
                </p>
                <p className="font-mono text-sm text-[#58a6ff]">
                  {report.target.address ? (
                    <>
                      <span className="hidden sm:inline">{report.target.address}</span>
                      <span className="sm:hidden">{targetDisplay}</span>
                    </>
                  ) : (
                    "Pasted source"
                  )}
                </p>
              </div>

              <div className="flex gap-6">
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                    Network
                  </p>
                  <span className="inline-flex items-center gap-1.5 text-xs bg-blue-900/30 text-blue-300 border border-blue-800 rounded-full px-3 py-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                    {report.target.network}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                    Compiler
                  </p>
                  <span className="font-mono text-sm text-[#c9d1d9]">
                    {report.target.compiler}
                  </span>
                </div>
              </div>

              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">
                  Generated
                </p>
                <p className="text-sm text-[#c9d1d9]">{formattedDate}</p>
              </div>

              {/* Verified on-chain badge */}
              {txHash && (
                <div>
                  <a
                    href={`https://basescan.org/tx/${txHash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-xs bg-emerald-900/30 text-emerald-400 border border-emerald-800 rounded-full px-3 py-1.5 hover:bg-emerald-900/50 transition-colors"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Verified on-chain, {txHash.slice(0, 10)}…
                  </a>
                </div>
              )}
            </div>

            {/* Right: risk gauge */}
            <div className="flex items-center justify-center sm:justify-end">
              <RiskGauge score={report.risk_score} />
            </div>
          </div>
        </div>

        {/* Summary */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
            Summary
          </h2>
          <p className="text-[#c9d1d9] leading-relaxed">{report.summary}</p>
        </div>

        {/* Cannot analyze path */}
        {report.status === "cannot_analyze" && (
          <div className="bg-[#1a1400] border border-yellow-800 rounded-xl p-6">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-yellow-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <h3 className="font-semibold text-yellow-400 mb-1">
                  Analysis could not be completed
                </h3>
                <p className="text-sm text-[#c9d1d9]">
                  {report.reason ?? "No reason provided."}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Findings */}
        {report.status === "ok" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                Findings
              </h2>
              <span className="text-xs text-gray-500">
                {sorted.length} issue{sorted.length !== 1 ? "s" : ""}
              </span>
            </div>

            {sorted.length === 0 ? (
              <div className="bg-green-900/20 border border-green-800 rounded-xl p-6 text-center">
                <p className="text-green-400 font-semibold">No findings, clean audit</p>
              </div>
            ) : (
              <div className="space-y-4">
                {sorted.map((f) => (
                  <FindingCard key={f.id} finding={f} />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#21262d] mt-12 py-6 text-center text-xs text-gray-600">
        Aegis, AI suggests, you decide. No auto-postings, no on-chain changes.
      </footer>
    </div>
  );
}
