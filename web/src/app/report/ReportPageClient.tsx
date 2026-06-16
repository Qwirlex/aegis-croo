"use client";

import { useState, useEffect, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import ReportView from "@/components/ReportView";
import { Report } from "@/lib/report";

// ─────────────────────────────────────────────
// Sample report (reentrancy example)
// ─────────────────────────────────────────────
const SAMPLE_REPORT: Report = {
  agent: "Aegis",
  version: "1.0",
  target: {
    address: "0xd6524721d0a0761f57946eba4e23fbbf278bd1ed",
    network: "base",
    compiler: "0.8.25",
  },
  status: "ok",
  reason: null,
  risk_score: 100,
  summary:
    "The withdraw function sends funds before it sets the balance to zero. A malicious contract can call back into withdraw and drain the vault.",
  findings: [
    {
      id: "F-1",
      severity: "critical",
      title: "Reentrancy in the withdraw function",
      location: "VulnerableVault.sol:8",
      source: "slither:reentrancy-eth",
      description:
        "The external call sends funds before the balance is set to zero, so an attacker contract can call back into the withdraw function and drain the vault.",
      recommendation:
        "Set the balance to zero before the external call, or use a reentrancy guard such as the OpenZeppelin ReentrancyGuard.",
    },
    {
      id: "F-2",
      severity: "low",
      title: "Unchecked low level call",
      location: "VulnerableVault.sol:8",
      source: "slither:low-level-calls",
      description:
        "The return value of the low level call is not checked, so a failed transfer can pass silently.",
      recommendation:
        "Check the success value and revert on failure, or use a safer transfer method.",
    },
  ],
  confidence: "high",
  generated_at: "2026-06-16T12:00:00Z",
};

const SAMPLE_JSON = JSON.stringify(SAMPLE_REPORT, null, 2);

// ─────────────────────────────────────────────
// Parse helper
// ─────────────────────────────────────────────
function tryParse(text: string): { report: Report | null; error: string | null } {
  try {
    const parsed = JSON.parse(text) as Report;
    if (!parsed.agent || !parsed.status || !parsed.target) {
      return {
        report: null,
        error: "JSON parsed but missing required fields (agent, status, target).",
      };
    }
    return { report: parsed, error: null };
  } catch (e) {
    return { report: null, error: `Invalid JSON: ${(e as Error).message}` };
  }
}

// ─────────────────────────────────────────────
// Client component
// ─────────────────────────────────────────────
export default function ReportPageClient() {
  const searchParams = useSearchParams();
  const [rawJson, setRawJson] = useState<string>(SAMPLE_JSON);
  const [report, setReport] = useState<Report | null>(SAMPLE_REPORT);
  const [parseError, setParseError] = useState<string | null>(null);
  const [showEditor, setShowEditor] = useState(false);

  // Handle ?data= query param on mount
  useEffect(() => {
    const dataParam = searchParams.get("data");
    if (!dataParam) return;

    // Try base64 decode first, then URL decode
    let decoded: string | null = null;
    try {
      decoded = atob(dataParam);
    } catch {
      try {
        decoded = decodeURIComponent(dataParam);
      } catch {
        setParseError("Could not decode ?data parameter.");
        setReport(null);
        return;
      }
    }

    const { report: parsed, error } = tryParse(decoded);
    if (parsed) {
      setRawJson(JSON.stringify(parsed, null, 2));
      setReport(parsed);
      setParseError(null);
    } else {
      setParseError(error);
      setReport(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRender = useCallback(() => {
    const { report: parsed, error } = tryParse(rawJson);
    setReport(parsed);
    setParseError(error);
    if (parsed) setShowEditor(false);
  }, [rawJson]);

  const handleLoadSample = useCallback(() => {
    setRawJson(SAMPLE_JSON);
    setReport(SAMPLE_REPORT);
    setParseError(null);
    setShowEditor(false);
  }, []);

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#e6edf3]">
      {/* Toolbar */}
      <div className="sticky top-0 z-10 border-b border-[#21262d] bg-[#0d1117]/95 backdrop-blur px-4 py-3">
        <div className="max-w-4xl mx-auto flex items-center gap-3 flex-wrap">
          <span className="text-xs font-mono text-gray-500 mr-auto">
            aegis / report viewer
          </span>
          <button
            onClick={() => setShowEditor((v) => !v)}
            className="text-xs px-3 py-1.5 rounded border border-[#30363d] bg-[#161b22] hover:bg-[#21262d] transition-colors"
          >
            {showEditor ? "Hide Editor" : "Paste JSON"}
          </button>
          <button
            onClick={handleLoadSample}
            className="text-xs px-3 py-1.5 rounded border border-[#30363d] bg-[#161b22] hover:bg-[#21262d] transition-colors text-blue-400"
          >
            Load Sample
          </button>
        </div>
      </div>

      {/* JSON editor panel */}
      {showEditor && (
        <div className="max-w-4xl mx-auto px-4 py-6 space-y-3">
          <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
            Paste Aegis Report JSON
          </label>
          <textarea
            className="w-full h-64 font-mono text-xs bg-[#161b22] border border-[#30363d] rounded-lg p-4 text-[#c9d1d9] resize-y focus:outline-none focus:border-blue-600 transition-colors placeholder-gray-600"
            value={rawJson}
            onChange={(e) => setRawJson(e.target.value)}
            placeholder='{ "agent": "Aegis", ... }'
            spellCheck={false}
          />
          {parseError && (
            <div className="flex items-start gap-2 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3">
              <svg
                className="w-4 h-4 text-red-500 mt-0.5 shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
              <p className="text-sm text-red-400">{parseError}</p>
            </div>
          )}
          <div className="flex gap-3">
            <button
              onClick={handleRender}
              className="px-4 py-2 text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Render Report
            </button>
            <button
              onClick={handleLoadSample}
              className="px-4 py-2 text-sm border border-[#30363d] bg-[#161b22] hover:bg-[#21262d] rounded-lg transition-colors text-gray-400"
            >
              Reset to Sample
            </button>
          </div>
        </div>
      )}

      {/* Parse error (editor hidden) */}
      {!showEditor && parseError && (
        <div className="max-w-4xl mx-auto px-4 py-4">
          <div className="flex items-start gap-2 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3">
            <svg
              className="w-4 h-4 text-red-500 mt-0.5 shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
            <div>
              <p className="text-sm font-semibold text-red-400">Invalid report JSON</p>
              <p className="text-xs text-red-300 mt-0.5">{parseError}</p>
            </div>
          </div>
        </div>
      )}

      {/* Report view */}
      {report && !showEditor && <ReportView report={report} />}
    </div>
  );
}
