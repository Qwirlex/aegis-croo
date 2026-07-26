import FindingCard from "./FindingCard";
import PowersTable from "./PowersTable";
import { severityCounts, type AuditReport, type Verdict } from "@/lib/audit";

const VERDICT_COPY: Record<Verdict, { label: string; tone: string }> = {
  critical_risk: { label: "Critical risk", tone: "bg-red-500/15 text-red-200 border-red-500/40" },
  high_risk: { label: "High risk", tone: "bg-orange-500/15 text-orange-200 border-orange-500/40" },
  caution: { label: "Caution", tone: "bg-yellow-500/15 text-yellow-100 border-yellow-500/40" },
  looks_ok: { label: "Nothing serious found", tone: "bg-emerald-500/15 text-emerald-200 border-emerald-500/40" },
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-10">
      <h2 className="mb-4 text-sm uppercase tracking-wide text-gray-400">{title}</h2>
      {children}
    </section>
  );
}

export default function AuditView({ report, id }: { report: AuditReport; id: string }) {
  const v = VERDICT_COPY[report.verdict] ?? VERDICT_COPY.looks_ok;
  const counts = severityCounts(report.findings);
  const real = report.findings.filter((f) => f.severity !== "info");
  const tierLabel = report.tier === "scan" ? "quick scan" : "full audit";

  return (
    <main className="audit-report min-h-screen bg-[#0d1117] text-[#e6edf3]">
      <div className="mx-auto max-w-3xl px-5 py-10">
        <div className={`rounded-xl border p-5 ${v.tone}`}>
          <div className="flex flex-wrap items-baseline gap-3">
            <h1 className="text-2xl font-semibold">{v.label}</h1>
            <span className="text-sm opacity-80">risk score {report.risk_score} of 100</span>
            <span className="ml-auto text-xs opacity-70">confidence {report.confidence}</span>
          </div>
          <p className="mt-3 text-sm leading-relaxed opacity-95">{report.summary}</p>
          <p className="mt-3 text-[11px] opacity-70">
            This is a {tierLabel}. A clean result is not an endorsement. The audit reads code, it
            does not run it.
          </p>
        </div>

        <dl className="mt-5 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
          {[
            ["Contract", report.target.contract_name],
            ["Chain", report.target.chain],
            ["Compiler", report.target.compiler],
            ["Source", report.target.source_verified ? "verified" : "supplied"],
          ].map(([k, val]) => (
            <div key={k} className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
              <dt className="text-[11px] uppercase tracking-wide text-gray-500">{k}</dt>
              <dd className="mt-1 truncate font-mono text-[13px]">{val}</dd>
            </div>
          ))}
        </dl>

        {report.target.address && (
          <p className="mt-3 break-all font-mono text-[12px] text-gray-500">{report.target.address}</p>
        )}

        <div className="mt-5 flex flex-wrap gap-2 text-[12px]">
          {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
            <span key={s} className="rounded border border-white/10 bg-white/5 px-2 py-0.5">
              {counts[s]} {s}
            </span>
          ))}
        </div>

        {report.status === "degraded" && (
          <p className="mt-5 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-100">
            {report.reason} You have one free rerun, use the retry link from the status route.
          </p>
        )}

        <Section title={`Findings, ${real.length} that matter`}>
          {report.findings.length === 0 ? (
            <p className="text-sm text-gray-400">
              Nothing survived the refutation pass. The coverage list below says what was examined,
              which is the part worth reading when a report is empty.
            </p>
          ) : (
            <div className="grid gap-4">
              {report.findings.map((f) => <FindingCard key={f.id} finding={f} />)}
            </div>
          )}
        </Section>

        <Section title="What the owner can do">
          <PowersTable powers={report.privileged_powers} />
        </Section>

        <Section title="Method and coverage">
          <div className="grid gap-3 text-sm text-gray-300">
            <p>
              Lenses run: {report.coverage.lenses_run.join(", ") || "none"}. Static detectors that
              reported: {report.coverage.detectors_run}. Finished in{" "}
              {Math.max(1, Math.round(report.duration_ms / 1000))} seconds.
            </p>
            {report.coverage.lenses_skipped.length > 0 && (
              <p className="text-yellow-200/80">
                Skipped: {report.coverage.lenses_skipped.map((s) => s.lens).join(", ")}
              </p>
            )}
            {report.coverage.dropped?.length > 0 && (
              <p className="text-gray-400">
                Discarded for having no real line:{" "}
                {report.coverage.dropped.map((d) => `${d.lens} ${d.count}`).join(", ")}
              </p>
            )}
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">Not checked</div>
              <ul className="list-disc pl-5">
                {report.coverage.not_checked.map((n) => <li key={n}>{n}</li>)}
              </ul>
            </div>
          </div>
        </Section>

        <footer className="mt-10 border-t border-white/10 pt-5 text-[11px] leading-relaxed text-gray-500">
          <p>Audit {id}, generated {report.generated_at}, tier {report.tier}.</p>
          <p className="mt-1 break-all">Report hash {report.report_hash}</p>
          {report.signer ? (
            <p className="mt-1 break-all">
              Signed by {report.signer}. Recover the signer from the hash with any Ethereum message
              tool to confirm this report was not altered. Signature {report.report_signature}
            </p>
          ) : (
            <p className="mt-1">This run was not signed. The hash still lets you detect a change.</p>
          )}
        </footer>
      </div>
    </main>
  );
}
