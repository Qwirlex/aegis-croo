import type { AuditFinding, Severity } from "@/lib/audit";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300 border-red-500/30",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-200 border-yellow-500/30",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  info: "bg-white/5 text-gray-300 border-white/10",
};

function Block({ label, body }: { label: string; body: string }) {
  if (!body) return null;
  return (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">{label}</div>
      <p className="text-sm leading-relaxed text-gray-200">{body}</p>
    </div>
  );
}

export default function FindingCard({ finding }: { finding: AuditFinding }) {
  const ex = finding.code_excerpt;
  const angles = finding.provenance.length;
  return (
    <article className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
      <header className="mb-3 flex flex-wrap items-center gap-2">
        <span className={`rounded border px-2 py-0.5 text-[11px] uppercase ${SEVERITY_STYLE[finding.severity]}`}>
          {finding.severity}
        </span>
        <h3 className="text-base font-semibold text-white">{finding.title}</h3>
        <code className="ml-auto text-[12px] text-gray-400">{finding.location}</code>
      </header>

      {ex && (
        <div className="mb-4 overflow-x-auto rounded-lg border border-white/10 bg-black/40">
          <pre className="p-3 text-[12px] leading-relaxed">
            {ex.lines.map((line, i) => {
              const n = ex.start_line + i;
              const focus = n === ex.focus_line;
              return (
                <div key={n} className={focus ? "bg-yellow-500/10 text-yellow-100" : "text-gray-400"}>
                  <span className="mr-3 inline-block w-10 select-none text-right text-gray-600">{n}</span>
                  {line}
                </div>
              );
            })}
          </pre>
        </div>
      )}

      <div className="grid gap-4">
        <Block label="What is wrong" body={finding.description} />
        <Block label="What can happen" body={finding.impact} />
        <Block label="How it plays out" body={finding.exploit_scenario} />
        <Block label="How to fix it" body={finding.recommendation} />
      </div>

      {finding.also_flagged?.length > 0 && (
        <div className="mt-4 rounded-lg border border-white/10 bg-white/[0.02] p-3">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-gray-500">
            Another angle on the same line
          </div>
          <ul className="grid gap-1 text-sm text-gray-300">
            {finding.also_flagged.map((a, i) => (
              <li key={i}>{a.description || a.category}</li>
            ))}
          </ul>
        </div>
      )}

      <footer className="mt-4 flex flex-wrap gap-2 text-[11px] text-gray-500">
        {finding.provenance.map((p) => (
          <span key={p} className="rounded bg-white/5 px-2 py-0.5 font-mono">{p}</span>
        ))}
        {angles > 1 && (
          <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-emerald-300">
            flagged from {angles} angles
          </span>
        )}
        {finding.refutation?.verdict === "kept" && (
          <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-emerald-300">
            survived the refutation pass
          </span>
        )}
        {finding.refutation?.verdict === "demoted" && (
          <span className="rounded bg-white/5 px-2 py-0.5">
            weakened by review: {finding.refutation.reason}
          </span>
        )}
        {finding.refutation?.verdict === "not_checked" && (
          <span className="rounded bg-white/5 px-2 py-0.5">
            not challenged: {finding.refutation.reason}
          </span>
        )}
      </footer>
    </article>
  );
}
