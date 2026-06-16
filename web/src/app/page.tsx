import Link from "next/link";

// ─────────────────────────────────────────────
// Shield icon (matches ReportView header)
// ─────────────────────────────────────────────
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
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
  );
}

// ─────────────────────────────────────────────
// Step card for "How it works"
// ─────────────────────────────────────────────
function Step({
  number,
  title,
  description,
}: {
  number: number;
  title: string;
  description: string;
}) {
  return (
    <div className="flex gap-4">
      <div className="shrink-0 w-8 h-8 rounded-full bg-blue-900/50 border border-blue-700 flex items-center justify-center text-blue-400 text-sm font-bold">
        {number}
      </div>
      <div className="pt-0.5">
        <p className="font-semibold text-[#e6edf3] mb-1">{title}</p>
        <p className="text-sm text-[#8b949e] leading-relaxed">{description}</p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Credibility feature pill
// ─────────────────────────────────────────────
function FeaturePill({
  icon,
  label,
}: {
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2.5 bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-3 text-sm text-[#c9d1d9]">
      <span className="text-blue-400">{icon}</span>
      {label}
    </div>
  );
}

// ─────────────────────────────────────────────
// Placeholder link (clearly marked)
// ─────────────────────────────────────────────
function PlaceholderLink({
  label,
  note,
}: {
  label: string;
  note?: string;
}) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[#21262d] last:border-0">
      <span className="text-[#e6edf3] text-sm">{label}</span>
      <span className="inline-flex items-center gap-1.5 text-xs text-gray-500 border border-[#30363d] rounded px-2.5 py-1">
        <span className="w-1.5 h-1.5 rounded-full bg-gray-600" />
        {note ?? "Coming at launch"}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────
// Landing page (server component)
// ─────────────────────────────────────────────
export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#0d1117] text-[#e6edf3]">
      {/* ── Nav ── */}
      <header className="border-b border-[#21262d] bg-[#161b22] px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <ShieldIcon className="w-7 h-7 text-blue-400" />
            <span className="font-bold text-lg tracking-tight">Aegis</span>
          </div>
          <Link
            href="/report"
            className="text-sm text-[#58a6ff] hover:text-blue-300 transition-colors"
          >
            Live demo →
          </Link>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6">
        {/* ── Hero ── */}
        <section className="py-20 flex flex-col items-center text-center gap-6">
          <div className="inline-flex items-center gap-2 text-xs bg-blue-900/30 text-blue-300 border border-blue-800 rounded-full px-3 py-1.5 mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
            CAP Agent · Base Mainnet · 0.5 USDC/audit
          </div>

          <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight max-w-2xl">
            Aegis
          </h1>
          <p className="text-lg sm:text-xl text-[#8b949e] max-w-xl leading-relaxed">
            On-chain smart-contract auditor agent. Slither + LLM. Verifiable on Base.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 mt-2">
            <Link
              href="/report"
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-3 rounded-lg transition-colors text-sm"
            >
              <ShieldIcon className="w-4 h-4" />
              See a live report
            </Link>
            <a
              href="#how-it-works"
              className="inline-flex items-center gap-2 text-sm text-[#8b949e] hover:text-[#e6edf3] border border-[#30363d] rounded-lg px-6 py-3 transition-colors"
            >
              How it works
            </a>
          </div>
        </section>

        {/* ── How it works ── */}
        <section
          id="how-it-works"
          className="py-14 border-t border-[#21262d]"
        >
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-8">
            How it works
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-8 max-w-3xl">
            <Step
              number={1}
              title="Send a contract via CAP"
              description="Pass a verified Base address or pasted Solidity source to Aegis through the CROO Agent Protocol. Any developer or agent can call it."
            />
            <Step
              number={2}
              title="Pay 0.5 USDC — escrowed on-chain"
              description="The fee is held in the CAP escrow contract and released on delivery. No upfront trust required."
            />
            <Step
              number={3}
              title="Aegis runs Slither + LLM"
              description="Real static analysis with Slither detectors, combined with LLM reasoning. Every finding is grounded in a detector name or a specific code line — no hallucinated issues."
            />
            <Step
              number={4}
              title="Receive a verified audit report"
              description="A severity-ranked JSON report is returned. Its hash is committed on-chain by CAP, giving you a tamper-proof, timestamped proof of audit."
            />
          </div>
        </section>

        {/* ── Why it's credible ── */}
        <section className="py-14 border-t border-[#21262d]">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-8">
            Why Aegis findings are credible
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-w-4xl">
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2V9l-6-6z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v6h6" />
                </svg>
              }
              label="Real static analysis via Slither"
            />
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              }
              label="LLM reasoning over real findings"
            />
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
              }
              label="Every finding cites a detector or line"
            />
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
              label="Report hash committed on-chain"
            />
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              }
              label="Read-only — no wallet permissions"
            />
            <FeaturePill
              icon={
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
                </svg>
              }
              label="Severity-ranked, actionable output"
            />
          </div>
        </section>

        {/* ── A2A / For agents ── */}
        <section className="py-14 border-t border-[#21262d]">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">
            Built for agent-to-agent composability
          </h2>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 max-w-3xl space-y-4">
            <p className="text-[#c9d1d9] leading-relaxed">
              Aegis is a first-class CAP agent. Other agents — deployers, code
              generators, DeFi bots — can hire Aegis as a pre-deploy dependency
              without any human in the loop.
            </p>
            <ul className="space-y-2 text-sm text-[#8b949e]">
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                Machine-readable JSON deliverable — parse findings programmatically.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                Deterministic call interface via CROO Agent Protocol.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                On-chain proof lets downstream agents verify the audit occurred.
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5">✓</span>
                "AI suggests, you decide" — Aegis never writes transactions on your behalf.
              </li>
            </ul>
          </div>
        </section>

        {/* ── Service details + placeholder links ── */}
        <section className="py-14 border-t border-[#21262d]">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-8">
            Service details
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 max-w-3xl">
            {/* Details */}
            <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 space-y-4">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Service</p>
                <p className="text-sm text-[#e6edf3]">Smart Contract Audit</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Price</p>
                <p className="text-sm text-[#e6edf3]">0.5 USDC per audit</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Network</p>
                <span className="inline-flex items-center gap-1.5 text-xs bg-blue-900/30 text-blue-300 border border-blue-800 rounded-full px-3 py-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                  Base Mainnet
                </span>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Protocol</p>
                <p className="text-sm text-[#e6edf3]">CROO Agent Protocol (CAP)</p>
              </div>
            </div>

            {/* Placeholder links */}
            <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6">
              <p className="text-xs text-gray-500 uppercase tracking-wider mb-4">Links</p>
              <PlaceholderLink label="Agent Store listing" />
              <PlaceholderLink label="GitHub repo" />
              <PlaceholderLink label="Demo video" />
              <p className="text-xs text-gray-600 mt-4">
                These links go live at launch.
              </p>
            </div>
          </div>
        </section>

        {/* ── Demo CTA ── */}
        <section className="py-14 border-t border-[#21262d] flex flex-col items-center text-center gap-5">
          <ShieldIcon className="w-10 h-10 text-blue-400" />
          <h2 className="text-2xl font-bold">See Aegis in action</h2>
          <p className="text-[#8b949e] text-sm max-w-sm">
            The live report page renders a real audit result — severity rankings,
            Slither findings, and an on-chain verification link.
          </p>
          <Link
            href="/report"
            className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-3 rounded-lg transition-colors text-sm"
          >
            <ShieldIcon className="w-4 h-4" />
            Open live report
          </Link>
        </section>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-[#21262d] mt-4 py-6 px-6">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-600">
          <div className="flex items-center gap-2">
            <ShieldIcon className="w-4 h-4 text-gray-600" />
            <span>Aegis — AI suggests, you decide. No auto-postings, no on-chain changes.</span>
          </div>
          <span>Built on CROO Agent Protocol · Base Mainnet</span>
        </div>
      </footer>
    </div>
  );
}
