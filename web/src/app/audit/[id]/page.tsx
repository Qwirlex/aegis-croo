import AuditView from "@/components/AuditView";
import { loadAudit } from "@/lib/audit";

// Audits are produced at runtime, so this route renders per request.
export const dynamic = "force-dynamic";

export default async function AuditPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const report = await loadAudit(id);

  if (!report) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0d1117] p-8 text-[#e6edf3]">
        <div className="max-w-md text-center">
          <h1 className="mb-2 text-lg font-semibold">This audit is not ready yet</h1>
          <p className="text-sm text-gray-400">
            A full audit takes a few minutes. Poll the status url you received when you paid, then
            reload this page. Audits are kept for seven days.
          </p>
        </div>
      </main>
    );
  }

  return <AuditView report={report} id={id} />;
}
