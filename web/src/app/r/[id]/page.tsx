import ReportView from "@/components/ReportView";
import { loadReport } from "@/lib/store";

// Reports are created at runtime, so this route must render per request.
export const dynamic = "force-dynamic";

export default async function StoredReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const report = await loadReport(id);

  if (!report) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center text-gray-500 text-sm">
        Report not found or expired.
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#e6edf3]">
      <ReportView report={report} />
    </div>
  );
}
