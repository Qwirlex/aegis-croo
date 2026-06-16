import { Suspense } from "react";
import ReportPageClient from "./ReportPageClient";

export default function ReportPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#0d1117] flex items-center justify-center text-gray-500 text-sm">
          Loading…
        </div>
      }
    >
      <ReportPageClient />
    </Suspense>
  );
}
