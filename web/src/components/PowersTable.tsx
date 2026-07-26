import type { PrivilegedPower } from "@/lib/audit";

export default function PowersTable({ powers }: { powers: PrivilegedPower[] }) {
  if (powers.length === 0) {
    return (
      <p className="text-sm text-gray-400">
        No function in this contract is limited to a privileged caller, so there is no owner power
        to list.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-white/10">
      <table className="w-full text-sm">
        <thead className="bg-white/5 text-left text-gray-300">
          <tr>
            <th className="p-3 font-medium">Function</th>
            <th className="p-3 font-medium">What it can do</th>
            <th className="p-3 font-medium">Gate</th>
            <th className="p-3 font-medium">Touches funds</th>
          </tr>
        </thead>
        <tbody>
          {powers.map((p) => (
            <tr key={`${p.file}:${p.line}:${p.function}`} className="border-t border-white/5">
              <td className="p-3 whitespace-nowrap font-mono text-[13px]">{p.function}</td>
              <td className="p-3 text-gray-200">
                {p.capability}
                {p.confidence === "low" && (
                  <span className="ml-2 text-[11px] text-gray-500">read as a guess</span>
                )}
              </td>
              <td className="p-3 font-mono text-[12px] text-gray-400">{p.modifiers.join(", ")}</td>
              <td className="p-3">
                {p.can_move_funds ? (
                  <span className="rounded bg-red-500/15 px-2 py-0.5 text-[12px] text-red-300">yes</span>
                ) : (
                  <span className="text-[12px] text-gray-500">no</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="border-t border-white/5 p-3 text-[11px] text-gray-500">
        These are the functions a privileged caller can reach. A yes in the last column means the
        function can move or freeze value that is not theirs.
      </p>
    </div>
  );
}
