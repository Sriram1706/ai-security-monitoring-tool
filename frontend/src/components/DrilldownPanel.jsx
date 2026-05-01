export default function DrilldownPanel({ title, rows = [] }) {
  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">{title}</h2>
      <div className="space-y-2 max-h-72 overflow-auto">
        {rows.length === 0 && <p className="text-sm text-slate-400">No records for this selection.</p>}
        {rows.map((row) => (
          <div key={row.id} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <p className="text-sm text-slate-100">{(row.prompt || "").slice(0, 180)}{(row.prompt || "").length > 180 ? "..." : ""}</p>
            <div className="flex justify-between mt-1 text-xs">
              <span className="text-cyan-300">{row.findings?.[0]?.risk_type || "none"}</span>
              <span className="text-slate-400">{new Date(row.created_at).toLocaleString()}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
