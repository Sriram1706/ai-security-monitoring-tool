export default function ActionPanel({ onRefresh, onSeed, canSeed }) {
  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">Action Panel</h2>
      <div className="flex flex-wrap gap-2">
        <button onClick={onRefresh} className="bg-slate-700 hover:bg-slate-600 rounded px-3 py-2 text-sm font-semibold">
          Refresh Intelligence
        </button>
        {canSeed && (
          <button onClick={onSeed} className="bg-cyan-600 hover:bg-cyan-500 rounded px-3 py-2 text-sm font-semibold">
            Run Sample Scans
          </button>
        )}
      </div>
    </section>
  );
}
