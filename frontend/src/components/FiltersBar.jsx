export default function FiltersBar({
  filters,
  onChange,
  onApply,
  riskTypeOptions = [],
  severityOptions = [],
  providerOptions = [],
}) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-5 gap-3 bg-slate-900/70 border border-slate-800 rounded-xl p-4">
      <select
        className="bg-slate-800 border border-slate-700 rounded p-2"
        value={filters.risk_type}
        onChange={(e) => onChange({ ...filters, risk_type: e.target.value })}
      >
        <option value="">All Risk Types</option>
        {riskTypeOptions.map((opt) => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
      <select
        className="bg-slate-800 border border-slate-700 rounded p-2"
        value={filters.severity}
        onChange={(e) => onChange({ ...filters, severity: e.target.value })}
      >
        <option value="">All Severities</option>
        {severityOptions.map((opt) => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
      <select
        className="bg-slate-800 border border-slate-700 rounded p-2"
        value={filters.provider}
        onChange={(e) => onChange({ ...filters, provider: e.target.value })}
      >
        <option value="">All Providers</option>
        {providerOptions.map((opt) => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
      <input
        type="datetime-local"
        className="bg-slate-800 border border-slate-700 rounded p-2"
        value={filters.start_time}
        onChange={(e) => onChange({ ...filters, start_time: e.target.value })}
      />
      <button onClick={onApply} className="bg-cyan-600 hover:bg-cyan-500 rounded p-2 font-semibold">
        Apply Filters
      </button>
    </div>
  );
}
