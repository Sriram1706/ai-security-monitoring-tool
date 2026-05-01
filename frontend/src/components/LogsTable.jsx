import SeverityBadge from "./SeverityBadge";

export default function LogsTable({ rows }) {
  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 overflow-auto">
      <h2 className="text-lg font-semibold mb-3">Scanned Prompts & Responses</h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-slate-300 border-b border-slate-700">
            <th className="py-2">Time</th>
            <th>Provider</th>
            <th>Prompt</th>
            <th>Risk</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-slate-800 align-top">
              <td className="py-2 pr-2">{new Date(r.created_at).toLocaleString()}</td>
              <td className="pr-2">{r.provider}</td>
              <td className="pr-2 max-w-lg truncate">{r.prompt}</td>
              <td className="pr-2">{r.risk_score}</td>
              <td><SeverityBadge severity={r.severity} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
