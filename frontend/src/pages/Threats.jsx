import { useEffect, useState } from "react";
import { api } from "../lib/api";

export default function Threats() {
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.get("/alerts").then((r) => setAlerts(r.data || []));
  }, []);

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Threats</h1>
      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4">
        <h2 className="text-lg font-semibold text-slate-100 mb-3">Live Threats</h2>
        <div className="space-y-2">
          {alerts.length === 0 && <p className="text-sm text-slate-400">No active SOC alerts.</p>}
          {alerts.map((a, idx) => (
            <button
              key={`${a.type}-${idx}`}
              type="button"
              onClick={() => setSelected(a)}
              className={`w-full text-left rounded-xl border p-3 transition cursor-pointer ${
                (a.severity || "").toUpperCase() === "CRITICAL"
                  ? "border-rose-500/50 bg-rose-500/10 shadow-[0_0_22px_rgba(244,63,94,0.16)]"
                  : "border-slate-800 bg-slate-900/70 hover:border-cyan-500/60"
              }`}
            >
              <div className="flex justify-between items-center">
                <p className="text-sm font-semibold text-slate-100">{a.type}</p>
                <p className="text-xs text-slate-400">{new Date(a.timestamp).toLocaleString()}</p>
              </div>
              <p className="text-xs text-slate-300 mt-1">{a.message}</p>
            </button>
          ))}
        </div>
      </section>

      {selected && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-xl rounded-2xl border border-slate-700 bg-slate-900 p-5">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-semibold text-slate-100">Threat Details</h3>
              <button onClick={() => setSelected(null)} className="text-slate-300 hover:text-white">Close</button>
            </div>
            <p className="text-sm text-slate-300 mt-3">Type: <span className="text-cyan-300">{selected.type}</span></p>
            <p className="text-sm text-slate-300 mt-1">Severity: <span className="text-rose-300">{selected.severity}</span></p>
            <p className="text-sm text-slate-300 mt-1">Message: {selected.message}</p>
            <p className="text-xs text-slate-500 mt-2">{new Date(selected.timestamp).toLocaleString()}</p>
          </div>
        </div>
      )}
    </div>
  );
}
