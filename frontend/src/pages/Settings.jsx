import { useState } from "react";

export default function Settings() {
  const [refresh, setRefresh] = useState("5s");
  const [theme, setTheme] = useState("dark");

  return (
    <div className="space-y-4 fade-in">
      <h1 className="text-2xl font-bold text-slate-100">Settings</h1>
      <section className="rounded-2xl border border-slate-800 bg-white/5 backdrop-blur-xl p-4 space-y-3">
        <div>
          <p className="text-sm text-slate-300 mb-1">Refresh Interval</p>
          <select value={refresh} onChange={(e) => setRefresh(e.target.value)} className="rounded-xl bg-slate-900/70 border border-slate-700 px-3 py-2">
            <option>5s</option>
            <option>10s</option>
            <option>30s</option>
          </select>
        </div>
        <div>
          <p className="text-sm text-slate-300 mb-1">Theme</p>
          <select value={theme} onChange={(e) => setTheme(e.target.value)} className="rounded-xl bg-slate-900/70 border border-slate-700 px-3 py-2">
            <option value="dark">Dark Cybersecurity</option>
          </select>
        </div>
        <p className="text-xs text-slate-500">Settings are UI-scoped and can be wired to backend config later.</p>
      </section>
    </div>
  );
}
