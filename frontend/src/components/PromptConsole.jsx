import { useState } from "react";

const scoreClass = (score) => {
  if (score >= 80) return "text-rose-300";
  if (score >= 60) return "text-orange-300";
  if (score >= 30) return "text-amber-300";
  return "text-emerald-300";
};

export default function PromptConsole({ onSubmitPrompt, busy, result }) {
  const [prompt, setPrompt] = useState("");
  const [bulkPrompts, setBulkPrompts] = useState("");

  const submit = async (e) => {
    if (e?.preventDefault) e.preventDefault();
    if (!prompt.trim()) return;
    await onSubmitPrompt(prompt);
    setPrompt("");
  };

  const submitBulk = async (e) => {
    if (e?.preventDefault) e.preventDefault();
    if (!bulkPrompts.trim()) return;
    if (typeof onSubmitPrompt !== "function") return;
    if (typeof window !== "undefined" && !window.confirm("Run bulk prompts now?")) return;
    await onSubmitPrompt(bulkPrompts, true);
    setBulkPrompts("");
  };

  return (
    <section className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
      <h2 className="text-lg font-semibold text-slate-100 mb-3">Secure Prompt Console</h2>
      <form onSubmit={submit} className="space-y-3">
        <textarea
          className="w-full min-h-28 rounded-lg bg-slate-900 border border-slate-700 p-3 text-slate-100"
          placeholder="Type a prompt to process securely..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
        <button
          type="submit"
          disabled={busy}
          onClick={submit}
          className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded px-4 py-2 font-semibold"
        >
          {busy ? "Processing..." : "Send Prompt"}
        </button>
        {busy && <p className="text-sm text-cyan-300">Scanning...</p>}
      </form>
      <div className="mt-4 border-t border-slate-800 pt-4 space-y-3">
        <p className="text-sm text-slate-300">Bulk Test Runner (paste one prompt per line or CSV rows)</p>
        <textarea
          className="w-full min-h-28 rounded-lg bg-slate-900 border border-slate-700 p-3 text-slate-100"
          placeholder={"Prompt 1\nPrompt 2\nPrompt 3"}
          value={bulkPrompts}
          onChange={(e) => setBulkPrompts(e.target.value)}
        />
        <button
          type="button"
          disabled={busy}
          onClick={submitBulk}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded px-4 py-2 font-semibold"
        >
          {busy ? "Running Bulk Tests..." : "Run Bulk Test Runner"}
        </button>
      </div>
      {result && (
        <div className="mt-4 border border-slate-800 bg-slate-900 rounded-lg p-3 space-y-2">
          <div className="flex flex-wrap gap-3 text-xs">
            <span className={`font-semibold ${scoreClass(result?.risk_score ?? 0)}`}>Risk Score: {result?.risk_score ?? 0}</span>
            <span className="text-cyan-300">Risk Type: {result?.risk_type || "none"}</span>
            <span className="text-slate-300">Severity: {result?.severity || "LOW"}</span>
            <span className={result?.blocked ? "text-rose-300" : "text-emerald-300"}>
              Action: {result?.blocked ? "Blocked" : "Allowed"}
            </span>
            <span className={result.status === "BLOCKED" ? "text-rose-300" : result.status === "WARNING" ? "text-amber-300" : "text-emerald-300"}>
              Status: {result?.status || (result?.blocked ? "BLOCKED" : "SAFE")}
            </span>
          </div>
          <div className="text-sm text-slate-200 whitespace-pre-wrap">
            {result?.blocked ? (result?.response || "Blocked due to high risk") : (result?.response || "No LLM response returned")}
          </div>
        </div>
      )}
      {result && (
        <div className="mt-4 p-4 bg-gray-800 rounded text-white">
          <h3 className="font-semibold mb-2">Scan Result</h3>
          <p><b>Status:</b> {result?.status}</p>
          <p><b>Risk Score:</b> {result?.risk_score}</p>
          <p><b>Risk Type:</b> {result?.risk_type}</p>
          <p><b>Severity:</b> {result?.severity}</p>
          <p><b>Message:</b> {result?.response}</p>
        </div>
      )}
    </section>
  );
}
