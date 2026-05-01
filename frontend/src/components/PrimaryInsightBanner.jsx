export default function PrimaryInsightBanner({ message, level = "warning" }) {
  const style = level === "critical"
    ? "border-rose-500/50 bg-rose-500/10 shadow-[0_0_30px_rgba(244,63,94,0.18)]"
    : level === "safe"
      ? "border-emerald-500/40 bg-emerald-500/10"
      : "border-amber-500/40 bg-amber-500/10";

  return (
    <section className={`rounded-xl border p-4 ${style}`}>
      <h2 className="text-lg font-semibold text-slate-100">Primary Insight</h2>
      <p className="text-sm text-slate-200 mt-1">{message}</p>
    </section>
  );
}
