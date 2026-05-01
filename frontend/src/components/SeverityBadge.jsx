const styles = {
  low: "bg-emerald-600/20 text-emerald-300 border-emerald-500/40",
  medium: "bg-amber-600/20 text-amber-300 border-amber-500/40",
  high: "bg-orange-600/20 text-orange-300 border-orange-500/40",
  critical: "bg-rose-600/20 text-rose-300 border-rose-500/40",
};

export default function SeverityBadge({ severity }) {
  const key = (severity || "low").toLowerCase();
  return (
    <span className={`px-2 py-1 rounded border text-xs font-semibold uppercase tracking-wide ${styles[key] || styles.low}`}>
      {severity}
    </span>
  );
}
