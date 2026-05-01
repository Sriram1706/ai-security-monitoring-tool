const items = [
  { key: "dashboard", label: "Dashboard", icon: "grid" },
  { key: "requests", label: "Requests", icon: "list" },
  { key: "integrations", label: "Integrations", icon: "link" },
  { key: "supply-chain", label: "Vulnerability Findings", icon: "chain" },
  { key: "posture", label: "Posture", icon: "shield" },
  { key: "ai-firewall", label: "AI Firewall", icon: "firewall" },
  { key: "data-security", label: "Data Security", icon: "lock" },
  { key: "agentic-risks", label: "Agentic AI Risks", icon: "agent" },
  { key: "reports", label: "Reports", icon: "doc" },
];

function Icon({ name }) {
  if (name === "grid") {
    return <span className="text-xs font-bold">▦</span>;
  }
  if (name === "eye") {
    return <span className="text-xs font-bold">◉</span>;
  }
  if (name === "shield") {
    return <span className="text-xs font-bold">⬢</span>;
  }
  if (name === "alert") {
    return <span className="text-xs font-bold">▲</span>;
  }
  if (name === "list") {
    return <span className="text-xs font-bold">☰</span>;
  }
  if (name === "link") {
    return <span className="text-xs font-bold">⛓</span>;
  }
  if (name === "chain") {
    return <span className="text-xs font-bold">⛓</span>;
  }
  if (name === "agent") {
    return <span className="text-xs font-bold">◎</span>;
  }
  if (name === "firewall") {
    return <span className="text-xs font-bold">⛨</span>;
  }
  if (name === "lock") {
    return <span className="text-xs font-bold">⌁</span>;
  }
  return <span className="text-xs font-bold">▤</span>;
}

export default function SidebarNav({ active, onChange, collapsed, onToggle }) {
  return (
    <aside
      className={`h-screen sticky top-0 border-r border-slate-800/80 bg-white/5 backdrop-blur-xl transition-all duration-500 ease-in-out ${
        collapsed ? "w-20" : "w-64"
      }`}
    >
      <div className="h-full flex flex-col p-3">
        <button
          type="button"
          onClick={onToggle}
          className="mb-4 rounded-xl border border-slate-700 bg-slate-900/60 px-3 py-2 text-slate-200 hover:border-cyan-500/60 transition-all duration-300"
        >
          {collapsed ? ">>" : "<< Collapse"}
        </button>

        <nav className="space-y-1">
          {items.map((item) => {
            const isActive = active === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => onChange(item.key)}
                className={`w-full rounded-xl px-3 py-2.5 flex items-center gap-3 text-left transition-all duration-300 cursor-pointer ${
                  isActive
                    ? "bg-cyan-500/15 border border-cyan-500/50 text-cyan-200 shadow-[0_0_22px_rgba(56,189,248,0.22)] translate-x-0.5"
                    : "border border-transparent hover:border-slate-700 text-slate-300 hover:text-slate-100 hover:bg-slate-900/40"
                }`}
                title={item.label}
              >
                <span className={`w-6 h-6 rounded-lg border flex items-center justify-center transition-all duration-300 ${
                  isActive ? "border-cyan-400/60 bg-cyan-500/15 text-cyan-200" : "border-slate-700 bg-slate-900/70 text-slate-300"
                }`}>
                  <Icon name={item.icon} />
                </span>
                <span className={`text-sm font-medium transition-all duration-300 ${collapsed ? "opacity-0 w-0 overflow-hidden" : "opacity-100 w-auto"}`}>
                  {item.label}
                </span>
              </button>
            );
          })}
        </nav>

        <div className="mt-auto rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 pulse-slow">
          <div className="flex items-center gap-2 text-xs text-emerald-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 blink-dot" />
            {!collapsed && "LIVE monitoring"}
          </div>
        </div>
      </div>
    </aside>
  );
}
