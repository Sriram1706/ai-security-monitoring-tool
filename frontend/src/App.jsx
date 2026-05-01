import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import DrilldownDrawer from "./components/DrilldownDrawer";
import SidebarNav from "./components/SidebarNav";
import Dashboard from "./pages/Dashboard";
import Requests from "./pages/Requests";
import Integrations from "./pages/Integrations";
import Visibility from "./pages/Visibility";
import SupplyChain from "./pages/SupplyChain";
import Posture from "./pages/Posture";
import Risks from "./pages/Risks";
import Reports from "./pages/Reports";
import AgenticRisks from "./pages/AgenticRisks";
import AIFirewall from "./pages/AIFirewall";
import DataSecurity from "./pages/DataSecurity";
import { api, ensureAuthToken, setToken } from "./lib/api";

const pathToKey = {
  "/": "dashboard",
  "/dashboard": "dashboard",
  "/requests": "requests",
  "/integrations": "integrations",
  "/visibility": "visibility",
  "/supply-chain": "supply-chain",
  "/posture": "posture",
  "/ai-firewall": "ai-firewall",
  "/data-security": "data-security",
  "/risks": "risks",
  "/agentic-risks": "agentic-risks",
  "/reports": "reports",
};

const keyToPath = {
  dashboard: "/dashboard",
  requests: "/requests",
  integrations: "/integrations",
  visibility: "/visibility",
  "supply-chain": "/supply-chain",
  posture: "/posture",
  "ai-firewall": "/ai-firewall",
  "data-security": "/data-security",
  risks: "/risks",
  "agentic-risks": "/agentic-risks",
  reports: "/reports",
};

export default function App() {
  const [email, setEmail] = useState("admin@ai-sec.local");
  const [password, setPassword] = useState("AdminPass123!");
  const [authError, setAuthError] = useState("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [globalFilters, setGlobalFilters] = useState({
    selectedRiskType: "",
    selectedProvider: "",
  });
  const [drawer, setDrawer] = useState({ open: false, title: "Investigation", rows: [] });
  const location = useLocation();
  const navigate = useNavigate();

  const active = pathToKey[location.pathname] || "dashboard";
  const onChange = (key) => navigate(keyToPath[key] || "/dashboard");

  useEffect(() => {
    const initAuth = async () => {
      const token = await ensureAuthToken();
      setIsAuthenticated(Boolean(token));
      const sessionError = localStorage.getItem("auth_error");
      if (sessionError) {
        setAuthError(sessionError);
        localStorage.removeItem("auth_error");
      }
      setAuthLoading(false);
    };
    initAuth();
  }, []);

  const login = async (e) => {
    e.preventDefault();
    setAuthError("");
    try {
      const { data } = await api.post("/auth/login", { email, password });
      setToken(data.access_token);
      setIsAuthenticated(true);
      navigate("/dashboard");
    } catch {
      setAuthError("Invalid credentials or backend unavailable.");
    }
  };

  return (
    <Routes>
      {authLoading && <Route path="*" element={<div className="min-h-screen flex items-center justify-center text-slate-300">Initializing secure session...</div>} />}
      {!isAuthenticated && <Route path="*" element={<Navigate to="/login" replace />} />}
      <Route
        path="/login"
        element={
          isAuthenticated ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <div className="min-h-screen flex items-center justify-center p-4">
              <form onSubmit={login} className="w-full max-w-md bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-3">
                <h1 className="text-2xl font-bold">AI Security Monitor</h1>
                <p className="text-slate-400 text-sm">Sign in to access dashboards.</p>
                <input className="w-full p-2 rounded bg-slate-800 border border-slate-700" value={email} onChange={(e) => setEmail(e.target.value)} />
                <input className="w-full p-2 rounded bg-slate-800 border border-slate-700" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                {authError && <p className="text-rose-400 text-sm">{authError}</p>}
                <button className="w-full bg-cyan-600 hover:bg-cyan-500 rounded p-2 font-semibold">Login</button>
              </form>
            </div>
          )
        }
      />
      <Route
        path="*"
        element={!isAuthenticated ? <Navigate to="/login" replace /> : (
          <div className="min-h-screen flex">
      <SidebarNav
        active={active}
        onChange={onChange}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((prev) => !prev)}
      />
      <main className="flex-1 overflow-x-hidden">
        <div className="px-5 pt-4 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400">Global Filters:</span>
          <span className="text-xs rounded-full border border-slate-700 px-3 py-1">
            risk_type: {globalFilters.selectedRiskType || "all"}
          </span>
          <span className="text-xs rounded-full border border-slate-700 px-3 py-1">
            provider: {globalFilters.selectedProvider || "all"}
          </span>
          {(globalFilters.selectedRiskType || globalFilters.selectedProvider) && (
            <button
              type="button"
              onClick={() => setGlobalFilters({ selectedRiskType: "", selectedProvider: "" })}
              className="text-xs rounded-full border border-slate-700 px-3 py-1 hover:border-cyan-500/60"
            >
              Clear
            </button>
          )}
        </div>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard role="admin" globalFilters={globalFilters} setGlobalFilters={setGlobalFilters} onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="/requests" element={<Requests />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/visibility" element={<Visibility globalFilters={globalFilters} setGlobalFilters={setGlobalFilters} onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="/supply-chain" element={<SupplyChain onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="/posture" element={<Posture globalFilters={globalFilters} setGlobalFilters={setGlobalFilters} onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="/ai-firewall" element={<AIFirewall />} />
          <Route path="/data-security" element={<DataSecurity />} />
          <Route path="/risks" element={<Risks globalFilters={globalFilters} setGlobalFilters={setGlobalFilters} onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="/agentic-risks" element={<AgenticRisks />} />
          <Route path="/vulnerability-findings" element={<Navigate to="/supply-chain" replace />} />
          <Route path="/reports" element={<Reports globalFilters={globalFilters} setGlobalFilters={setGlobalFilters} onOpenDrilldown={(title, rows) => setDrawer({ open: true, title, rows })} />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>
      <DrilldownDrawer
        open={drawer.open}
        title={drawer.title}
        rows={drawer.rows}
        onClose={() => setDrawer({ open: false, title: "Investigation", rows: [] })}
      />
          </div>
        )}
      />
    </Routes>
  );
}
