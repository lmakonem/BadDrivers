"use client";

import { useState, useEffect, useCallback } from "react";
import { apiFetchJSON } from "@/lib/fetch";

// ── Types ─────────────────────────────────────────────────────────────────────

interface CredRecord {
  email: string;
  username?: string;
  domain: string;
  password_type: string;
  password_length?: string;
  source_name: string;
  breach_date?: string;
  severity: string;
  country?: string;
  vip_match?: string;
}

interface CredData {
  total: number;
  plaintext_count: number;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
  by_type: Record<string, number>;
  by_domain: Record<string, number>;
  domains_checked: string[];
  records: CredRecord[];
}

interface IocRecord {
  indicator: string;
  indicator_type: string;
  threat_type: string;
  source: string;
  risk_score: string | number;
  tags?: string;
  country_code?: string;
}

interface IntelData {
  total: number;
  by_threat_type: Record<string, number>;
  by_source: Record<string, number>;
  by_ioc_type: Record<string, number>;
  bases_searched: string[];
  records: IocRecord[];
}

interface BrandMonitor {
  id: string;
  client_id?: number;
  brand_name: string;
  primary_keyword: string;
  domains: string[];
  keywords: string[];
  industry?: string;
  country_code?: string;
  active: boolean;
  last_scan_at: string | null;
  typosquat_count: number;
}

interface BrandAlert {
  id: string;
  brand_id: string;
  client_id?: number;
  brand_name?: string;
  country_code?: string;
  industry?: string;
  alert_type: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  domain?: string;
  similarity?: number;
  details?: Record<string, unknown>;
  detected_at: string;
  acknowledged: boolean;
}

interface Stats {
  total_monitors: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  total_typosquats: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fmtDate = (d: string | null | undefined) => {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
};
const timeAgo = (d: string | null | undefined) => {
  if (!d) return "Never";
  const h = Math.floor((Date.now() - new Date(d).getTime()) / 3600000);
  if (h < 1) return `${Math.floor((Date.now() - new Date(d).getTime()) / 60000)}m ago`;
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const sevBadge = (s: string) => ({
  critical: "text-red-300 bg-red-900/40 border-red-700/50",
  high:     "text-orange-300 bg-orange-900/40 border-orange-700/50",
  medium:   "text-yellow-300 bg-yellow-900/40 border-yellow-700/50",
  low:      "text-slate-300 bg-slate-700/40 border-slate-600",
}[s] ?? "text-slate-300 bg-slate-700/40 border-slate-600");

const sevDot = (s: string) => ({
  critical: "bg-red-400",
  high:     "bg-orange-400",
  medium:   "bg-yellow-400",
  low:      "bg-slate-400",
}[s] ?? "bg-slate-400");

const ALERT_TYPE_LABEL: Record<string, string> = {
  typosquat_detected:   "Typosquat",
  domain_registered:    "Domain Squatting",
  phishing_detected:    "Phishing",
  ssl_certificate:      "Cert Transparency",
  brand_mention:        "Dark Web",
  social_impersonation: "Social Media",
  credential_leak:      "Credential Leak",
  ti_hit:               "Threat Intel",
  ioc_match:            "IOC Match",
};

const ALERT_TYPE_ICON: Record<string, string> = {
  typosquat_detected:   "🔡",
  domain_registered:    "🌐",
  phishing_detected:    "🎣",
  ssl_certificate:      "🔐",
  brand_mention:        "🕳",
  social_impersonation: "📱",
  credential_leak:      "🔑",
  ti_hit:               "🎯",
  ioc_match:            "🎯",
};

const industryIcon = (ind?: string) =>
  (ind ?? "").toLowerCase().includes("bank") ? "🏦" : "📡";

// ── Main component ────────────────────────────────────────────────────────────

export default function BrandPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [monitors, setMonitors] = useState<BrandMonitor[]>([]);
  const [allAlerts, setAllAlerts] = useState<BrandAlert[]>([]);
  const [loading, setLoading] = useState(true);

  // Client navigation
  const [selectedMonitor, setSelectedMonitor] = useState<BrandMonitor | null>(null);
  const [clientAlerts, setClientAlerts] = useState<BrandAlert[]>([]);
  const [clientAlertsTotal, setClientAlertsTotal] = useState(0);
  const [loadingClient, setLoadingClient] = useState(false);
  const [clientAlertPage, setClientAlertPage] = useState(0);
  const CLIENT_LIMIT = 50;

  // Client detail tab
  const [clientTab, setClientTab] = useState<"overview" | "typosquats" | "certs" | "credentials" | "intel">("overview");

  // Credential leaks
  const [credData, setCredData] = useState<CredData | null>(null);
  const [loadingCred, setLoadingCred] = useState(false);
  const [credPage, setCredPage] = useState(0);
  const [credSev, setCredSev] = useState("all");
  const CRED_LIMIT = 50;

  // Threat intel
  const [intelData, setIntelData] = useState<IntelData | null>(null);
  const [loadingIntel, setLoadingIntel] = useState(false);

  // Global filters
  const [sevFilter, setSevFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [monSearch, setMonSearch] = useState("");

  // Alert detail drawer
  const [selectedAlert, setSelectedAlert] = useState<BrandAlert | null>(null);

  // Add monitor modal
  const [showAdd, setShowAdd] = useState(false);
  const [addForm, setAddForm] = useState({ name: "", domain: "", keywords: "" });
  const [adding, setAdding] = useState(false);

  // ── Fetch ──────────────────────────────────────────────────────────────────

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, m, a] = await Promise.all([
        apiFetchJSON("/api/v1/brand/stats") as Promise<Stats | null>,
        apiFetchJSON("/api/v1/brand/monitors?limit=200") as Promise<{ total: number; brands: BrandMonitor[] } | null>,
        apiFetchJSON("/api/v1/brand/alerts?limit=100") as Promise<{ total: number; alerts: BrandAlert[] } | null>,
      ]);
      if (s) setStats(s);
      const mons = m?.brands ?? [];
      setMonitors(mons);
      setAllAlerts(a?.alerts ?? []);
      // Auto-select first monitor that has alerts
      if (!selectedMonitor && mons.length > 0) {
        const first = mons.find(m => m.typosquat_count > 0) ?? mons[0];
        setSelectedMonitor(first);
      }
    } finally {
      setLoading(false);
    }
  }, [selectedMonitor]);

  const fetchCredentials = useCallback(async (monitorId: string, page = 0, sev = "all") => {
    setLoadingCred(true);
    try {
      const params = new URLSearchParams({ limit: String(CRED_LIMIT), offset: String(page * CRED_LIMIT) });
      if (sev !== "all") params.set("severity", sev);
      const d = await apiFetchJSON(`/api/v1/brand/monitors/${monitorId}/credentials?${params}`) as CredData | null;
      setCredData(d);
      setCredPage(page);
    } finally {
      setLoadingCred(false);
    }
  }, []);

  const fetchIntel = useCallback(async (monitorId: string) => {
    setLoadingIntel(true);
    try {
      const d = await apiFetchJSON(`/api/v1/brand/monitors/${monitorId}/intel?limit=100`) as IntelData | null;
      setIntelData(d);
    } finally {
      setLoadingIntel(false);
    }
  }, []);

  const fetchClientAlerts = useCallback(async (monitor: BrandMonitor, page = 0, sev = "all", type = "all") => {
    setLoadingClient(true);
    try {
      const params = new URLSearchParams({ limit: String(CLIENT_LIMIT), offset: String(page * CLIENT_LIMIT) });
      params.set("brand_id", monitor.id);
      if (sev !== "all") params.set("severity", sev);
      if (type !== "all") params.set("alert_type", type);
      const d = await apiFetchJSON(`/api/v1/brand/alerts?${params}`) as { total: number; alerts: BrandAlert[] } | null;
      setClientAlerts(d?.alerts ?? []);
      setClientAlertsTotal(d?.total ?? 0);
      setClientAlertPage(page);
    } finally {
      setLoadingClient(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, []);

  useEffect(() => {
    if (selectedMonitor) {
      setClientTab("overview");
      setClientAlertPage(0);
      setSevFilter("all");
      setTypeFilter("all");
      setCredData(null);
      setIntelData(null);
      setCredPage(0);
      setCredSev("all");
      fetchClientAlerts(selectedMonitor, 0);
    }
  }, [selectedMonitor]);

  // Fetch cred/intel data when tab is selected
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!selectedMonitor) return;
    if (clientTab === "credentials" && !credData && !loadingCred) {
      fetchCredentials(selectedMonitor.id, 0);
    }
    if (clientTab === "intel" && !intelData && !loadingIntel) {
      fetchIntel(selectedMonitor.id);
    }
  }, [clientTab, selectedMonitor]); // eslint-disable-line

  // ── Actions ─────────────────────────────────────────────────────────────────

  const acknowledgeAlert = async (alertId: string) => {
    await apiFetchJSON(`/api/v1/brand/alerts/${alertId}/acknowledge`, { method: "POST" });
    setClientAlerts(prev => prev.map(a => a.id === alertId ? { ...a, acknowledged: true } : a));
    if (selectedAlert?.id === alertId) setSelectedAlert(a => a ? { ...a, acknowledged: true } : a);
  };

  const handleAddMonitor = async () => {
    if (!addForm.name.trim() || !addForm.domain.trim()) return;
    setAdding(true);
    try {
      await apiFetchJSON("/api/v1/brand/monitor", {
        method: "POST",
        body: JSON.stringify({
          brand_name: addForm.name.trim(),
          primary_domain: addForm.domain.trim(),
          keywords: addForm.keywords.split(",").map(k => k.trim()).filter(Boolean),
        }),
      });
      setShowAdd(false);
      setAddForm({ name: "", domain: "", keywords: "" });
      fetchAll();
    } finally {
      setAdding(false);
    }
  };

  // ── Derived data ───────────────────────────────────────────────────────────

  // Alerts grouped by type for the selected client
  const byType = clientAlerts.reduce((acc, a) => {
    acc[a.alert_type] = (acc[a.alert_type] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const bySev = clientAlerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Client alert tabs
  const typosquatAlerts = clientAlerts.filter(a => a.alert_type === "typosquat_detected" || a.alert_type === "domain_registered");
  const certAlerts      = clientAlerts.filter(a => a.alert_type === "ssl_certificate");
  const credAlerts      = clientAlerts.filter(a => a.alert_type === "credential_leak");
  const intelAlerts     = clientAlerts.filter(a => a.alert_type === "ti_hit" || a.alert_type === "ioc_match" || a.alert_type === "brand_mention");


  const filteredMons = monitors.filter(m => {
    if (!monSearch) return true;
    const q = monSearch.toLowerCase();
    return m.brand_name.toLowerCase().includes(q) || (m.country_code ?? "").toLowerCase().includes(q);
  });

  // Sort monitors: most threats first
  const sortedMons = [...filteredMons].sort((a, b) => b.typosquat_count - a.typosquat_count);

  const maxThreat = sortedMons[0]?.typosquat_count ?? 1;

  // ── Render helpers ─────────────────────────────────────────────────────────

  const AlertRow = ({ a }: { a: BrandAlert }) => (
    <tr
      onClick={() => setSelectedAlert(a)}
      className={`hover:bg-white/[0.025] cursor-pointer transition-colors group ${a.acknowledged ? "opacity-40" : ""}`}
    >
      <td className="px-4 py-2.5 w-24">
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${sevDot(a.severity)}`} />
          <span className={`text-xs font-semibold px-1.5 py-0 rounded border ${sevBadge(a.severity)}`}>
            {a.severity.toUpperCase()}
          </span>
        </div>
      </td>
      <td className="px-4 py-2.5 max-w-xs">
        <div className="text-sm text-white truncate font-medium">{a.title}</div>
        {a.domain && <div className="text-xs text-cyan-400 font-mono truncate mt-0.5">{a.domain}</div>}
      </td>
      <td className="px-4 py-2.5 hidden md:table-cell">
        <span className="text-xs text-slate-400 flex items-center gap-1 whitespace-nowrap">
          {ALERT_TYPE_ICON[a.alert_type] ?? "⚠"} {ALERT_TYPE_LABEL[a.alert_type] ?? a.alert_type}
        </span>
      </td>
      <td className="px-4 py-2.5 hidden lg:table-cell">
        {a.similarity ? (
          <div className="flex items-center gap-1.5">
            <div className="w-10 bg-white/10 rounded-full h-1.5">
              <div className={`h-1.5 rounded-full ${a.similarity >= 80 ? "bg-red-400" : "bg-orange-400"}`}
                style={{ width: `${a.similarity}%` }} />
            </div>
            <span className="text-xs text-slate-400">{a.similarity}%</span>
          </div>
        ) : <span className="text-slate-600 text-xs">—</span>}
      </td>
      <td className="px-4 py-2.5 text-xs text-slate-500 whitespace-nowrap hidden sm:table-cell">{timeAgo(a.detected_at)}</td>
      <td className="px-4 py-2.5 text-slate-600 group-hover:text-slate-300 text-sm transition-colors">›</td>
    </tr>
  );

  const AlertTable = ({ alerts, showEmpty = "No alerts in this category" }: { alerts: BrandAlert[]; showEmpty?: string }) => (
    <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="text-left text-xs text-slate-400 border-b border-[#1E2A3D] bg-[#0d1528] sticky top-0 z-10">
            <th className="px-4 py-2.5 font-medium">Severity</th>
            <th className="px-4 py-2.5 font-medium">Finding</th>
            <th className="px-4 py-2.5 font-medium hidden md:table-cell">Type</th>
            <th className="px-4 py-2.5 font-medium hidden lg:table-cell">Similarity</th>
            <th className="px-4 py-2.5 font-medium hidden sm:table-cell">When</th>
            <th className="px-4 py-2.5 w-6" />
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {alerts.length === 0 ? (
            <tr><td colSpan={6} className="py-10 text-center text-sm text-slate-500">{showEmpty}</td></tr>
          ) : (
            alerts.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4))
              .map(a => <AlertRow key={a.id} a={a} />)
          )}
        </tbody>
      </table>
    </div>
  );

  // ── Layout ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex bg-body-dark text-white" style={{ position: "absolute", inset: 0, overflow: "hidden" }}>

      {/* ── LEFT SIDEBAR: client list ── */}
      <div className="flex-shrink-0 flex flex-col bg-card-dark border-r border-[#1E2A3D]"
        style={{ width: "17rem", height: "100%", overflow: "hidden" }}>

        {/* Sidebar header */}
        <div className="flex-shrink-0 p-3 border-b border-[#1E2A3D] space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Brand Monitors</span>
            <button onClick={() => setShowAdd(true)}
              className="text-xs bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 px-2 py-1 rounded transition-colors flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add
            </button>
          </div>
          <input
            type="text" value={monSearch} onChange={e => setMonSearch(e.target.value)}
            placeholder="Search brands…"
            className="w-full bg-card-light border border-[#1E2A3D] rounded px-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-primary/50"
          />
          {/* Summary pills */}
          <div className="flex gap-1.5 flex-wrap">
            <span className="text-xs bg-white/10 text-slate-300 px-2 py-0.5 rounded">{sortedMons.length} brands</span>
            {stats && stats.critical_alerts > 0 && (
              <span className="text-xs bg-red-900/50 text-red-300 border border-red-700/40 px-2 py-0.5 rounded">{stats.critical_alerts} critical</span>
            )}
          </div>
        </div>

        {/* Client list */}
        <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
            </div>
          ) : sortedMons.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <div className="text-2xl mb-2 opacity-60">🛡️</div>
              <p className="text-xs text-slate-300 font-medium">No brands yet</p>
              <button onClick={() => setShowAdd(true)} className="mt-2 text-xs text-primary hover:text-primary-light font-medium">
                Add your first brand →
              </button>
            </div>
          ) : (
            sortedMons.map(m => {
              const isSelected = selectedMonitor?.id === m.id;
              const clientCritical = allAlerts.filter(a => a.brand_id === m.id && a.severity === "critical").length;
              return (
                <button key={m.id} onClick={() => setSelectedMonitor(m)}
                  className={`w-full text-left px-3 py-2.5 border-b border-[#1E2A3D]/60 transition-colors hover:bg-white/5 ${
                    isSelected ? "bg-primary/10 border-l-2 border-l-primary" : "border-l-2 border-l-transparent"
                  }`}>
                  {/* Row 1: name + critical badge */}
                  <div className="flex items-center justify-between gap-1">
                    <span className="text-sm font-semibold text-white truncate leading-tight">{m.brand_name}</span>
                    {clientCritical > 0 && (
                      <span className="text-xs bg-red-900/60 text-red-300 border border-red-700/40 px-1.5 py-0 rounded font-mono flex-shrink-0">
                        {clientCritical}!
                      </span>
                    )}
                  </div>
                  {/* Row 2: country + industry */}
                  <div className="text-xs text-slate-500 mt-0.5">
                    {[m.country_code, m.industry].filter(Boolean).join(" · ")}
                  </div>
                  {/* Row 3: threat bar */}
                  <div className="flex items-center gap-2 mt-1.5">
                    <div className="flex-1 bg-white/10 rounded-full h-1">
                      <div className={`h-1 rounded-full ${m.typosquat_count > 20 ? "bg-red-500" : m.typosquat_count > 5 ? "bg-orange-500" : "bg-yellow-500"}`}
                        style={{ width: `${Math.max((m.typosquat_count / maxThreat) * 100, m.typosquat_count > 0 ? 6 : 0)}%` }} />
                    </div>
                    <span className={`text-xs flex-shrink-0 ${m.typosquat_count > 20 ? "text-red-400" : m.typosquat_count > 5 ? "text-orange-400" : m.typosquat_count > 0 ? "text-yellow-400" : "text-slate-600"}`}>
                      {m.typosquat_count}
                    </span>
                  </div>
                  {/* Row 4: domains */}
                  {m.domains?.length > 0 && (
                    <div className="text-xs text-slate-600 font-mono truncate mt-0.5">
                      {m.domains[0]}
                    </div>
                  )}
                </button>
              );
            })
          )}
        </div>

        {/* Sidebar footer: global stats */}
        {stats && (
          <div className="flex-shrink-0 border-t border-[#1E2A3D] p-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-slate-500">Total alerts</span>
              <span className="text-slate-300 font-mono">{(stats.total_alerts).toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-slate-500">Typosquats</span>
              <span className="text-yellow-400 font-mono">{stats.total_typosquats.toLocaleString()}</span>
            </div>
            <button onClick={() => { fetchAll(); if (selectedMonitor) fetchClientAlerts(selectedMonitor, 0); }}
              className="w-full text-xs bg-white/5 hover:bg-white/10 text-slate-300 border border-[#1E2A3D] rounded py-1.5 mt-1 transition-colors flex items-center justify-center gap-1">
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Refresh
            </button>
          </div>
        )}
      </div>

      {/* ── RIGHT: client detail pane ── */}
      <div className="flex flex-col" style={{ flex: 1, height: "100%", overflow: "hidden" }}>

        {!selectedMonitor ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center max-w-sm px-6">
              <div className="text-5xl mb-3 opacity-60">🛡️</div>
              <h2 className="text-lg font-display font-semibold text-white mb-1">Brand Protection</h2>
              <p className="text-sm text-slate-400 mb-5">
                Select a brand from the list to review typosquats, lookalike certificates, credential leaks, and threat-intel hits.
              </p>
              <button onClick={() => setShowAdd(true)}
                className="inline-flex items-center gap-2 bg-primary hover:bg-primary-hover text-body-dark text-sm font-semibold py-2 px-5 rounded-[10px] transition-colors">
                Add Brand Monitor
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Client header */}
            <div className="flex-shrink-0 bg-card-dark/60 border-b border-[#1E2A3D] px-6 py-4">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{industryIcon(selectedMonitor.industry)}</span>
                  <div>
                    <h1 className="text-lg font-bold text-white leading-tight">{selectedMonitor.brand_name}</h1>
                    <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                      <span className="text-xs text-slate-400">{selectedMonitor.country_code}</span>
                      {selectedMonitor.industry && <span className="text-xs text-slate-500">· {selectedMonitor.industry}</span>}
                      <span className="text-xs text-slate-600">· Last scan {timeAgo(selectedMonitor.last_scan_at)}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${selectedMonitor.active ? "text-green-300 bg-green-900/20 border-green-700/30" : "text-slate-400 bg-white/5 border-[#1E2A3D]"}`}>
                        {selectedMonitor.active ? "Active" : "Paused"}
                      </span>
                    </div>
                    {/* Official domains */}
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {(selectedMonitor.domains ?? []).slice(0,4).map(d => (
                        <a key={d} href={`https://${d}`} target="_blank" rel="noreferrer"
                          onClick={e => e.stopPropagation()}
                          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 bg-cyan-900/10 border border-cyan-700/20 px-1.5 py-0.5 rounded transition-colors">
                          {d} ↗
                        </a>
                      ))}
                    </div>
                  </div>
                </div>
                {/* Severity summary */}
                <div className="flex gap-2 flex-wrap flex-shrink-0">
                  {(["critical","high","medium","low"] as const).map(s => {
                    const cnt = bySev[s] ?? 0;
                    if (!cnt) return null;
                    return (
                      <button key={s}
                        onClick={() => { setSevFilter(s); setClientTab("overview"); fetchClientAlerts(selectedMonitor, 0, s, typeFilter); }}
                        className={`flex flex-col items-center px-3 py-1.5 rounded-lg border transition-colors hover:opacity-80 ${sevBadge(s)}`}>
                        <span className="text-lg font-bold leading-none">{cnt}</span>
                        <span className="text-xs capitalize">{s}</span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Client sub-tabs */}
              <div className="flex gap-1 mt-4 border-b border-[#1E2A3D] overflow-x-auto">
                {([
                  ["overview",    `Overview (${clientAlertsTotal})`],
                  ["typosquats",  `Typosquats (${typosquatAlerts.length})`],
                  ["certs",       `Cert Watch (${certAlerts.length})`],
                  ["credentials", `Credential Leaks${credData ? ` (${credData.total.toLocaleString()})` : credAlerts.length > 0 ? ` (${credAlerts.length})` : ""}`],
                  ["intel",       `Threat Intel${intelData ? ` (${intelData.total.toLocaleString()})` : intelAlerts.length > 0 ? ` (${intelAlerts.length})` : ""}`],
                ] as [typeof clientTab, string][]).map(([t, label]) => (
                  <button key={t} onClick={() => setClientTab(t)}
                    className={`px-3 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors flex-shrink-0 ${
                      clientTab === t ? "border-primary text-primary" : "border-transparent text-slate-400 hover:text-white"
                    }`}>
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Client detail body */}
            <div className="p-6 space-y-5" style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>

              {loadingClient ? (
                <div className="flex items-center gap-2 text-slate-400 text-sm py-12">
                  <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  Loading brand intelligence…
                </div>
              ) : (

                <>
                  {/* ── Overview ── */}
                  {clientTab === "overview" && (
                    <div className="space-y-5">
                      {/* Alert type breakdown */}
                      {Object.keys(byType).length > 0 ? (
                        <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] p-5">
                          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Threat Breakdown</h3>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
                            {(["critical","high","medium","low"] as const).map(s => {
                              const cnt = bySev[s] ?? 0;
                              return (
                                <button key={s}
                                  onClick={() => { setSevFilter(s); fetchClientAlerts(selectedMonitor, 0, s, "all"); }}
                                  className={`rounded-[14px] p-3 text-left border transition-all hover:opacity-80 ${
                                    s === "critical" ? "bg-red-900/15 border-red-700/30" :
                                    s === "high"     ? "bg-orange-900/15 border-orange-700/30" :
                                    s === "medium"   ? "bg-yellow-900/15 border-yellow-700/30" :
                                                       "bg-slate-700/25 border-slate-600/50"
                                  }`}>
                                  <div className={`text-2xl font-bold ${s === "critical" ? "text-red-300" : s === "high" ? "text-orange-300" : s === "medium" ? "text-yellow-300" : "text-slate-300"}`}>
                                    {cnt}
                                  </div>
                                  <div className="text-xs text-slate-400 capitalize mt-0.5">{s}</div>
                                  <div className="text-xs text-slate-600 mt-0.5">click to filter</div>
                                </button>
                              );
                            })}
                          </div>
                          <div className="space-y-2.5">
                            {Object.entries(byType).sort(([,a],[,b]) => b - a).map(([type, count]) => {
                              const total = Object.values(byType).reduce((s,v) => s+v, 0);
                              return (
                                <button key={type}
                                  onClick={() => { setTypeFilter(type); fetchClientAlerts(selectedMonitor, 0, "all", type); setClientTab("overview"); }}
                                  className="w-full flex items-center gap-3 text-left hover:opacity-80 transition-opacity group">
                                  <span className="w-8 text-center text-sm">{ALERT_TYPE_ICON[type] ?? "⚠"}</span>
                                  <span className="text-xs text-slate-400 w-36 flex-shrink-0 truncate">
                                    {ALERT_TYPE_LABEL[type] ?? type}
                                  </span>
                                  <div className="flex-1 bg-white/5 rounded-full h-2">
                                    <div className="h-2 bg-primary rounded-full transition-all"
                                      style={{ width: `${(count/total*100).toFixed(1)}%` }} />
                                  </div>
                                  <span className="text-xs text-slate-300 w-8 text-right flex-shrink-0">{count}</span>
                                  <span className="text-xs text-slate-600 group-hover:text-primary transition-colors">→</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      ) : (
                        <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] p-8 text-center">
                          <div className="text-3xl mb-2">✓</div>
                          <div className="text-sm text-slate-300 font-medium">No threats detected</div>
                          <div className="text-xs text-slate-500 mt-1">This brand has no active brand protection alerts</div>
                        </div>
                      )}

                      {/* Keywords being monitored */}
                      <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] p-4">
                        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Monitored Keywords</h3>
                        <div className="flex flex-wrap gap-1.5">
                          {(selectedMonitor.keywords ?? []).map(k => (
                            <span key={k} className="text-xs bg-primary/10 text-primary/80 border border-primary/20 px-2 py-0.5 rounded">{k}</span>
                          ))}
                          {(!selectedMonitor.keywords || selectedMonitor.keywords.length === 0) && (
                            <span className="text-xs text-slate-500">No keywords configured</span>
                          )}
                        </div>
                      </div>

                      {/* Recent alerts */}
                      {clientAlerts.length > 0 && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">All Findings ({clientAlertsTotal})</h3>
                            <div className="flex gap-2">
                              <select value={sevFilter}
                                onChange={e => { setSevFilter(e.target.value); fetchClientAlerts(selectedMonitor, 0, e.target.value, typeFilter); }}
                                className="bg-card-light border border-[#1E2A3D] rounded px-2 py-1 text-xs text-white focus:outline-none">
                                <option value="all">All severities</option>
                                {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
                              </select>
                              <select value={typeFilter}
                                onChange={e => { setTypeFilter(e.target.value); fetchClientAlerts(selectedMonitor, 0, sevFilter, e.target.value); }}
                                className="bg-card-light border border-[#1E2A3D] rounded px-2 py-1 text-xs text-white focus:outline-none">
                                <option value="all">All types</option>
                                {Object.entries(ALERT_TYPE_LABEL).map(([v,l]) => <option key={v} value={v}>{l}</option>)}
                              </select>
                            </div>
                          </div>
                          <AlertTable alerts={clientAlerts} />
                          {clientAlertsTotal > CLIENT_LIMIT && (
                            <div className="flex items-center justify-between mt-3">
                              <button disabled={clientAlertPage === 0}
                                onClick={() => fetchClientAlerts(selectedMonitor, clientAlertPage - 1, sevFilter, typeFilter)}
                                className="text-xs text-slate-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-[#1E2A3D] rounded">← Prev</button>
                              <span className="text-xs text-slate-400">
                                {clientAlertPage * CLIENT_LIMIT + 1}–{Math.min((clientAlertPage+1)*CLIENT_LIMIT, clientAlertsTotal)} of {clientAlertsTotal}
                              </span>
                              <button disabled={(clientAlertPage+1)*CLIENT_LIMIT >= clientAlertsTotal}
                                onClick={() => fetchClientAlerts(selectedMonitor, clientAlertPage + 1, sevFilter, typeFilter)}
                                className="text-xs text-slate-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-[#1E2A3D] rounded">Next →</button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* ── Typosquats tab ── */}
                  {clientTab === "typosquats" && (
                    <div className="space-y-3">
                      <p className="text-sm text-slate-400">
                        Registered domains detected impersonating <strong className="text-white">{selectedMonitor.brand_name}</strong> via typosquatting, domain squatting, or TLD abuse.
                      </p>
                      <AlertTable alerts={typosquatAlerts} showEmpty="No typosquat or domain squatting detected" />
                    </div>
                  )}

                  {/* ── Cert watch tab ── */}
                  {clientTab === "certs" && (
                    <div className="space-y-3">
                      <p className="text-sm text-slate-400">
                        SSL certificates issued for lookalike domains found in certificate transparency logs.
                      </p>
                      <AlertTable alerts={certAlerts} showEmpty="No suspicious SSL certificates detected in CT logs" />
                    </div>
                  )}

                  {/* ── Credential leaks tab ── */}
                  {clientTab === "credentials" && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <p className="text-sm text-slate-400">
                          Leaked credentials matching <strong className="text-white">{selectedMonitor.brand_name}</strong> domains in platform breach databases.
                        </p>
                        {credData && (
                          <button onClick={() => fetchCredentials(selectedMonitor.id, 0, credSev)}
                            className="text-xs text-slate-400 hover:text-white border border-[#1E2A3D] rounded px-2.5 py-1 transition-colors">↻ Refresh</button>
                        )}
                      </div>

                      {loadingCred ? (
                        <div className="flex items-center gap-2 text-slate-400 text-sm py-8">
                          <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                          Searching breach databases…
                        </div>
                      ) : !credData ? null : credData.total === 0 ? (
                        <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] p-8 text-center">
                          <div className="text-3xl mb-2">✓</div>
                          <div className="text-sm text-slate-300 font-medium">No credential leaks found</div>
                          <div className="text-xs text-slate-500 mt-1">Domains checked: {credData.domains_checked.join(", ")}</div>
                        </div>
                      ) : (
                        <>
                          {/* Stats bar */}
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            <div className="bg-red-900/20 border border-red-700/30 rounded-[14px] p-3 text-center">
                              <div className="text-2xl font-bold text-red-300">{credData.total.toLocaleString()}</div>
                              <div className="text-xs text-slate-400 mt-0.5">Total Records</div>
                            </div>
                            <div className={`${credData.plaintext_count > 0 ? "bg-red-900/30 border-red-600/50" : "bg-white/5 border-[#1E2A3D]"} border rounded-[14px] p-3 text-center`}>
                              <div className={`text-2xl font-bold ${credData.plaintext_count > 0 ? "text-red-200" : "text-slate-400"}`}>{credData.plaintext_count.toLocaleString()}</div>
                              <div className="text-xs text-slate-400 mt-0.5">Plaintext Passwords</div>
                            </div>
                            <div className="bg-white/5 border border-[#1E2A3D] rounded-[14px] p-3">
                              <div className="text-xs text-slate-400 mb-1.5">By Source</div>
                              {Object.entries(credData.by_source).slice(0,3).map(([src, cnt]) => (
                                <div key={src} className="flex justify-between text-xs">
                                  <span className="text-slate-300 truncate max-w-[120px]" title={src}>{src}</span>
                                  <span className="text-slate-400 ml-1 flex-shrink-0">{cnt.toLocaleString()}</span>
                                </div>
                              ))}
                            </div>
                            <div className="bg-white/5 border border-[#1E2A3D] rounded-[14px] p-3">
                              <div className="text-xs text-slate-400 mb-1.5">By Password Type</div>
                              {Object.entries(credData.by_type).slice(0,4).map(([type, cnt]) => (
                                <div key={type} className="flex justify-between text-xs">
                                  <span className={`${type === "plaintext" ? "text-red-300" : "text-slate-300"}`}>{type}</span>
                                  <span className="text-slate-400">{cnt.toLocaleString()}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Filters */}
                          <div className="flex gap-2 items-center">
                            <select value={credSev}
                              onChange={e => { setCredSev(e.target.value); fetchCredentials(selectedMonitor.id, 0, e.target.value); }}
                              className="bg-card-light border border-[#1E2A3D] rounded px-2.5 py-1.5 text-xs text-white focus:outline-none">
                              <option value="all">All severities</option>
                              {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
                            </select>
                            <span className="text-xs text-slate-500 ml-auto">
                              {credPage * CRED_LIMIT + 1}–{Math.min((credPage+1)*CRED_LIMIT, credData.total)} of {credData.total.toLocaleString()} records
                            </span>
                          </div>

                          {/* Records table */}
                          <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] overflow-hidden">
                            <table className="w-full text-sm">
                              <thead className="sticky top-0 z-10">
                                <tr className="text-left text-xs text-slate-400 border-b border-[#1E2A3D] bg-[#0d1528]">
                                  <th className="px-4 py-2.5 font-medium">Email / Username</th>
                                  <th className="px-4 py-2.5 font-medium">Domain</th>
                                  <th className="px-4 py-2.5 font-medium">Password Type</th>
                                  <th className="px-4 py-2.5 font-medium">Breach Source</th>
                                  <th className="px-4 py-2.5 font-medium">Breach Date</th>
                                  <th className="px-4 py-2.5 font-medium">Severity</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-white/5">
                                {credData.records.map((r, i) => (
                                  <tr key={i} className="hover:bg-white/[0.02]">
                                    <td className="px-4 py-2.5">
                                      <div className="text-xs font-mono text-cyan-300 truncate max-w-[200px]" title={r.email}>{r.email}</div>
                                      {r.username && r.username !== r.email?.split("@")[0] && (
                                        <div className="text-xs text-slate-500">{r.username}</div>
                                      )}
                                    </td>
                                    <td className="px-4 py-2.5 text-xs font-mono text-slate-300">{r.domain}</td>
                                    <td className="px-4 py-2.5">
                                      <span className={`text-xs px-1.5 py-0.5 rounded border ${
                                        r.password_type === "plaintext" ? "bg-red-900/40 text-red-300 border-red-700/40" :
                                        r.password_type === "md5"       ? "bg-orange-900/40 text-orange-300 border-orange-700/40" :
                                        "bg-white/5 text-slate-300 border-[#1E2A3D]"
                                      }`}>{r.password_type}{r.password_length ? ` (${r.password_length})` : ""}</span>
                                    </td>
                                    <td className="px-4 py-2.5 text-xs text-slate-400 max-w-[160px] truncate" title={r.source_name}>{r.source_name}</td>
                                    <td className="px-4 py-2.5 text-xs text-slate-500">{r.breach_date ? new Date(r.breach_date).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) : "—"}</td>
                                    <td className="px-4 py-2.5">
                                      <span className={`text-xs px-1.5 py-0.5 rounded border ${sevBadge(r.severity)}`}>{r.severity?.toUpperCase()}</span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>

                          {/* Pagination */}
                          {credData.total > CRED_LIMIT && (
                            <div className="flex items-center justify-between">
                              <button disabled={credPage === 0}
                                onClick={() => fetchCredentials(selectedMonitor.id, credPage - 1, credSev)}
                                className="text-xs text-slate-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-[#1E2A3D] rounded">← Prev</button>
                              <span className="text-xs text-slate-400">{credPage * CRED_LIMIT + 1}–{Math.min((credPage+1)*CRED_LIMIT, credData.total)} of {credData.total.toLocaleString()}</span>
                              <button disabled={(credPage+1)*CRED_LIMIT >= credData.total}
                                onClick={() => fetchCredentials(selectedMonitor.id, credPage + 1, credSev)}
                                className="text-xs text-slate-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-[#1E2A3D] rounded">Next →</button>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}

                  {/* ── Threat intel tab ── */}
                  {clientTab === "intel" && (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <p className="text-sm text-slate-400">
                          Live IOC feed matches for <strong className="text-white">{selectedMonitor.brand_name}</strong> domains and brand keywords.
                        </p>
                        {intelData && (
                          <button onClick={() => fetchIntel(selectedMonitor.id)}
                            className="text-xs text-slate-400 hover:text-white border border-[#1E2A3D] rounded px-2.5 py-1 transition-colors">↻ Refresh</button>
                        )}
                      </div>

                      {loadingIntel ? (
                        <div className="flex items-center gap-2 text-slate-400 text-sm py-8">
                          <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                          Querying threat intelligence feed…
                        </div>
                      ) : !intelData ? null : intelData.total === 0 ? (
                        <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] p-8 text-center">
                          <div className="text-3xl mb-2">✓</div>
                          <div className="text-sm text-slate-300 font-medium">No threat intelligence hits</div>
                          <div className="text-xs text-slate-500 mt-1">Brand keywords searched: {intelData.bases_searched.join(", ") || "none"}</div>
                        </div>
                      ) : (
                        <>
                          {/* Stats */}
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                            <div className="bg-orange-900/20 border border-orange-700/30 rounded-[14px] p-3 text-center">
                              <div className="text-2xl font-bold text-orange-300">{intelData.total.toLocaleString()}</div>
                              <div className="text-xs text-slate-400 mt-0.5">Total IOC Hits</div>
                            </div>
                            <div className="bg-white/5 border border-[#1E2A3D] rounded-[14px] p-3">
                              <div className="text-xs text-slate-400 mb-1.5">By Threat Type</div>
                              {Object.entries(intelData.by_threat_type).slice(0,4).map(([t, cnt]) => (
                                <div key={t} className="flex justify-between text-xs">
                                  <span className="text-slate-300 capitalize">{t}</span>
                                  <span className="text-slate-400">{cnt}</span>
                                </div>
                              ))}
                            </div>
                            <div className="bg-white/5 border border-[#1E2A3D] rounded-[14px] p-3">
                              <div className="text-xs text-slate-400 mb-1.5">By IOC Type</div>
                              {Object.entries(intelData.by_ioc_type).slice(0,4).map(([t, cnt]) => (
                                <div key={t} className="flex justify-between text-xs">
                                  <span className="text-slate-300 capitalize">{t}</span>
                                  <span className="text-slate-400">{cnt}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* IOC records table */}
                          <div className="bg-card-dark border border-[#1E2A3D] rounded-[14px] overflow-hidden">
                            <table className="w-full text-sm">
                              <thead className="sticky top-0 z-10">
                                <tr className="text-left text-xs text-slate-400 border-b border-[#1E2A3D] bg-[#0d1528]">
                                  <th className="px-4 py-2.5 font-medium">Indicator</th>
                                  <th className="px-4 py-2.5 font-medium">Type</th>
                                  <th className="px-4 py-2.5 font-medium">Threat</th>
                                  <th className="px-4 py-2.5 font-medium">Source</th>
                                  <th className="px-4 py-2.5 font-medium">Risk</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-white/5">
                                {intelData.records.map((r, i) => {
                                  const risk = parseFloat(String(r.risk_score));
                                  return (
                                    <tr key={i} className="hover:bg-white/[0.02]">
                                      <td className="px-4 py-2.5">
                                        <div className="text-xs font-mono text-cyan-300 truncate max-w-[250px]" title={r.indicator}>{r.indicator}</div>
                                      </td>
                                      <td className="px-4 py-2.5">
                                        <span className="text-xs bg-white/10 text-slate-300 px-1.5 py-0.5 rounded">{r.indicator_type}</span>
                                      </td>
                                      <td className="px-4 py-2.5">
                                        <span className={`text-xs px-1.5 py-0.5 rounded border ${
                                          r.threat_type === "c2" ? "bg-red-900/40 text-red-300 border-red-700/40" :
                                          r.threat_type === "phishing" ? "bg-orange-900/40 text-orange-300 border-orange-700/40" :
                                          r.threat_type === "malware" ? "bg-cyan-900/40 text-cyan-300 border-cyan-700/40" :
                                          "bg-white/5 text-slate-300 border-[#1E2A3D]"
                                        } capitalize`}>{r.threat_type}</span>
                                      </td>
                                      <td className="px-4 py-2.5 text-xs text-slate-400">{r.source}</td>
                                      <td className="px-4 py-2.5">
                                        <div className="flex items-center gap-1.5">
                                          <div className="w-10 bg-white/10 rounded-full h-1.5">
                                            <div className={`h-1.5 rounded-full ${risk >= 80 ? "bg-red-400" : risk >= 60 ? "bg-orange-400" : "bg-yellow-400"}`}
                                              style={{ width: `${risk}%` }} />
                                          </div>
                                          <span className="text-xs text-slate-400">{Math.round(risk)}</span>
                                        </div>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </>
        )}
      </div>

      {/* ── Alert Detail Drawer ── */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex" onClick={() => setSelectedAlert(null)}>
          <div className="flex-1 bg-black/50" />
          <div className="w-full max-w-md bg-[#0d1528] border-l border-[#1E2A3D] overflow-y-auto flex flex-col shadow-2xl"
            onClick={e => e.stopPropagation()}>
            {/* Header */}
            <div className="flex-shrink-0 p-5 border-b border-[#1E2A3D]">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1.5">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${sevBadge(selectedAlert.severity)}`}>
                      {selectedAlert.severity.toUpperCase()}
                    </span>
                    <span className="text-xs text-slate-400 flex items-center gap-1">
                      {ALERT_TYPE_ICON[selectedAlert.alert_type] ?? "⚠"} {ALERT_TYPE_LABEL[selectedAlert.alert_type] ?? selectedAlert.alert_type}
                    </span>
                    {selectedAlert.acknowledged && (
                      <span className="text-xs text-green-400 bg-green-900/20 border border-green-700/30 px-2 py-0.5 rounded">✓ Acknowledged</span>
                    )}
                  </div>
                  <h2 className="text-sm font-bold text-white leading-snug">{selectedAlert.title}</h2>
                </div>
                <button onClick={() => setSelectedAlert(null)}
                  className="flex-shrink-0 text-slate-500 hover:text-white text-xl leading-none mt-0.5">✕</button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 p-5 space-y-4">
              {/* Domain */}
              {selectedAlert.domain && (
                <div className="bg-white/5 rounded-[14px] p-3.5">
                  <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Domain / Indicator</div>
                  <div className="font-mono text-sm text-cyan-300 break-all">{selectedAlert.domain}</div>
                  <div className="flex gap-2 mt-2">
                    <a href={`https://${selectedAlert.domain}`} target="_blank" rel="noreferrer"
                      className="text-xs text-slate-500 hover:text-primary transition-colors border border-[#1E2A3D] hover:border-primary/40 px-2 py-1 rounded">Visit ↗</a>
                    <a href={`https://who.is/whois/${selectedAlert.domain}`} target="_blank" rel="noreferrer"
                      className="text-xs text-slate-500 hover:text-primary transition-colors border border-[#1E2A3D] hover:border-primary/40 px-2 py-1 rounded">WHOIS ↗</a>
                    <a href={`https://urlscan.io/search/#domain:${selectedAlert.domain}`} target="_blank" rel="noreferrer"
                      className="text-xs text-slate-500 hover:text-primary transition-colors border border-[#1E2A3D] hover:border-primary/40 px-2 py-1 rounded">Scan ↗</a>
                  </div>
                </div>
              )}

              {/* Similarity */}
              {selectedAlert.similarity != null && selectedAlert.similarity > 0 && (
                <div>
                  <div className="text-xs text-slate-400 uppercase tracking-wider mb-1.5">Brand Similarity</div>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 bg-white/5 rounded-full h-2.5">
                      <div className={`h-2.5 rounded-full ${selectedAlert.similarity >= 80 ? "bg-red-500" : selectedAlert.similarity >= 60 ? "bg-orange-500" : "bg-yellow-500"}`}
                        style={{ width: `${selectedAlert.similarity}%` }} />
                    </div>
                    <span className={`text-lg font-bold flex-shrink-0 ${selectedAlert.similarity >= 80 ? "text-red-300" : "text-orange-300"}`}>
                      {selectedAlert.similarity}%
                    </span>
                  </div>
                </div>
              )}

              {/* Evidence details */}
              {selectedAlert.details && Object.keys(selectedAlert.details).length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">Evidence</div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {Object.entries(selectedAlert.details)
                      .filter(([,v]) => v !== null && v !== undefined && v !== "" && !Array.isArray(v) && typeof v !== "object")
                      .slice(0,8)
                      .map(([k, v]) => (
                        <div key={k} className="bg-white/5 rounded p-2">
                          <div className="text-xs text-slate-500 capitalize">{k.replace(/_/g, " ")}</div>
                          <div className="text-xs text-slate-200 font-mono mt-0.5 truncate" title={String(v)}>{String(v).slice(0,50)}</div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Detected */}
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-white/5 rounded p-2.5">
                  <div className="text-xs text-slate-500">Detected</div>
                  <div className="text-xs text-slate-200 mt-0.5">{fmtDate(selectedAlert.detected_at)}</div>
                </div>
                <div className="bg-white/5 rounded p-2.5">
                  <div className="text-xs text-slate-500">Brand</div>
                  <div className="text-xs text-slate-200 mt-0.5 truncate">{selectedAlert.brand_name ?? selectedMonitor?.brand_name ?? "—"}</div>
                </div>
              </div>

              {/* Recommended actions */}
              <div className="bg-orange-900/10 border border-orange-700/20 rounded-[14px] p-4">
                <div className="text-xs font-semibold text-orange-300 uppercase tracking-wider mb-2">Recommended Actions</div>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {(selectedAlert.alert_type === "typosquat_detected" || selectedAlert.alert_type === "domain_registered") && (<>
                    <li>• Submit takedown to registrar via ICANN UDRP process</li>
                    <li>• File abuse report with hosting provider</li>
                    <li>• Add to DNS blocklist and WAF rules immediately</li>
                    <li>• Alert customers via official channels</li>
                    <li>• Report to national CERT and AfriNIC abuse team</li>
                  </>)}
                  {selectedAlert.alert_type === "credential_leak" && (<>
                    <li>• Force immediate password reset for all accounts</li>
                    <li>• Enable MFA on all corporate systems</li>
                    <li>• Notify affected users under POPIA/GDPR obligations</li>
                    <li>• Review access logs for suspicious activity</li>
                  </>)}
                  {selectedAlert.alert_type === "ssl_certificate" && (<>
                    <li>• Investigate the domain for active phishing content</li>
                    <li>• Report to Certificate Authority for revocation</li>
                    <li>• Submit to Google Safe Browsing and Microsoft SmartScreen</li>
                  </>)}
                  {(selectedAlert.alert_type === "ti_hit" || selectedAlert.alert_type === "ioc_match") && (<>
                    <li>• Block indicator at DNS resolver and perimeter firewall</li>
                    <li>• Check for internal connections to this indicator</li>
                    <li>• Alert customers not to interact with this domain</li>
                  </>)}
                  {selectedAlert.alert_type === "brand_mention" && (<>
                    <li>• Review content for leaked data or attack planning</li>
                    <li>• Engage incident response if sensitive data is exposed</li>
                    <li>• Notify relevant authorities</li>
                  </>)}
                </ul>
              </div>
            </div>

            {/* Footer */}
            <div className="flex-shrink-0 p-4 border-t border-[#1E2A3D] flex gap-2 flex-wrap">
              {!selectedAlert.acknowledged && (
                <button onClick={() => acknowledgeAlert(selectedAlert.id)}
                  className="flex-1 px-4 py-2 bg-green-900/20 hover:bg-green-900/30 text-green-400 border border-green-700/30 rounded-lg text-xs font-medium transition-colors">
                  ✓ Acknowledge
                </button>
              )}
              <a href={`https://www.virustotal.com/gui/domain/${selectedAlert.domain}`} target="_blank" rel="noreferrer"
                className="px-3 py-2 bg-white/5 hover:bg-white/10 text-slate-300 border border-[#1E2A3D] rounded-lg text-xs transition-colors">
                VT ↗
              </a>
              <button onClick={() => setSelectedAlert(null)}
                className="px-3 py-2 bg-white/5 hover:bg-white/10 text-slate-400 border border-[#1E2A3D] rounded-lg text-xs transition-colors">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Add Monitor Modal ── */}
      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60">
          <div className="bg-[#0d1528] border border-[#1E2A3D] rounded-2xl w-full max-w-md shadow-2xl">
            <div className="p-5 border-b border-[#1E2A3D] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Add Brand Monitor</h3>
              <button onClick={() => setShowAdd(false)} className="text-slate-500 hover:text-white text-lg">✕</button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Brand Name *</label>
                <input type="text" value={addForm.name} onChange={e => setAddForm(f => ({...f, name: e.target.value}))}
                  placeholder="e.g. Equity Bank Kenya"
                  className="w-full bg-white/5 border border-[#1E2A3D] rounded-lg px-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary/50" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Primary Domain *</label>
                <input type="text" value={addForm.domain} onChange={e => setAddForm(f => ({...f, domain: e.target.value}))}
                  placeholder="e.g. equitybank.co.ke"
                  className="w-full bg-white/5 border border-[#1E2A3D] rounded-lg px-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary/50" />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1.5">Keywords (comma-separated)</label>
                <input type="text" value={addForm.keywords} onChange={e => setAddForm(f => ({...f, keywords: e.target.value}))}
                  placeholder="e.g. equity, equitybank, eazzy"
                  className="w-full bg-white/5 border border-[#1E2A3D] rounded-lg px-3 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-primary/50" />
              </div>
            </div>
            <div className="p-5 border-t border-[#1E2A3D] flex gap-3 justify-end">
              <button onClick={() => setShowAdd(false)}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 text-slate-300 border border-[#1E2A3D] rounded-lg text-sm transition-colors">Cancel</button>
              <button onClick={handleAddMonitor} disabled={adding || !addForm.name || !addForm.domain}
                className="px-4 py-2 bg-primary hover:bg-primary-hover disabled:opacity-50 text-body-dark rounded-[10px] text-sm font-semibold transition-colors flex items-center gap-2">
                {adding && <div className="w-3.5 h-3.5 border-2 border-body-dark border-t-transparent rounded-full animate-spin" />}
                {adding ? "Adding…" : "Add Monitor"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
