"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { apiFetch } from "@/lib/fetch";

// Sample/mock alerts are demo-only and OFF by default so users never act on
// fabricated intel. Set NEXT_PUBLIC_ENABLE_SAMPLE_ALERTS=true to show them.
const SHOW_SAMPLE_ALERTS = process.env.NEXT_PUBLIC_ENABLE_SAMPLE_ALERTS === "true";

// Types
interface Alert {
  id: string;
  title: string;
  description: string;
  type: "c2" | "phishing" | "darkweb" | "asm" | "brand" | "malware" | "dga";
  severity: "critical" | "high" | "medium" | "low";
  status: "new" | "acknowledged" | "investigating" | "resolved";
  source: string;
  indicator?: string;
  indicatorType?: "domain" | "ip" | "url" | "email" | "hash";
  affectedAsset?: string;
  timestamp: string;
  updatedAt?: string;
  assignedTo?: string;
  notes?: string;
}

// Mock data
const mockAlerts: Alert[] = [
  {
    id: "1",
    title: "Active C2 Domain Detected",
    description: "New command and control domain detected communicating with African financial sector networks. Domain appears to be part of larger botnet infrastructure.",
    type: "c2",
    severity: "critical",
    status: "new",
    source: "DNS Analysis",
    indicator: "evil-c2.africa-finance.com",
    indicatorType: "domain",
    timestamp: "2024-01-15T10:30:00Z",
  },
  {
    id: "2",
    title: "M-Pesa Phishing Campaign",
    description: "Coordinated phishing campaign targeting M-Pesa customers discovered. Multiple domains registered with similar patterns.",
    type: "phishing",
    severity: "critical",
    status: "investigating",
    source: "Brand Monitor",
    indicator: "m-pesa-verify.com",
    indicatorType: "domain",
    affectedAsset: "M-Pesa Brand",
    timestamp: "2024-01-15T09:45:00Z",
    updatedAt: "2024-01-15T10:00:00Z",
    assignedTo: "John Doe",
  },
  {
    id: "3",
    title: "Employee Credentials on Dark Web",
    description: "Multiple employee credentials found in dark web database leak. Credentials appear to be from recent breach.",
    type: "darkweb",
    severity: "high",
    status: "acknowledged",
    source: "Dark Web Monitor",
    indicator: "user@company.co.ke",
    indicatorType: "email",
    timestamp: "2024-01-15T08:20:00Z",
    updatedAt: "2024-01-15T08:45:00Z",
  },
  {
    id: "4",
    title: "Exposed Development Server",
    description: "Development server with debug endpoints exposed to internet without authentication.",
    type: "asm",
    severity: "high",
    status: "new",
    source: "Attack Surface",
    indicator: "dev.company.co.ke:8080",
    indicatorType: "url",
    affectedAsset: "dev.company.co.ke",
    timestamp: "2024-01-15T07:15:00Z",
  },
  {
    id: "5",
    title: "Safaricom Typosquat Domain",
    description: "New typosquatting domain registered that impersonates Safaricom brand.",
    type: "brand",
    severity: "medium",
    status: "new",
    source: "Brand Monitor",
    indicator: "safar1com.co.ke",
    indicatorType: "domain",
    affectedAsset: "Safaricom Brand",
    timestamp: "2024-01-14T22:00:00Z",
  },
  {
    id: "6",
    title: "DGA Domain Activity",
    description: "Multiple algorithmically generated domains detected in DNS traffic patterns.",
    type: "dga",
    severity: "high",
    status: "acknowledged",
    source: "DNS Analysis",
    indicator: "xk7jq9m2.com",
    indicatorType: "domain",
    timestamp: "2024-01-14T18:30:00Z",
    assignedTo: "Jane Smith",
  },
  {
    id: "7",
    title: "Malware Distribution Site",
    description: "Known malware distribution domain accessed from internal network.",
    type: "malware",
    severity: "critical",
    status: "investigating",
    source: "Threat Intel",
    indicator: "malware-drop.badsite.com",
    indicatorType: "domain",
    timestamp: "2024-01-14T15:00:00Z",
    updatedAt: "2024-01-14T16:30:00Z",
    assignedTo: "Security Team",
  },
  {
    id: "8",
    title: "SSL Certificate Expiring",
    description: "SSL certificate for production server expires in 7 days.",
    type: "asm",
    severity: "medium",
    status: "acknowledged",
    source: "Attack Surface",
    affectedAsset: "api.company.co.ke",
    timestamp: "2024-01-14T12:00:00Z",
    notes: "Certificate renewal scheduled",
  },
  {
    id: "9",
    title: "New IP in Threat Feed",
    description: "IP address from internal network found in new threat intelligence feed.",
    type: "c2",
    severity: "medium",
    status: "resolved",
    source: "Threat Intel",
    indicator: "192.168.1.100",
    indicatorType: "ip",
    timestamp: "2024-01-13T10:00:00Z",
    updatedAt: "2024-01-13T14:00:00Z",
    notes: "False positive - IP belongs to security scanner",
  },
  {
    id: "10",
    title: "KCB Bank Impersonation",
    description: "Phishing kit mimicking KCB Bank login page detected.",
    type: "phishing",
    severity: "high",
    status: "resolved",
    source: "Brand Monitor",
    indicator: "kcb-secure-login.com",
    indicatorType: "domain",
    affectedAsset: "KCB Bank Brand",
    timestamp: "2024-01-12T09:00:00Z",
    updatedAt: "2024-01-12T16:00:00Z",
    notes: "Domain taken down by registrar",
  },
];

const typeLabels: Record<Alert["type"], string> = {
  c2: "C2/Botnet",
  phishing: "Phishing",
  darkweb: "Dark Web",
  asm: "Attack Surface",
  brand: "Brand",
  malware: "Malware",
  dga: "DGA",
};

const typeColors: Record<Alert["type"], string> = {
  c2: "bg-red-500/20 text-red-400 border-red-500/30",
  phishing: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  darkweb: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  asm: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  brand: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  malware: "bg-pink-500/20 text-pink-400 border-pink-500/30",
  dga: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
};

const severityColors: Record<Alert["severity"], string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-green-500",
};

const statusColors: Record<Alert["status"], string> = {
  new: "bg-blue-500/20 text-blue-400",
  acknowledged: "bg-yellow-500/20 text-yellow-400",
  investigating: "bg-purple-500/20 text-purple-400",
  resolved: "bg-green-500/20 text-green-400",
};

// Icons
const BellIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
  </svg>
);

const CloseIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
  </svg>
);

const CheckIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
  </svg>
);

const ExternalLinkIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
  </svg>
);

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const formatTimeAgo = (timestamp: string) => {
  const now = new Date();
  const date = new Date(timestamp);
  const diff = now.getTime() - date.getTime();
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor(diff / (1000 * 60));

  if (hours > 24) {
    return `${Math.floor(hours / 24)}d ago`;
  } else if (hours > 0) {
    return `${hours}h ago`;
  } else {
    return `${minutes}m ago`;
  }
};

type FilterType = "all" | Alert["type"];
type FilterSeverity = "all" | Alert["severity"];
type FilterStatus = "all" | Alert["status"];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSample, setIsSample] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<FilterType>("all");
  const [severityFilter, setSeverityFilter] = useState<FilterSeverity>("all");
  const [statusFilter, setStatusFilter] = useState<FilterStatus>("all");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await apiFetch(`/api/v1/alerts/feed?limit=100`);
      if (!res.ok) throw new Error(`Failed to load alerts (${res.status})`);
      const data = await res.json();
      const items = (data.items || []) as Record<string, unknown>[];
      if (items.length > 0) {
        setIsSample(false);
        setAlerts(items.map((a, i) => ({
          id: String(a.id ?? `alert-${i}`),
          title: String(a.title || ""),
          description: String(a.description || ""),
          type: String(a.type || "malware") as Alert["type"],
          severity: String(a.severity || "medium") as Alert["severity"],
          status: String(a.status || "new") as Alert["status"],
          source: String(a.source || ""),
          indicator: a.indicator ? String(a.indicator) : undefined,
          timestamp: String(a.timestamp || new Date().toISOString()),
        })));
      } else {
        // No real alerts. Show sample data ONLY behind the explicit flag,
        // otherwise show a genuine empty state (never fabricate intel).
        setIsSample(SHOW_SAMPLE_ALERTS);
        setAlerts(SHOW_SAMPLE_ALERTS ? mockAlerts : []);
      }
    } catch (err) {
      console.error("Failed to fetch alerts:", err);
      setError(err instanceof Error ? err.message : "Failed to load alerts");
      setIsSample(SHOW_SAMPLE_ALERTS);
      setAlerts(SHOW_SAMPLE_ALERTS ? mockAlerts : []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  // Dialog a11y: focus into the dialog, trap Tab, close on Escape, restore focus.
  useEffect(() => {
    if (!selectedAlert) return;
    const dialog = dialogRef.current;
    const prevFocus = document.activeElement as HTMLElement | null;

    const focusable = () =>
      dialog
        ? Array.from(
            dialog.querySelectorAll<HTMLElement>(
              'a[href],button:not([disabled]),textarea,input,select,[tabindex]:not([tabindex="-1"])',
            ),
          ).filter((el) => el.offsetParent !== null)
        : [];

    (focusable()[0] ?? dialog)?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        setSelectedAlert(null);
        return;
      }
      if (e.key === "Tab") {
        const items = focusable();
        if (items.length === 0) { e.preventDefault(); return; }
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement as HTMLElement;
        if (e.shiftKey && active === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      prevFocus?.focus?.();
    };
  }, [selectedAlert]);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch = 
      alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (alert.indicator && alert.indicator.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = typeFilter === "all" || alert.type === typeFilter;
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || alert.status === statusFilter;
    return matchesSearch && matchesType && matchesSeverity && matchesStatus;
  });

  const handleStatusChange = async (alertId: string, newStatus: Alert["status"]) => {
    const now = new Date().toISOString();
    const prev = alerts;
    // Optimistic update
    setAlerts((cur) => cur.map((a) =>
      a.id === alertId ? { ...a, status: newStatus, updatedAt: now } : a,
    ));
    setSelectedAlert((cur) =>
      cur && cur.id === alertId ? { ...cur, status: newStatus, updatedAt: now } : cur,
    );
    // Sample/demo alerts aren't real records — don't try to persist them.
    if (isSample) return;
    try {
      const res = await apiFetch(`/api/v1/alerts/${encodeURIComponent(alertId)}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error(`status ${res.status}`);
    } catch {
      // Revert on failure and surface the error.
      setAlerts(prev);
      setSelectedAlert((cur) =>
        cur && cur.id === alertId ? (prev.find((a) => a.id === alertId) ?? cur) : cur,
      );
      setError("Could not save alert status. Please retry.");
    }
  };

  const alertCounts = {
    total: alerts.length,
    critical: alerts.filter((a) => a.severity === "critical" && a.status !== "resolved").length,
    high: alerts.filter((a) => a.severity === "high" && a.status !== "resolved").length,
    new: alerts.filter((a) => a.status === "new").length,
    resolved: alerts.filter((a) => a.status === "resolved").length,
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-card-dark rounded animate-pulse" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 bg-card-dark rounded-xl animate-pulse" />
          ))}
        </div>
        <div className="h-96 bg-card-dark rounded-2xl animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-4 pb-8">
      {/* Sticky page header */}
      <div className="sticky top-0 z-20 bg-ebony-950/95 backdrop-blur-sm pt-4 pb-2 -mx-4 px-4 lg:-mx-8 lg:px-8 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">All Alerts</h1>
          <p className="text-gray-400 mt-1">Unified view of security alerts across all modules</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">
            {filteredAlerts.length} of {alerts.length} alerts
          </span>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Alerts</p>
              <p className="text-2xl font-bold text-white mt-1">{alertCounts.total}</p>
            </div>
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400">
              <BellIcon />
            </div>
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Critical</p>
              <p className="text-2xl font-bold text-red-400 mt-1">{alertCounts.critical}</p>
            </div>
            <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">New</p>
              <p className="text-2xl font-bold text-blue-400 mt-1">{alertCounts.new}</p>
            </div>
            <div className="w-3 h-3 bg-blue-500 rounded-full" />
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Resolved</p>
              <p className="text-2xl font-bold text-green-400 mt-1">{alertCounts.resolved}</p>
            </div>
            <div className="p-1 bg-green-500/20 rounded-full">
              <CheckIcon />
            </div>
          </div>
        </div>
      </div>

      </div>{/* end sticky header */}

      {error && (
        <div role="alert" className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
          {error}
        </div>
      )}
      {isSample && alerts.length > 0 && (
        <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-amber-400 text-sm">
          Showing sample data — no live alerts are available.
        </div>
      )}

      {/* Search/filter bar + alerts list */}
      <div className="bg-card-dark border border-white/10 rounded-2xl">
        {/* Sticky filter bar inside the card */}
        <div className="sticky top-[120px] z-10 bg-card-dark rounded-t-2xl p-4 border-b border-white/10">
          <div className="flex flex-col lg:flex-row gap-4">
            {/* Search */}
            <div className="relative flex-1">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search alerts, indicators, descriptions..."
                className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-primary/50"
              />
              <svg
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>

            {/* Filter toggles */}
            <div className="flex flex-wrap gap-2">
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value as FilterType)}
                className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:border-primary/50"
              >
                <option value="all">All Types</option>
                {Object.entries(typeLabels).map(([key, label]) => (
                  <option key={key} value={key}>{label}</option>
                ))}
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as FilterSeverity)}
                className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:border-primary/50"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as FilterStatus)}
                className="px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-white text-sm focus:outline-none focus:border-primary/50"
              >
                <option value="all">All Status</option>
                <option value="new">New</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>

          {/* Active filters */}
          {(typeFilter !== "all" || severityFilter !== "all" || statusFilter !== "all") && (
            <div className="flex flex-wrap gap-2 mt-4">
              {typeFilter !== "all" && (
                <span className="flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-sm">
                  Type: {typeLabels[typeFilter as Alert["type"]]}
                  <button onClick={() => setTypeFilter("all")} className="ml-1 hover:text-white">
                    <CloseIcon />
                  </button>
                </span>
              )}
              {severityFilter !== "all" && (
                <span className="flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-sm">
                  Severity: {severityFilter}
                  <button onClick={() => setSeverityFilter("all")} className="ml-1 hover:text-white">
                    <CloseIcon />
                  </button>
                </span>
              )}
              {statusFilter !== "all" && (
                <span className="flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded text-sm">
                  Status: {statusFilter}
                  <button onClick={() => setStatusFilter("all")} className="ml-1 hover:text-white">
                    <CloseIcon />
                  </button>
                </span>
              )}
              <button
                onClick={() => {
                  setTypeFilter("all");
                  setSeverityFilter("all");
                  setStatusFilter("all");
                }}
                className="text-sm text-gray-400 hover:text-white"
              >
                Clear all
              </button>
            </div>
          )}
        </div>

        {/* Alerts list */}
        <div className="divide-y divide-white/5">
          {filteredAlerts.length === 0 ? (
            <div className="p-12 text-center">
              <BellIcon />
              <h3 className="text-lg font-medium text-white mt-4">No alerts found</h3>
              <p className="text-gray-400 mt-2">Try adjusting your filters or search query</p>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className="p-4 hover:bg-white/[0.02] transition-colors"
              >
                <div className="flex items-start gap-4">
                  {/* Severity indicator */}
                  <div className={`w-1 h-full min-h-[60px] rounded-full ${severityColors[alert.severity]}`} />

                  {/* Main content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-4">
                      <button
                        type="button"
                        onClick={() => setSelectedAlert(alert)}
                        aria-label={`View alert: ${alert.title}`}
                        className="flex-1 min-w-0 text-left cursor-pointer rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                      >
                        <div className="flex items-center flex-wrap gap-2 mb-1">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${typeColors[alert.type]}`}>
                            {typeLabels[alert.type]}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-xs ${statusColors[alert.status]}`}>
                            {alert.status.replace("_", " ")}
                          </span>
                          <span className="text-xs text-gray-500">{formatTimeAgo(alert.timestamp)}</span>
                        </div>
                        <h3 className="text-white font-medium truncate">{alert.title}</h3>
                        <p className="text-sm text-gray-400 mt-1 line-clamp-2">{alert.description}</p>
                        
                        {alert.indicator && (
                          <div className="flex items-center gap-2 mt-2">
                            <code className="text-xs text-primary bg-primary/10 px-2 py-0.5 rounded">
                              {alert.indicator}
                            </code>
                            {alert.indicatorType && (
                              <span className="text-xs text-gray-500 capitalize">{alert.indicatorType}</span>
                            )}
                          </div>
                        )}

                        <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                          <span>Source: {alert.source}</span>
                          {alert.affectedAsset && (
                            <>
                              <span>|</span>
                              <span>Asset: {alert.affectedAsset}</span>
                            </>
                          )}
                          {alert.assignedTo && (
                            <>
                              <span>|</span>
                              <span>Assigned: {alert.assignedTo}</span>
                            </>
                          )}
                        </div>
                      </button>

                      {/* Quick actions */}
                      <div className="flex items-center gap-2">
                        {alert.status !== "resolved" && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleStatusChange(alert.id, "resolved");
                            }}
                            className="p-2 hover:bg-green-500/10 text-gray-400 hover:text-green-400 rounded-lg transition-colors"
                            title="Mark as resolved"
                          >
                            <CheckIcon />
                          </button>
                        )}
                        <button
                          onClick={(e) => e.stopPropagation()}
                          className="p-2 hover:bg-white/5 text-gray-400 hover:text-white rounded-lg transition-colors"
                        >
                          <ExternalLinkIcon />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Alert details modal */}
      {selectedAlert && (
        <div
          className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4"
          onClick={() => setSelectedAlert(null)}
        >
          <div
            ref={dialogRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="alert-dialog-title"
            tabIndex={-1}
            onClick={(e) => e.stopPropagation()}
            className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto outline-none">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${severityColors[selectedAlert.severity]}`} />
                  <span className={`px-2 py-0.5 rounded text-xs font-medium border ${typeColors[selectedAlert.type]}`}>
                    {typeLabels[selectedAlert.type]}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs ${statusColors[selectedAlert.status]}`}>
                    {selectedAlert.status.replace("_", " ")}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="p-2 hover:bg-white/5 rounded-lg text-gray-400 hover:text-white transition-colors"
                >
                  <CloseIcon />
                </button>
              </div>
              <h2 id="alert-dialog-title" className="text-xl font-semibold text-white mt-4">{selectedAlert.title}</h2>
            </div>

            <div className="p-6 space-y-6">
              {/* Description */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Description</h3>
                <p className="text-gray-300">{selectedAlert.description}</p>
              </div>

              {/* Indicator */}
              {selectedAlert.indicator && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Indicator</h3>
                  <div className="flex items-center gap-3">
                    <code className="text-primary bg-primary/10 px-3 py-2 rounded-lg">
                      {selectedAlert.indicator}
                    </code>
                    {selectedAlert.indicatorType && (
                      <span className="text-sm text-gray-500 capitalize">({selectedAlert.indicatorType})</span>
                    )}
                  </div>
                </div>
              )}

              {/* Details grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-white/[0.02] rounded-xl">
                  <p className="text-xs text-gray-500 mb-1">Source</p>
                  <p className="text-white">{selectedAlert.source}</p>
                </div>
                <div className="p-4 bg-white/[0.02] rounded-xl">
                  <p className="text-xs text-gray-500 mb-1">Severity</p>
                  <p className="text-white capitalize">{selectedAlert.severity}</p>
                </div>
                <div className="p-4 bg-white/[0.02] rounded-xl">
                  <p className="text-xs text-gray-500 mb-1">Created</p>
                  <p className="text-white">{formatDate(selectedAlert.timestamp)}</p>
                </div>
                <div className="p-4 bg-white/[0.02] rounded-xl">
                  <p className="text-xs text-gray-500 mb-1">Last Updated</p>
                  <p className="text-white">
                    {selectedAlert.updatedAt ? formatDate(selectedAlert.updatedAt) : "—"}
                  </p>
                </div>
                {selectedAlert.affectedAsset && (
                  <div className="p-4 bg-white/[0.02] rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Affected Asset</p>
                    <p className="text-white">{selectedAlert.affectedAsset}</p>
                  </div>
                )}
                {selectedAlert.assignedTo && (
                  <div className="p-4 bg-white/[0.02] rounded-xl">
                    <p className="text-xs text-gray-500 mb-1">Assigned To</p>
                    <p className="text-white">{selectedAlert.assignedTo}</p>
                  </div>
                )}
              </div>

              {/* Notes */}
              {selectedAlert.notes && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Notes</h3>
                  <p className="text-gray-300 p-4 bg-white/[0.02] rounded-xl">{selectedAlert.notes}</p>
                </div>
              )}

              {/* Status actions */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-3">Update Status</h3>
                <div className="flex flex-wrap gap-2">
                  {(["new", "acknowledged", "investigating", "resolved"] as Alert["status"][]).map((status) => (
                    <button
                      key={status}
                      onClick={() => handleStatusChange(selectedAlert.id, status)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        selectedAlert.status === status
                          ? "bg-primary text-white"
                          : "bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white"
                      }`}
                    >
                      {status.charAt(0).toUpperCase() + status.slice(1).replace("_", " ")}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 text-gray-300 rounded-lg transition-colors"
              >
                Close
              </button>
              {selectedAlert.status !== "resolved" && (
                <button
                  onClick={() => {
                    handleStatusChange(selectedAlert.id, "resolved");
                    setSelectedAlert(null);
                  }}
                  className="px-4 py-2 bg-green-500/10 hover:bg-green-500/20 text-green-400 rounded-lg transition-colors flex items-center gap-2"
                >
                  <CheckIcon />
                  Mark as Resolved
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
