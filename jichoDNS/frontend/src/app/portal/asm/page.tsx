"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { apiFetch, apiFetchJSON } from "@/lib/fetch";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ASMClient {
  id: number;
  name: string;
  slug: string;
  industry: string | null;
  country_code: string | null;
  description: string | null;
  asset_owner: string | null;
  business_unit: string | null;
  contact_email: string | null;
  webhook_url: string | null;
  notify_on: string[];
  is_active: boolean;
  scan_schedule: string;    // display label e.g. "every_24h"
  scan_interval_minutes: number;
  last_scan_at: string | null;
  next_scan_at: string | null;
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  risk_score: number;
  risk_grade: string;
  ti_hit_count: number;
  open_ports: number;
  ssl_issues: number;
  created_at: string;
  updated_at: string;
}

interface DiscoveryGroup {
  id: number;
  client_id: number;
  name: string;
  description: string | null;
  is_active: boolean;
  seeds: Array<{ type: string; value: string }>;
  include_subdomains: boolean;
  include_ports: boolean;
  include_ssl: boolean;
  include_whois: boolean;
  include_ct_logs: boolean;
  include_http_checks: boolean;
  include_nuclei: boolean;
  include_ti_enrich: boolean;
  last_run_at: string | null;
  assets_discovered: number;
  findings_count: number;
  created_at: string;
}

interface Asset {
  id: string;
  type: string;
  value: string;
  status: string | null;
  risk_score: number;
  tags: string[] | null;
  tech_stack?: string[] | null;
  ti_tagged?: boolean;
  ti_threat_types?: string[] | null;
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown> | null;
  root_domain?: string;
}

// Enterprise finding (replaces Vulnerability) — includes EPSS, KEV, TI categories
interface Finding {
  id: string;
  title: string;
  severity: string | null;
  category: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_cisa_kev: boolean;
  is_exploitable: boolean;
  exploit_available: boolean;
  description: string | null;
  affected_asset_value?: string;   // raw ES field name
  affected_asset_type?: string;
  asset_value: string;             // API-mapped name
  asset_type: string;
  remediation: string | null;
  references: string[] | null;
  status: string;
  source: string | null;
  first_seen: string | null;
  last_seen: string | null;
  detected_at?: string | null;     // raw ES field
}

// Keep Vulnerability as alias for backwards compat within the file
type Vulnerability = Finding;

interface Change {
  id: string;
  asset_id: string;
  asset_value: string;
  change_type: string;
  old_value: string | null;
  new_value: string | null;
  detected_at: string;
}

interface Summary {
  total_assets: number;
  by_type: Record<string, number>;
  average_risk_score: number;
  high_risk_assets: number;
  risk_score: number;
  // enterprise findings
  total_findings: number;
  findings_by_severity: Record<string, number>;
  findings_by_category: Record<string, number>;
  kev_count: number;
  exploitable_count: number;
  avg_epss: number;
  risk_grade: string;
  risk_factors: string[];
  // base discovery stats (may exist)
  total_vulnerabilities?: number;
  critical_vulnerabilities?: number;
  high_vulnerabilities?: number;
  total_open_ports: number;
  ssl_issues: number;
  changes_last_7_days: number;
  // cross-dataset intel
  brand_exposures: number;
  credential_leaks: number;
  country_indicator_count: number;
  region_risk: {
    overall_risk: number;
    c2_risk: number;
    exfil_risk: number;
    phishing_risk: number;
    indicator_count: number;
    c2_count: number;
    exfil_count: number;
    phishing_count: number;
  } | null;
  client_name?: string;
  country_code?: string;
  industry?: string;
}

interface SecurityFinding {
  category: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
}

interface SecurityPosture {
  domain: string;
  security_score: number;
  grade: string;
  total_findings: number;
  by_severity: Record<string, number>;
  findings: SecurityFinding[];
  checks_performed: string[];
}

interface Toast {
  id: number;
  type: "success" | "error" | "info";
  message: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const severityColor = (s: string) => {
  switch (s) {
    case "critical": return "bg-red-900/60 text-red-200 border border-red-700";
    case "high":     return "bg-orange-900/60 text-orange-200 border border-orange-700";
    case "medium":   return "bg-yellow-900/60 text-yellow-200 border border-yellow-700";
    case "low":      return "bg-blue-900/60 text-blue-200 border border-blue-700";
    default:         return "bg-gray-700 text-gray-300 border border-gray-600";
  }
};

const riskColor = (s: number) =>
  s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-green-400";

const riskBg = (s: number) =>
  s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-500" : s >= 40 ? "bg-yellow-500" : "bg-green-500";

const assetIcon = (t: string) => {
  const m: Record<string, string> = {
    domain: "🌐", subdomain: "🔗", ip: "📡", port: "🔌", service: "⚙️", certificate: "🔒"
  };
  return m[t] ?? "📦";
};

const gradeColor = (g: string) =>
  g === "A" ? "text-green-400" : g === "B" ? "text-blue-400" : g === "C" ? "text-yellow-400" :
  g === "D" ? "text-orange-400" : "text-red-400";

function fmt(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

function fmtTs(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

// ── Dark-web exposure (per-client) ──────────────────────────────────────────
interface DarkwebPost {
  _id?: string;
  title?: string;
  body_text?: string;
  url?: string;
  source?: string;
  source_type?: string;
  crawl_query?: string;
  discovered_at?: string;
  severity?: string;
  tags?: string[];
  onion_links?: string[];
  emails_found?: string[];
  domains_found?: string[];
  ips_found?: string[];
}
interface DarkwebIoc {
  _id?: string;
  indicator?: string;
  indicator_type?: string;
  threat_type?: string;
  source?: string;
  source_url?: string;
  last_seen?: string;
  tags?: string[];
}
interface DarkwebData {
  client_id: number;
  terms: string[];
  watchlist_id: number | null;
  posts: DarkwebPost[];
  ioc_hits: DarkwebIoc[];
  total_posts: number;
  total_ioc_hits: number;
}

// ─── Schedule options ─────────────────────────────────────────────────────────

const SCHEDULE_OPTIONS = [
  { label: "Manual only",    minutes: 0 },
  { label: "Every 30 min",   minutes: 30 },
  { label: "Every 1 hour",   minutes: 60 },
  { label: "Every 4 hours",  minutes: 240 },
  { label: "Every 6 hours",  minutes: 360 },
  { label: "Every 8 hours",  minutes: 480 },
  { label: "Every 12 hours", minutes: 720 },
  { label: "Every 24 hours", minutes: 1440 },
] as const;

// ─── Seed type options ────────────────────────────────────────────────────────

const SEED_TYPES = [
  { value: "domain",       label: "Domain",        placeholder: "safaricom.co.ke",        hint: "Apex domain or subdomain" },
  { value: "ip_range",     label: "IP / CIDR",     placeholder: "196.201.0.0/18",         hint: "Single IP or CIDR block" },
  { value: "asn",          label: "ASN",           placeholder: "AS36908",                hint: "Autonomous System Number" },
  { value: "org_name",     label: "Org Name",      placeholder: "Safaricom",              hint: "WHOIS organisation search" },
  { value: "email_domain", label: "Email Domain",  placeholder: "safaricom.co.ke",        hint: "Certificate & OSINT pivot" },
] as const;

// ─── Modal ────────────────────────────────────────────────────────────────────

function Modal({ onClose, children, maxWidth = "max-w-lg" }: {
  onClose: () => void;
  children: React.ReactNode;
  maxWidth?: string;
}) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
  if (!mounted) return null;
  return createPortal(
    <div
      className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      style={{ zIndex: 9999 }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className={`w-full ${maxWidth}`}>{children}</div>
    </div>,
    document.body
  );
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function ToastContainer({ toasts, remove }: { toasts: Toast[]; remove: (id: number) => void }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);
  if (!mounted || toasts.length === 0) return null;
  return createPortal(
    <div className="fixed bottom-4 right-4 flex flex-col gap-2" style={{ zIndex: 10000 }}>
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg text-sm font-medium max-w-sm cursor-pointer
            ${t.type === "success" ? "bg-green-800 text-green-100 border border-green-600" :
              t.type === "error" ? "bg-red-900 text-red-100 border border-red-700" :
              "bg-gray-700 text-white border border-gray-600"}`}
          onClick={() => remove(t.id)}
        >
          <span>{t.type === "success" ? "✓" : t.type === "error" ? "✕" : "ℹ"}</span>
          <span className="flex-1">{t.message}</span>
        </div>
      ))}
    </div>,
    document.body
  );
}

// ─── StatCard ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
      <p className="text-xs text-gray-400 uppercase tracking-wide">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color ?? "text-white"}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ASMPage() {
  // ── Scroll refs ───────────────────────────────────────────────────────────
  const detailPaneRef = useRef<HTMLDivElement>(null);

  // ── Core state ────────────────────────────────────────────────────────────
  const [clients, setClients] = useState<ASMClient[]>([]);
  const [selectedClient, setSelectedClient] = useState<ASMClient | null>(null);
  const [groups, setGroups] = useState<DiscoveryGroup[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetsTotal, setAssetsTotal] = useState(0);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [vulnsTotal, setVulnsTotal] = useState(0);
  const [vulnsOffset, setVulnsOffset] = useState(0);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [vulnCategoryFilter, setVulnCategoryFilter] = useState("all");
  const [vulnSearch, setVulnSearch] = useState("");
  const VULN_LIMIT = 50;
  const [changes, setChanges] = useState<Change[]>([]);
  const [secPosture, setSecPosture] = useState<SecurityPosture | null>(null);
  const [darkweb, setDarkweb] = useState<DarkwebData | null>(null);
  const [tab, setTab] = useState<"overview" | "assets" | "vulns" | "changes" | "security" | "darkweb" | "groups">("overview");

  // ── Loading/error state ───────────────────────────────────────────────────
  const [loadingMain, setLoadingMain] = useState(false);
  const [loadingTab, setLoadingTab] = useState(false);
  const [loadingSecCheck, setLoadingSecCheck] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanJobState, setScanJobState] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastCounter = useRef(0);

  // ── Filters ───────────────────────────────────────────────────────────────
  const [assetSearch, setAssetSearch] = useState("");
  const [assetTypeFilter, setAssetTypeFilter] = useState("all");
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState("all");
  const [changesDays, setChangesDays] = useState(30);
  const [assetOffset, setAssetOffset] = useState(0);
  const ASSET_LIMIT = 50;

  // ── Modal state ───────────────────────────────────────────────────────────
  const [showNewClient, setShowNewClient] = useState(false);
  const [showNewGroup, setShowNewGroup] = useState(false);
  const [showEditClient, setShowEditClient] = useState(false);
  const [showEditGroup, setShowEditGroup] = useState<DiscoveryGroup | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // ── New client form ───────────────────────────────────────────────────────
  const [ncName, setNcName] = useState("");
  const [ncIndustry, setNcIndustry] = useState("");
  const [ncCountry, setNcCountry] = useState("");
  const [ncDesc, setNcDesc] = useState("");
  const [ncInterval, setNcInterval] = useState(1440); // default: every 24h
  const [ncOwner, setNcOwner] = useState("");
  const [ncBU, setNcBU] = useState("");
  const [ncEmail, setNcEmail] = useState("");

  // ── Edit client form ──────────────────────────────────────────────────────
  const [ecName, setEcName] = useState("");
  const [ecIndustry, setEcIndustry] = useState("");
  const [ecCountry, setEcCountry] = useState("");
  const [ecDesc, setEcDesc] = useState("");
  const [ecInterval, setEcInterval] = useState(1440);
  const [ecOwner, setEcOwner] = useState("");
  const [ecBU, setEcBU] = useState("");
  const [ecEmail, setEcEmail] = useState("");

  // ── New group form: structured seeds ─────────────────────────────────────
  const [ngName, setNgName] = useState("");
  const [ngDesc, setNgDesc] = useState("");
  // Each seed: { type, value }
  const [ngSeeds, setNgSeeds] = useState<Array<{ type: string; value: string }>>([
    { type: "domain", value: "" },
  ]);
  const [ngPorts, setNgPorts] = useState(true);
  const [ngSSL, setNgSSL] = useState(true);
  const [ngSubdomains, setNgSubdomains] = useState(true);
  const [ngWhois, setNgWhois] = useState(true);
  const [ngCT, setNgCT] = useState(true);
  const [ngHttp, setNgHttp] = useState(true);
  const [ngTI, setNgTI] = useState(true);

  // ── Security check domain ─────────────────────────────────────────────────
  const [secCheckDomain, setSecCheckDomain] = useState("");

  // ── Toast helpers ─────────────────────────────────────────────────────────
  const toast = useCallback((type: Toast["type"], message: string) => {
    const id = ++toastCounter.current;
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // ── Data fetchers ─────────────────────────────────────────────────────────

  const fetchClients = useCallback(async () => {
    try {
      const data = await apiFetchJSON("/api/v1/asm/clients") as Record<string, unknown> | null;
      const list = (data?.clients as ASMClient[]) ?? [];
      setClients(list);
      // Auto-select the first client on initial load
      if (list.length > 0) {
        setSelectedClient((prev) => prev ?? list[0]);
      }
    } catch {
      setClients([]);
    }
  }, []);

  const fetchClientData = useCallback(async (client: ASMClient) => {
    setLoadingMain(true);
    try {
      const [sumData, groupData] = await Promise.all([
        apiFetchJSON(`/api/v1/asm/clients/${client.id}/summary`).catch(() => null),
        apiFetchJSON(`/api/v1/asm/clients/${client.id}/groups`).catch(() => null),
      ]);
      setSummary(sumData as Summary | null);
      setGroups(((groupData as Record<string, unknown> | null)?.groups as DiscoveryGroup[]) ?? []);
    } finally {
      setLoadingMain(false);
    }
  }, []);

  const fetchAssets = useCallback(async (clientId: number, offset = 0, typeFilter = "all", search = "") => {
    setLoadingTab(true);
    try {
      const params = new URLSearchParams({ limit: String(ASSET_LIMIT), offset: String(offset) });
      if (typeFilter !== "all") params.set("asset_type", typeFilter);
      if (search.trim()) params.set("search", search.trim());
      const data = await apiFetchJSON(`/api/v1/asm/clients/${clientId}/assets?${params}`) as Record<string, unknown> | null;
      setAssets((data?.assets as Asset[]) ?? []);
      setAssetsTotal((data?.total as number) ?? 0);
    } finally {
      setLoadingTab(false);
    }
  }, []);

  const fetchVulns = useCallback(async (
    clientId: number,
    severity = "all",
    category = "all",
    search = "",
    offset = 0,
  ) => {
    setLoadingTab(true);
    try {
      const params = new URLSearchParams({ limit: String(VULN_LIMIT), status: "open", offset: String(offset) });
      if (severity !== "all") params.set("severity", severity);
      if (category !== "all") params.set("category", category);
      if (search.trim()) params.set("search", search.trim());
      const data = await apiFetchJSON(`/api/v1/asm/clients/${clientId}/findings?${params}`) as Record<string, unknown> | null;
      setVulns((data?.findings as Finding[]) ?? []);
      setVulnsTotal((data?.total as number) ?? 0);
      setVulnsOffset(offset);
    } finally {
      setLoadingTab(false);
    }
  }, []);

  const fetchChanges = useCallback(async (clientId: number, days = 30) => {
    setLoadingTab(true);
    try {
      const data = await apiFetchJSON(`/api/v1/asm/clients/${clientId}/changes?days=${days}&limit=200`) as Record<string, unknown> | null;
      setChanges((data?.changes as Change[]) ?? []);
    } finally {
      setLoadingTab(false);
    }
  }, []);

  const fetchDarkweb = useCallback(async (clientId: number) => {
    setLoadingTab(true);
    try {
      const data = await apiFetchJSON(`/api/v1/asm/clients/${clientId}/darkweb?limit=100`) as DarkwebData | null;
      setDarkweb(data);
    } finally {
      setLoadingTab(false);
    }
  }, []);

  // ── Job polling ───────────────────────────────────────────────────────────

  useEffect(() => {
    if (!scanJobId || !selectedClient) return;
    if (scanJobState === "SUCCESS" || scanJobState === "FAILURE" || scanJobState === "REVOKED") return;

    const interval = setInterval(async () => {
      try {
        const data = await apiFetchJSON(`/api/v1/asm/jobs/${scanJobId}`) as Record<string, unknown> | null;
        const state = (data?.state as string) ?? "UNKNOWN";
        setScanJobState(state);
        if (state === "SUCCESS") {
          clearInterval(interval);
          setScanning(false);
          setScanJobId(null);
          toast("success", "Scan completed successfully");
          fetchClientData(selectedClient);
        } else if (state === "FAILURE") {
          clearInterval(interval);
          setScanning(false);
          setScanJobId(null);
          toast("error", "Scan failed — check server logs");
        }
      } catch {
        // ignore polling errors
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [scanJobId, scanJobState, selectedClient, fetchClientData, toast]);

  // ── Effects ───────────────────────────────────────────────────────────────

  useEffect(() => { fetchClients(); }, [fetchClients]);

  useEffect(() => {
    if (!selectedClient) return;
    fetchClientData(selectedClient);
    setTab("overview");
    setAssets([]); setVulns([]); setChanges([]); setDarkweb(null);
    setAssetOffset(0); setAssetSearch(""); setAssetTypeFilter("all");
    setVulnsOffset(0); setVulnSeverityFilter("all"); setVulnCategoryFilter("all"); setVulnSearch(""); setVulnsTotal(0); setSelectedFinding(null);
    setSecPosture(null); setSecCheckDomain("");
    // Reset detail pane scroll to top whenever a new client is selected
    if (detailPaneRef.current) detailPaneRef.current.scrollTop = 0;
  }, [selectedClient, fetchClientData]);

  useEffect(() => {
    if (!selectedClient) return;
    // Note: assetSearch is intentionally omitted — search is triggered manually via button/Enter
    if (tab === "assets") fetchAssets(selectedClient.id, assetOffset, assetTypeFilter, "");
    if (tab === "vulns") fetchVulns(selectedClient.id, vulnSeverityFilter, vulnCategoryFilter, vulnSearch, vulnsOffset);
    if (tab === "changes") fetchChanges(selectedClient.id, changesDays);
    if (tab === "darkweb") fetchDarkweb(selectedClient.id);
    if (tab === "groups") {
      apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}/groups`)
        .then((d) => setGroups(((d as Record<string, unknown> | null)?.groups as DiscoveryGroup[]) ?? []))
        .catch(() => {});
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, selectedClient, assetOffset, assetTypeFilter, vulnSeverityFilter, vulnCategoryFilter, vulnsOffset, changesDays,
      fetchAssets, fetchVulns, fetchChanges, fetchDarkweb]);

  // ── Actions ───────────────────────────────────────────────────────────────

  const createClient = async () => {
    if (!ncName.trim()) return;
    try {
      const created = await apiFetchJSON("/api/v1/asm/clients", {
        method: "POST",
        body: JSON.stringify({
          name: ncName,
          industry: ncIndustry || null,
          country_code: ncCountry || null,
          description: ncDesc || null,
          asset_owner: ncOwner || null,
          business_unit: ncBU || null,
          contact_email: ncEmail || null,
          scan_interval_minutes: ncInterval,
        }),
      }) as ASMClient | null;
      if (!created) throw new Error("No response from server");
      setClients((p) => [created, ...p]);
      setShowNewClient(false);
      setNcName(""); setNcIndustry(""); setNcCountry(""); setNcDesc("");
      setNcOwner(""); setNcBU(""); setNcEmail(""); setNcInterval(1440);
      setSelectedClient(created);
      toast("success", `Client "${created.name}" created`);
    } catch (e) {
      toast("error", `Failed to create client: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const saveClient = async () => {
    if (!selectedClient || !ecName.trim()) return;
    try {
      const updated = await apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: ecName,
          industry: ecIndustry || null,
          country_code: ecCountry || null,
          description: ecDesc || null,
          asset_owner: ecOwner || null,
          business_unit: ecBU || null,
          contact_email: ecEmail || null,
          scan_interval_minutes: ecInterval,
        }),
      }) as ASMClient | null;
      if (!updated) throw new Error("No response");
      setSelectedClient(updated);
      setClients((p) => p.map((c) => c.id === updated.id ? updated : c));
      setShowEditClient(false);
      toast("success", "Client updated");
    } catch (e) {
      toast("error", `Update failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const deleteClient = async () => {
    if (!selectedClient) return;
    try {
      await apiFetch(`/api/v1/asm/clients/${selectedClient.id}`, { method: "DELETE" });
      setClients((p) => p.filter((c) => c.id !== selectedClient.id));
      setSelectedClient(null); setSummary(null); setShowDeleteConfirm(false);
      toast("success", "Client deleted");
    } catch (e) {
      toast("error", `Delete failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const createGroup = async () => {
    if (!selectedClient || !ngName.trim()) return;
    const validSeeds = ngSeeds.filter((s) => s.value.trim());
    try {
      const grp = await apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}/groups`, {
        method: "POST",
        body: JSON.stringify({
          name: ngName,
          description: ngDesc || null,
          seeds: validSeeds.map((s) => ({ type: s.type, value: s.value.trim() })),
          include_subdomains: ngSubdomains,
          include_ports: ngPorts,
          include_ssl: ngSSL,
          include_whois: ngWhois,
          include_ct_logs: ngCT,
          include_http_checks: ngHttp,
          include_ti_enrich: ngTI,
          include_nuclei: false,
        }),
      }) as DiscoveryGroup | null;
      if (!grp) throw new Error("No response");
      setGroups((p) => [grp, ...p]);
      setShowNewGroup(false);
      setNgName(""); setNgDesc(""); setNgSeeds([{ type: "domain", value: "" }]);
      toast("success", `Group "${grp.name}" created`);
    } catch (e) {
      toast("error", `Failed to create group: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const saveGroup = async (group: DiscoveryGroup, patch: Partial<DiscoveryGroup>) => {
    if (!selectedClient) return;
    try {
      const updated = await apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}/groups/${group.id}`, {
        method: "PUT",
        body: JSON.stringify(patch),
      }) as DiscoveryGroup | null;
      if (!updated) throw new Error("No response");
      setGroups((p) => p.map((g) => g.id === updated.id ? updated : g));
      setShowEditGroup(null);
      toast("success", "Group updated");
    } catch (e) {
      toast("error", `Update failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const deleteGroup = async (groupId: number) => {
    if (!selectedClient) return;
    try {
      await apiFetch(`/api/v1/asm/clients/${selectedClient.id}/groups/${groupId}`, { method: "DELETE" });
      setGroups((p) => p.filter((g) => g.id !== groupId));
      toast("success", "Group deleted");
    } catch (e) {
      toast("error", `Delete failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const startScan = async () => {
    if (!selectedClient) return;
    setScanning(true); setScanJobId(null); setScanJobState("PENDING");
    try {
      const data = await apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}/discover`, { method: "POST" }) as Record<string, unknown> | null;
      if (!data) throw new Error("No response");
      const jobId = data.job_id as string;
      setScanJobId(jobId);
      toast("info", `Scan started — polling for results…`);
      // If it's a background (non-Celery) job, polling won't work; refresh after delay
      if (jobId.startsWith("bg-")) {
        setScanJobState("STARTED");
        setTimeout(() => {
          setScanning(false); setScanJobId(null); setScanJobState(null);
          toast("success", "Scan submitted (background task)");
          fetchClientData(selectedClient);
        }, 10000);
      }
    } catch (e) {
      setScanning(false); setScanJobId(null); setScanJobState(null);
      toast("error", `Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const runSecurityCheck = async () => {
    if (!secCheckDomain.trim()) return;
    setLoadingSecCheck(true); setSecPosture(null);
    try {
      const data = await apiFetchJSON(`/api/v1/asm/check/security/${encodeURIComponent(secCheckDomain.trim())}`) as SecurityPosture | null;
      setSecPosture(data);
      if (!data) toast("error", "Security check returned no data");
    } catch (e) {
      toast("error", `Check failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoadingSecCheck(false);
    }
  };

  const openEditClient = () => {
    if (!selectedClient) return;
    setEcName(selectedClient.name);
    setEcIndustry(selectedClient.industry ?? "");
    setEcCountry(selectedClient.country_code ?? "");
    setEcDesc(selectedClient.description ?? "");
    setEcOwner(selectedClient.asset_owner ?? "");
    setEcBU(selectedClient.business_unit ?? "");
    setEcEmail(selectedClient.contact_email ?? "");
    setEcInterval(selectedClient.scan_interval_minutes ?? 1440);
    setShowEditClient(true);
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex bg-gray-900 text-white" style={{ position: "absolute", inset: 0, overflow: "hidden" }}>
      <ToastContainer toasts={toasts} remove={removeToast} />

      {/* ── Client sidebar: fixed width, header pinned, list scrolls independently ── */}
      <div className="flex-shrink-0 bg-gray-800 border-r border-gray-700 flex flex-col" style={{ width: "16rem", height: "100%", overflow: "hidden" }}>
        <div className="p-4 border-b border-gray-700" style={{ flexShrink: 0 }}>
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Clients</h2>
            <button
              onClick={() => setShowNewClient(true)}
              className="text-blue-400 hover:text-blue-300 text-xs font-medium"
              title="Add new client"
            >
              + Add
            </button>
          </div>
        </div>
        <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
          {clients.length === 0 ? (
            <div className="p-6 text-center">
              <div className="text-3xl mb-2">🏢</div>
              <p className="text-xs text-gray-500 mb-3">No clients yet</p>
              <button
                onClick={() => setShowNewClient(true)}
                className="text-xs text-blue-400 hover:text-blue-300"
              >
                Add your first client →
              </button>
            </div>
          ) : (
            clients.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelectedClient(c)}
                className={`w-full text-left px-3 py-3 border-b border-gray-700/50 hover:bg-gray-700/40 transition-colors ${
                  selectedClient?.id === c.id ? "bg-gray-700/70 border-l-2 border-l-blue-500" : ""
                }`}
              >
                {/* Row 1: name + grade */}
                <div className="flex items-center justify-between gap-1">
                  <span className="text-sm font-semibold text-white truncate leading-tight">{c.name}</span>
                  <span className={`text-xs font-bold flex-shrink-0 px-1.5 py-0.5 rounded font-mono ${
                    c.risk_grade === "A" ? "bg-green-900/60 text-green-300" :
                    c.risk_grade === "B" ? "bg-blue-900/60 text-blue-300" :
                    c.risk_grade === "C" ? "bg-yellow-900/60 text-yellow-300" :
                    c.risk_grade === "D" ? "bg-orange-900/60 text-orange-300" :
                    c.risk_grade === "F" ? "bg-red-900/70 text-red-200" :
                    "bg-gray-700 text-gray-400"
                  }`}>{c.risk_grade || "?"}</span>
                </div>
                {/* Row 2: industry + country */}
                {(c.industry || c.country_code) && (
                  <div className="text-xs text-gray-500 mt-0.5 truncate">
                    {[c.industry, c.country_code].filter(Boolean).join(" · ")}
                  </div>
                )}
                {/* Row 3: risk score bar */}
                <div className="mt-1.5 flex items-center gap-2">
                  <div className="flex-1 bg-gray-700 rounded-full h-1">
                    <div className={`h-1 rounded-full transition-all ${riskBg(c.risk_score)}`}
                      style={{ width: `${Math.min(c.risk_score, 100)}%` }} />
                  </div>
                  <span className={`text-xs font-bold flex-shrink-0 ${riskColor(c.risk_score)}`}>
                    {Math.round(c.risk_score)}
                  </span>
                </div>
                {/* Row 4: finding severity pills */}
                <div className="mt-1.5 flex items-center gap-1 flex-wrap">
                  {c.critical_findings > 0 && (
                    <span className="text-xs bg-red-900/60 text-red-300 border border-red-700/50 px-1.5 py-0.5 rounded font-mono">
                      {c.critical_findings}C
                    </span>
                  )}
                  {c.high_findings > 0 && (
                    <span className="text-xs bg-orange-900/60 text-orange-300 border border-orange-700/50 px-1.5 py-0.5 rounded font-mono">
                      {c.high_findings}H
                    </span>
                  )}
                  {c.total_assets > 0 && (
                    <span className="text-xs text-gray-500 ml-auto">{c.total_assets} assets</span>
                  )}
                </div>
                {/* Row 5: port/ssl/TI indicators */}
                {(c.open_ports > 0 || c.ssl_issues > 0 || c.ti_hit_count > 0) && (
                  <div className="mt-1 flex items-center gap-2 text-xs text-gray-500">
                    {c.open_ports > 0 && <span title="Open ports">🔌 {c.open_ports}</span>}
                    {c.ssl_issues > 0 && <span title="SSL issues" className="text-yellow-600">⚠ SSL</span>}
                    {c.ti_hit_count > 0 && <span title="TI hits" className="text-red-500">🎯 TI</span>}
                    {!c.last_scan_at && <span className="text-gray-600 ml-auto">No scan</span>}
                  </div>
                )}
              </button>
            ))
          )}
        </div>
      </div>

      {/* ── Main area ────────────────────────────────────────────────────── */}
      <div className="flex flex-col" style={{ flex: 1, minWidth: 0, height: "100%", overflow: "hidden" }}>
        {!selectedClient ? (
          <div style={{ flex: 1, minHeight: 0 }} className="flex items-center justify-center">
            <div className="text-center max-w-md">
              <div className="text-7xl mb-4">🛡️</div>
              <h2 className="text-xl font-bold text-white mb-2">Attack Surface Management</h2>
              <p className="text-gray-400 text-sm mb-6">
                Monitor your clients&apos; external attack surface — domains, IPs, certificates, open ports,
                vulnerabilities, and security posture in one place.
              </p>
              <button
                onClick={() => setShowNewClient(true)}
                className="bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 px-6 rounded-lg transition-colors"
              >
                Add First Client
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Header */}
            <div className="bg-gray-800 border-b border-gray-700 px-6 py-4 flex-shrink-0">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3">
                    <h1 className="text-lg font-bold text-white">{selectedClient.name}</h1>
                    {selectedClient.country_code && (
                      <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{selectedClient.country_code}</span>
                    )}
                    {selectedClient.industry && (
                      <span className="text-xs text-gray-400">{selectedClient.industry}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                    <span>Scan: <span className="text-gray-300">{SCHEDULE_OPTIONS.find(s => s.minutes === selectedClient.scan_interval_minutes)?.label ?? selectedClient.scan_schedule}</span></span>
                    {selectedClient.last_scan_at && (
                      <span>Last: <span className="text-gray-300">{fmt(selectedClient.last_scan_at)}</span></span>
                    )}
                    {selectedClient.next_scan_at && selectedClient.scan_interval_minutes > 0 && (
                      <span>Next: <span className="text-gray-300">{fmtTs(selectedClient.next_scan_at)}</span></span>
                    )}
                    {scanning && scanJobState && (
                      <span className="flex items-center gap-1 text-blue-400">
                        <svg className="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                        </svg>
                        Scanning… ({scanJobState})
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    onClick={() => fetchClientData(selectedClient)}
                    className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-2.5 py-1.5 transition-colors"
                    title="Refresh"
                  >
                    ↻
                  </button>
                  <button
                    onClick={openEditClient}
                    className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-3 py-1.5 transition-colors"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => setShowDeleteConfirm(true)}
                    className="text-xs text-red-400 hover:text-red-300 border border-red-800 rounded px-3 py-1.5 transition-colors"
                  >
                    Delete
                  </button>
                  <button
                    onClick={startScan}
                    disabled={scanning || groups.filter((g) => g.is_active).length === 0}
                    className="bg-green-600 hover:bg-green-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium py-1.5 px-4 rounded-lg transition-colors"
                  >
                    {scanning ? "Scanning…" : "▶ Run Scan"}
                  </button>
                </div>
              </div>
            </div>

            {/* Tab bar */}
            <div className="bg-gray-800 border-b border-gray-700 px-6 flex gap-0 flex-shrink-0 overflow-x-auto">
              {(["overview", "assets", "vulns", "changes", "security", "darkweb", "groups"] as const).map((t) => {
                const labels: Record<typeof t, string> = {
                  overview: "Overview", assets: "Assets", vulns: "Findings",
                  changes: "Changes", security: "Security Posture", darkweb: "Dark Web", groups: "Discovery Groups"
                };
                const badges: Partial<Record<typeof t, number>> = {
                  assets: assetsTotal || undefined,
                  vulns: vulnsTotal || undefined,
                  darkweb: darkweb ? (darkweb.total_posts + darkweb.total_ioc_hits) || undefined : undefined,
                };
                return (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap transition-colors border-b-2 flex-shrink-0 ${
                      tab === t ? "border-blue-500 text-blue-400" : "border-transparent text-gray-400 hover:text-white"
                    }`}
                  >
                    {labels[t]}
                    {badges[t] ? (
                      <span className="ml-1.5 bg-gray-700 text-gray-300 text-xs rounded-full px-1.5">{badges[t]}</span>
                    ) : null}
                  </button>
                );
              })}
            </div>

            {/* Tab content — flex-1 with inline style guarantees it fills remaining height and scrolls */}
            <div ref={detailPaneRef} className="p-6" style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>

              {/* ── Overview ─────────────────────────────────────────────── */}
              {tab === "overview" && (
                <div className="space-y-5 max-w-5xl">
                  {loadingMain ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm py-8">
                      <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/>
                      <span>Loading…</span>
                    </div>
                  ) : summary ? (
                    <>
                      {/* ── Risk header ── */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
                        <div className="flex items-start gap-6 flex-wrap">
                          {/* Grade dial */}
                          <div className="flex flex-col items-center gap-1 flex-shrink-0">
                            <div className={`text-6xl font-black leading-none ${gradeColor(summary.risk_grade || "?")}`}>
                              {summary.risk_grade || "?"}
                            </div>
                            <div className="text-xs text-gray-500 uppercase tracking-wider">Risk Grade</div>
                          </div>
                          {/* Score bar */}
                          <div className="flex-1 min-w-48">
                            <div className="flex items-baseline justify-between mb-1">
                              <span className="text-xs text-gray-400">Risk Score</span>
                              <span className={`text-2xl font-bold ${riskColor(summary.risk_score ?? summary.average_risk_score)}`}>
                                {Math.round(summary.risk_score ?? summary.average_risk_score)}<span className="text-sm text-gray-500">/100</span>
                              </span>
                            </div>
                            <div className="w-full bg-gray-700 rounded-full h-3">
                              <div className={`h-3 rounded-full transition-all ${riskBg(summary.risk_score ?? summary.average_risk_score)}`}
                                style={{ width: `${Math.min(summary.risk_score ?? summary.average_risk_score, 100)}%` }} />
                            </div>
                            {/* Risk factors */}
                            {(summary.risk_factors || []).length > 0 && (
                              <ul className="mt-2 space-y-0.5">
                                {summary.risk_factors.map((f, i) => (
                                  <li key={i} className="text-xs text-gray-400 flex items-center gap-1.5">
                                    <span className="text-red-500 flex-shrink-0">▲</span>{f}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          {/* KEV + EPSS */}
                          <div className="flex flex-col gap-2 flex-shrink-0">
                            {summary.kev_count > 0 && (
                              <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-2 text-center">
                                <div className="text-lg font-bold text-red-300">{summary.kev_count}</div>
                                <div className="text-xs text-red-400">CISA KEV CVEs</div>
                              </div>
                            )}
                            {summary.exploitable_count > 0 && (
                              <div className="bg-orange-900/30 border border-orange-700/50 rounded-lg px-3 py-2 text-center">
                                <div className="text-lg font-bold text-orange-300">{summary.exploitable_count}</div>
                                <div className="text-xs text-orange-400">Exploitable</div>
                              </div>
                            )}
                            {summary.avg_epss > 0 && (
                              <div className="bg-gray-700/50 border border-gray-600 rounded-lg px-3 py-2 text-center">
                                <div className="text-lg font-bold text-white">{(summary.avg_epss * 100).toFixed(1)}%</div>
                                <div className="text-xs text-gray-400">Avg EPSS</div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* ── Stats grid ── */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <StatCard label="Total Assets" value={summary.total_assets} />
                        <StatCard label="Total Findings" value={summary.total_findings ?? summary.total_vulnerabilities ?? 0} />
                        <StatCard label="Open Ports" value={summary.total_open_ports} color={summary.total_open_ports > 10 ? "text-orange-400" : "text-white"} />
                        <StatCard label="SSL Issues" value={summary.ssl_issues} color={summary.ssl_issues > 0 ? "text-yellow-400" : "text-green-400"} />
                      </div>

                      {/* ── Finding severity breakdown ── */}
                      {Object.keys(summary.findings_by_severity || {}).length > 0 && (
                        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Findings by Severity</h3>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            {(["critical","high","medium","low"] as const).map((sev) => {
                              const count = (summary.findings_by_severity || {})[sev] ?? 0;
                              return (
                                <div key={sev} className={`rounded-lg p-3 border text-center ${
                                  sev === "critical" ? "bg-red-900/20 border-red-700/40" :
                                  sev === "high"     ? "bg-orange-900/20 border-orange-700/40" :
                                  sev === "medium"   ? "bg-yellow-900/20 border-yellow-700/40" :
                                                       "bg-blue-900/20 border-blue-700/40"
                                }`}>
                                  <div className={`text-2xl font-bold ${
                                    sev === "critical" ? "text-red-300" : sev === "high" ? "text-orange-300" :
                                    sev === "medium" ? "text-yellow-300" : "text-blue-300"
                                  }`}>{count}</div>
                                  <div className="text-xs text-gray-400 capitalize mt-0.5">{sev}</div>
                                  <button
                                    onClick={() => { setTab("vulns"); setVulnSeverityFilter(sev); }}
                                    className="text-xs text-gray-500 hover:text-blue-400 mt-1 transition-colors"
                                  >view →</button>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* ── Finding categories ── */}
                      {Object.keys(summary.findings_by_category || {}).length > 0 && (
                        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Finding Categories</h3>
                          <div className="space-y-2">
                            {Object.entries(summary.findings_by_category)
                              .sort(([,a],[,b]) => b - a)
                              .map(([cat, count]) => {
                                const total = Object.values(summary.findings_by_category).reduce((s, v) => s + v, 0);
                                const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                                const label: Record<string, string> = {
                                  cve: "CVE Vulnerability", ssl: "SSL/TLS Issue",
                                  http_header: "Missing Security Header", port: "Exposed Port",
                                  ti_hit: "Threat Intel Hit", email_security: "Email Security",
                                  dns_takeover: "DNS Takeover", misconfiguration: "Misconfiguration",
                                  credential_leak: "Credential Leak", darkweb_mention: "Dark Web Mention",
                                  brand_impersonation: "Brand Impersonation",
                                };
                                return (
                                  <div key={cat} className="flex items-center gap-3">
                                    <span className="text-xs text-gray-400 w-44 flex-shrink-0 truncate">{label[cat] ?? cat}</span>
                                    <div className="flex-1 bg-gray-700 rounded-full h-2">
                                      <div className="h-2 bg-blue-500 rounded-full" style={{ width: `${pct}%` }} />
                                    </div>
                                    <span className="text-xs text-gray-300 w-6 text-right flex-shrink-0">{count}</span>
                                  </div>
                                );
                              })}
                          </div>
                        </div>
                      )}

                      {/* ── Cross-dataset threat intelligence ── */}
                      {((summary.brand_exposures ?? 0) > 0 || (summary.credential_leaks ?? 0) > 0 || (summary.country_indicator_count ?? 0) > 0 || summary.region_risk) && (
                        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Platform Threat Intelligence</h3>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            {(summary.brand_exposures ?? 0) > 0 && (
                              <div className="bg-purple-900/20 border border-purple-700/40 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-purple-300">{summary.brand_exposures}</div>
                                <div className="text-xs text-gray-400 mt-0.5">Brand Exposures</div>
                              </div>
                            )}
                            {(summary.credential_leaks ?? 0) > 0 && (
                              <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-red-300">{summary.credential_leaks}</div>
                                <div className="text-xs text-gray-400 mt-0.5">Credential Leaks</div>
                              </div>
                            )}
                            {(summary.country_indicator_count ?? 0) > 0 && (
                              <div className="bg-orange-900/20 border border-orange-700/40 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-orange-300">{summary.country_indicator_count}</div>
                                <div className="text-xs text-gray-400 mt-0.5">Country Indicators ({summary.country_code})</div>
                              </div>
                            )}
                            {summary.region_risk && (
                              <div className="bg-gray-700/50 border border-gray-600 rounded-lg p-3 text-center">
                                <div className="text-2xl font-bold text-white">{Math.round(summary.region_risk.overall_risk)}</div>
                                <div className="text-xs text-gray-400 mt-0.5">Regional Risk</div>
                              </div>
                            )}
                          </div>
                          {summary.region_risk && (
                            <div className="mt-3 grid grid-cols-3 gap-2">
                              {[
                                { label: "C2", value: summary.region_risk.c2_risk, count: summary.region_risk.c2_count, color: "text-red-400" },
                                { label: "Exfil", value: summary.region_risk.exfil_risk, count: summary.region_risk.exfil_count, color: "text-orange-400" },
                                { label: "Phishing", value: summary.region_risk.phishing_risk, count: summary.region_risk.phishing_count, color: "text-yellow-400" },
                              ].map(({ label, value, count, color }) => (
                                <div key={label} className="bg-gray-700/30 rounded p-2 text-center">
                                  <div className={`text-sm font-bold ${color}`}>{Math.round(value)}</div>
                                  <div className="text-xs text-gray-500">{label} risk</div>
                                  <div className="text-xs text-gray-600">{count} IOCs</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* ── Asset type breakdown ── */}
                      {Object.keys(summary.by_type || {}).length > 0 && (
                        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Asset Inventory</h3>
                          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                            {Object.entries(summary.by_type).map(([type, count]) => (
                              <button
                                key={type}
                                onClick={() => { setTab("assets"); setAssetTypeFilter(type); }}
                                className="bg-gray-700/50 hover:bg-gray-700 rounded-lg p-3 text-center transition-colors"
                              >
                                <div className="text-2xl mb-1">{assetIcon(type)}</div>
                                <div className="text-lg font-bold text-white">{count}</div>
                                <div className="text-xs text-gray-400 capitalize">{type}</div>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {groups.filter((g) => g.is_active).length === 0 && (
                        <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-lg p-4 flex items-center justify-between">
                          <div>
                            <p className="text-yellow-300 font-medium text-sm">No active discovery groups</p>
                            <p className="text-yellow-600 text-xs mt-1">Add domain seeds to start discovering assets.</p>
                          </div>
                          <button onClick={() => { setTab("groups"); setShowNewGroup(true); }}
                            className="bg-yellow-600 hover:bg-yellow-500 text-white text-xs font-medium py-1.5 px-3 rounded flex-shrink-0">
                            Add Seeds
                          </button>
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="text-gray-500 text-sm py-8 text-center">No scan data yet. Run a scan to populate this dashboard.</div>
                  )}
                </div>
              )}

              {/* ── Assets ───────────────────────────────────────────────── */}
              {tab === "assets" && (
                <div className="space-y-4">
                  <div className="flex gap-2 flex-wrap items-center">
                    <input
                      type="text" placeholder="Search assets…" value={assetSearch}
                      onChange={(e) => setAssetSearch(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter" && selectedClient) fetchAssets(selectedClient.id, 0, assetTypeFilter, assetSearch); }}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-400 w-56 focus:outline-none focus:border-blue-500"
                    />
                    <select value={assetTypeFilter}
                      onChange={(e) => { setAssetTypeFilter(e.target.value); setAssetOffset(0); }}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
                      <option value="all">All types</option>
                      {["domain","subdomain","ip","port","certificate","service"].map((t) => (
                        <option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>
                      ))}
                    </select>
                    <button
                      onClick={() => selectedClient && fetchAssets(selectedClient.id, assetOffset, assetTypeFilter, assetSearch)}
                      className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-3 py-1.5">
                      Search
                    </button>
                    <span className="text-xs text-gray-400 ml-auto">{assetsTotal} total</span>
                  </div>

                  {loadingTab ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm py-8"><div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/><span>Loading assets…</span></div>
                  ) : assets.length === 0 ? (
                    <div className="text-gray-500 text-sm py-8 text-center">No assets found. Run a scan to discover assets.</div>
                  ) : (
                    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-700/50 text-xs text-gray-400 uppercase">
                          <tr>
                            <th className="px-4 py-3 text-left">Asset</th>
                            <th className="px-4 py-3 text-left">Type</th>
                            <th className="px-4 py-3 text-left">Status</th>
                            <th className="px-4 py-3 text-left w-32">Risk</th>
                            <th className="px-4 py-3 text-left">Tags</th>
                            <th className="px-4 py-3 text-left">Last Seen</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-700/50">
                          {assets.map((a) => (
                            <tr key={a.id} className="hover:bg-gray-700/30 transition-colors">
                              <td className="px-4 py-2.5 font-mono text-xs text-blue-300 max-w-xs truncate">{a.value}</td>
                              <td className="px-4 py-2.5">
                                <span className="flex items-center gap-1 text-xs text-gray-300">{assetIcon(a.type ?? "")} {a.type ?? "unknown"}</span>
                              </td>
                              <td className="px-4 py-2.5">
                                <span className={`text-xs px-2 py-0.5 rounded-full ${
                                  a.status === "active" ? "bg-green-900/50 text-green-300" :
                                  a.status === "vulnerable" ? "bg-red-900/50 text-red-300" :
                                  "bg-gray-700 text-gray-400"}`}>
                                  {a.status ?? "unknown"}
                                </span>
                              </td>
                              <td className="px-4 py-2.5">
                                <div className="flex items-center gap-2">
                                  <div className="w-16 bg-gray-700 rounded-full h-1.5">
                                    <div className={`h-1.5 rounded-full ${riskBg(a.risk_score)}`} style={{ width: `${a.risk_score}%` }} />
                                  </div>
                                  <span className={`text-xs font-medium ${riskColor(a.risk_score)}`}>{Math.round(a.risk_score)}</span>
                                </div>
                              </td>
                              <td className="px-4 py-2.5">
                                <div className="flex gap-1 flex-wrap">
                                  {(a.tags ?? []).slice(0, 2).map((tag) => (
                                    <span key={tag} className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{tag}</span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-2.5 text-xs text-gray-500">{fmt(a.last_seen)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {assetsTotal > ASSET_LIMIT && (
                    <div className="flex items-center justify-between">
                      <button disabled={assetOffset === 0}
                        onClick={() => setAssetOffset(Math.max(0, assetOffset - ASSET_LIMIT))}
                        className="text-xs text-gray-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-gray-600 rounded">
                        ← Prev
                      </button>
                      <span className="text-xs text-gray-400">{assetOffset + 1}–{Math.min(assetOffset + ASSET_LIMIT, assetsTotal)} of {assetsTotal}</span>
                      <button disabled={assetOffset + ASSET_LIMIT >= assetsTotal}
                        onClick={() => setAssetOffset(assetOffset + ASSET_LIMIT)}
                        className="text-xs text-gray-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-gray-600 rounded">
                        Next →
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* ── Findings ─────────────────────────────────────────────── */}
              {tab === "vulns" && (
                <div className="space-y-3">
                  {/* Filter bar */}
                  <div className="flex gap-2 items-center flex-wrap">
                    <input
                      type="text" placeholder="Search findings…" value={vulnSearch}
                      onChange={(e) => setVulnSearch(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter" && selectedClient) fetchVulns(selectedClient.id, vulnSeverityFilter, vulnCategoryFilter, vulnSearch, 0); }}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white placeholder-gray-400 w-48 focus:outline-none focus:border-blue-500"
                    />
                    <select value={vulnSeverityFilter}
                      onChange={(e) => { setVulnSeverityFilter(e.target.value); if (selectedClient) fetchVulns(selectedClient.id, e.target.value, vulnCategoryFilter, vulnSearch, 0); }}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
                      <option value="all">All severities</option>
                      {["critical","high","medium","low","info"].map((s) => (
                        <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
                      ))}
                    </select>
                    <select value={vulnCategoryFilter}
                      onChange={(e) => { setVulnCategoryFilter(e.target.value); if (selectedClient) fetchVulns(selectedClient.id, vulnSeverityFilter, e.target.value, vulnSearch, 0); }}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
                      <option value="all">All categories</option>
                      {[
                        ["cve","CVE / Vulnerability"],["ssl","SSL/TLS"],["http_header","HTTP Headers"],
                        ["port","Exposed Port"],["ti_hit","Threat Intel Hit"],
                        ["email_security","Email Security"],["dns_takeover","DNS Takeover"],
                        ["misconfiguration","Misconfiguration"],
                        ["credential_leak","Credential Leak"],
                        ["darkweb_mention","Dark Web Mention"],
                        ["brand_impersonation","Brand Impersonation"],
                      ].map(([v,l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                    <button onClick={() => selectedClient && fetchVulns(selectedClient.id, vulnSeverityFilter, vulnCategoryFilter, vulnSearch, 0)}
                      className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-3 py-1.5">↻ Refresh</button>
                    <span className="text-xs text-gray-400 ml-auto">{vulnsTotal} finding{vulnsTotal !== 1 ? "s" : ""}</span>
                  </div>

                  {loadingTab ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm py-8">
                      <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/>
                      <span>Loading findings…</span>
                    </div>
                  ) : vulns.length === 0 ? (
                    <div className="text-gray-500 text-sm py-8 text-center">No findings match the current filters.</div>
                  ) : (
                    <>
                      {/* Table */}
                      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                        <table className="w-full text-sm">
                          <thead className="bg-gray-900 text-xs text-gray-400 uppercase sticky top-0 z-10">
                            <tr>
                              <th className="px-4 py-3 text-left w-20">Severity</th>
                              <th className="px-4 py-3 text-left">Finding</th>
                              <th className="px-4 py-3 text-left">Category</th>
                              <th className="px-4 py-3 text-left">Affected Asset</th>
                              <th className="px-4 py-3 text-left">CVE / Score</th>
                              <th className="px-4 py-3 text-left">Detected</th>
                              <th className="px-4 py-3 text-left w-8"></th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-700/50">
                            {vulns.map((v) => (
                              <tr
                                key={v.id}
                                onClick={() => setSelectedFinding(v)}
                                className="hover:bg-gray-700/40 cursor-pointer transition-colors group"
                              >
                                {/* Severity */}
                                <td className="px-4 py-2.5">
                                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${severityColor(v.severity ?? "info")}`}>
                                    {(v.severity ?? "info").toUpperCase()}
                                  </span>
                                </td>
                                {/* Title + badges */}
                                <td className="px-4 py-2.5 max-w-xs">
                                  <div className="text-sm font-medium text-white truncate">{v.title}</div>
                                  <div className="flex gap-1 mt-0.5 flex-wrap">
                                    {v.is_cisa_kev && (
                                      <span className="text-xs bg-red-900/60 text-red-300 border border-red-700/50 px-1.5 py-0 rounded font-semibold">KEV</span>
                                    )}
                                    {v.is_exploitable && (
                                      <span className="text-xs bg-orange-900/50 text-orange-300 border border-orange-700/50 px-1.5 py-0 rounded">⚡ Exploit</span>
                                    )}
                                  </div>
                                </td>
                                {/* Category */}
                                <td className="px-4 py-2.5">
                                  <span className="text-xs bg-gray-700 text-gray-300 border border-gray-600 px-2 py-0.5 rounded capitalize">
                                    {(v.category ?? "unknown").replace(/_/g, " ")}
                                  </span>
                                </td>
                                {/* Asset */}
                                <td className="px-4 py-2.5 max-w-[160px]">
                                  <div className="font-mono text-xs text-blue-300 truncate" title={v.asset_value || v.affected_asset_value}>{v.asset_value || v.affected_asset_value}</div>
                                  <div className="text-xs text-gray-500 capitalize">{v.asset_type || v.affected_asset_type}</div>
                                </td>
                                {/* CVE + CVSS + EPSS */}
                                <td className="px-4 py-2.5">
                                  {v.cve_id ? (
                                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer"
                                      onClick={(e) => e.stopPropagation()}
                                      className="text-xs text-blue-400 hover:text-blue-300 font-mono block">{v.cve_id}</a>
                                  ) : null}
                                  {v.cvss_score != null && (
                                    <span className="text-xs text-gray-400">CVSS {v.cvss_score}</span>
                                  )}
                                  {v.epss_score != null && v.epss_score > 0 && (
                                    <span className={`text-xs ml-1 ${v.epss_score > 0.5 ? "text-red-400" : v.epss_score > 0.1 ? "text-orange-400" : "text-gray-500"}`}>
                                      {(v.epss_score * 100).toFixed(1)}% EPSS
                                    </span>
                                  )}
                                </td>
                                {/* Detected */}
                                <td className="px-4 py-2.5 text-xs text-gray-500 whitespace-nowrap">{fmt(v.first_seen || v.detected_at || null)}</td>
                                {/* Arrow */}
                                <td className="px-4 py-2.5 text-gray-600 group-hover:text-gray-300 transition-colors">›</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {/* Pagination */}
                      {vulnsTotal > VULN_LIMIT && (
                        <div className="flex items-center justify-between">
                          <button disabled={vulnsOffset === 0}
                            onClick={() => selectedClient && fetchVulns(selectedClient.id, vulnSeverityFilter, vulnCategoryFilter, vulnSearch, Math.max(0, vulnsOffset - VULN_LIMIT))}
                            className="text-xs text-gray-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-gray-600 rounded">
                            ← Prev
                          </button>
                          <span className="text-xs text-gray-400">
                            {vulnsOffset + 1}–{Math.min(vulnsOffset + VULN_LIMIT, vulnsTotal)} of {vulnsTotal}
                          </span>
                          <button disabled={vulnsOffset + VULN_LIMIT >= vulnsTotal}
                            onClick={() => selectedClient && fetchVulns(selectedClient.id, vulnSeverityFilter, vulnCategoryFilter, vulnSearch, vulnsOffset + VULN_LIMIT)}
                            className="text-xs text-gray-400 hover:text-white disabled:opacity-30 px-3 py-1.5 border border-gray-600 rounded">
                            Next →
                          </button>
                        </div>
                      )}
                    </>
                  )}

                  {/* ── Finding detail drawer ── */}
                  {selectedFinding && (
                    <div className="fixed inset-0 z-50 flex" onClick={() => setSelectedFinding(null)}>
                      {/* Backdrop */}
                      <div className="flex-1 bg-black/60" />
                      {/* Drawer */}
                      <div
                        className="w-full max-w-xl bg-gray-900 border-l border-gray-700 overflow-y-auto flex flex-col shadow-2xl"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {/* Drawer header */}
                        <div className="flex items-start justify-between p-5 border-b border-gray-700 flex-shrink-0">
                          <div className="flex-1 min-w-0 pr-3">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${severityColor(selectedFinding.severity ?? "info")}`}>
                                {(selectedFinding.severity ?? "info").toUpperCase()}
                              </span>
                              {selectedFinding.is_cisa_kev && (
                                <span className="text-xs bg-red-900/60 text-red-300 border border-red-700/50 px-2 py-0.5 rounded font-semibold">CISA KEV</span>
                              )}
                              {selectedFinding.is_exploitable && (
                                <span className="text-xs bg-orange-900/50 text-orange-300 border border-orange-700/50 px-2 py-0.5 rounded">⚡ Exploitable</span>
                              )}
                              <span className="text-xs bg-gray-700 text-gray-300 border border-gray-600 px-2 py-0.5 rounded capitalize">
                                {(selectedFinding.category ?? "unknown").replace(/_/g, " ")}
                              </span>
                            </div>
                            <h2 className="text-base font-bold text-white leading-snug">{selectedFinding.title}</h2>
                          </div>
                          <button onClick={() => setSelectedFinding(null)}
                            className="flex-shrink-0 text-gray-500 hover:text-white transition-colors text-lg leading-none">✕</button>
                        </div>

                        {/* Drawer body */}
                        <div className="flex-1 p-5 space-y-5 overflow-y-auto">

                          {/* Affected asset */}
                          <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
                            <div className="text-xs text-gray-400 uppercase tracking-wider mb-1">Affected Asset</div>
                            <div className="font-mono text-sm text-blue-300 break-all">{selectedFinding.asset_value || selectedFinding.affected_asset_value || "—"}</div>
                            <div className="text-xs text-gray-500 capitalize mt-0.5">{selectedFinding.asset_type || selectedFinding.affected_asset_type}</div>
                          </div>

                          {/* Description */}
                          <div>
                            <div className="text-xs text-gray-400 uppercase tracking-wider mb-1.5">Description</div>
                            <p className="text-sm text-gray-300 leading-relaxed">{selectedFinding.description || "No description available."}</p>
                          </div>

                          {/* CVE / Scoring */}
                          {(selectedFinding.cve_id || selectedFinding.cvss_score != null || (selectedFinding.epss_score != null && selectedFinding.epss_score > 0)) && (
                            <div className="grid grid-cols-3 gap-3">
                              {selectedFinding.cve_id && (
                                <a href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`} target="_blank" rel="noreferrer"
                                  className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-3 text-center hover:bg-blue-900/30 transition-colors">
                                  <div className="text-sm font-bold text-blue-300 font-mono">{selectedFinding.cve_id}</div>
                                  <div className="text-xs text-gray-400 mt-0.5">NVD ↗</div>
                                </a>
                              )}
                              {selectedFinding.cvss_score != null && (
                                <div className={`rounded-lg p-3 text-center border ${selectedFinding.cvss_score >= 9 ? "bg-red-900/20 border-red-700/40" : selectedFinding.cvss_score >= 7 ? "bg-orange-900/20 border-orange-700/40" : "bg-yellow-900/20 border-yellow-700/40"}`}>
                                  <div className={`text-xl font-bold ${selectedFinding.cvss_score >= 9 ? "text-red-300" : selectedFinding.cvss_score >= 7 ? "text-orange-300" : "text-yellow-300"}`}>{selectedFinding.cvss_score}</div>
                                  <div className="text-xs text-gray-400">CVSS Score</div>
                                </div>
                              )}
                              {selectedFinding.epss_score != null && selectedFinding.epss_score > 0 && (
                                <div className={`rounded-lg p-3 text-center border ${selectedFinding.epss_score > 0.5 ? "bg-red-900/20 border-red-700/40" : selectedFinding.epss_score > 0.1 ? "bg-orange-900/20 border-orange-700/40" : "bg-gray-700/50 border-gray-600"}`}>
                                  <div className={`text-xl font-bold ${selectedFinding.epss_score > 0.5 ? "text-red-300" : selectedFinding.epss_score > 0.1 ? "text-orange-300" : "text-gray-300"}`}>
                                    {(selectedFinding.epss_score * 100).toFixed(1)}%
                                  </div>
                                  <div className="text-xs text-gray-400">EPSS (exploit probability)</div>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Remediation */}
                          {selectedFinding.remediation && (
                            <div className="bg-green-900/15 border border-green-700/30 rounded-lg p-3">
                              <div className="text-xs text-green-400 uppercase tracking-wider mb-1.5 font-semibold">Recommended Fix</div>
                              <p className="text-sm text-green-200 leading-relaxed">{selectedFinding.remediation}</p>
                            </div>
                          )}

                          {/* Metadata grid */}
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {[
                              { label: "Source", value: selectedFinding.source },
                              { label: "Status", value: selectedFinding.status },
                              { label: "First Seen", value: fmt(selectedFinding.first_seen || selectedFinding.detected_at || null) },
                              { label: "Last Seen", value: fmt(selectedFinding.last_seen || selectedFinding.detected_at || null) },
                            ].map(({ label, value }) => value ? (
                              <div key={label} className="bg-gray-800 rounded p-2">
                                <div className="text-gray-500">{label}</div>
                                <div className="text-gray-200 font-medium mt-0.5 capitalize">{value}</div>
                              </div>
                            ) : null)}
                          </div>

                          {/* References */}
                          {selectedFinding.references && Array.isArray(selectedFinding.references) && selectedFinding.references.length > 0 && (
                            <div>
                              <div className="text-xs text-gray-400 uppercase tracking-wider mb-1.5">References</div>
                              <ul className="space-y-1">
                                {(selectedFinding.references as string[]).map((ref, i) => (
                                  <li key={i}>
                                    <a href={ref} target="_blank" rel="noreferrer"
                                      className="text-xs text-blue-400 hover:text-blue-300 break-all">{ref}</a>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>

                        {/* Drawer footer — status actions */}
                        <div className="flex-shrink-0 p-4 border-t border-gray-700 flex gap-2 flex-wrap">
                          <span className="text-xs text-gray-500 self-center mr-1">Mark as:</span>
                          {(["open","accepted","remediated"] as const).map((s) => (
                            <button key={s}
                              onClick={async () => {
                                if (!selectedClient) return;
                                await apiFetchJSON(`/api/v1/asm/clients/${selectedClient.id}/findings/${selectedFinding.id}/status?new_status=${s}`, { method: "PATCH" });
                                setSelectedFinding({ ...selectedFinding, status: s });
                                setVulns((prev) => prev.map((v) => v.id === selectedFinding.id ? { ...v, status: s } : v));
                              }}
                              className={`text-xs px-3 py-1.5 rounded border transition-colors capitalize ${
                                selectedFinding.status === s
                                  ? "bg-blue-600 border-blue-500 text-white"
                                  : "bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600"
                              }`}
                            >
                              {s}
                            </button>
                          ))}
                          <button onClick={() => setSelectedFinding(null)}
                            className="ml-auto text-xs px-3 py-1.5 rounded border border-gray-600 text-gray-400 hover:text-white hover:border-gray-500 transition-colors">
                            Close
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── Changes ──────────────────────────────────────────────── */}
              {tab === "changes" && (
                <div className="space-y-4">
                  <div className="flex gap-2 items-center flex-wrap">
                    <select value={changesDays}
                      onChange={(e) => setChangesDays(Number(e.target.value))}
                      className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
                      <option value={7}>Last 7 days</option>
                      <option value={30}>Last 30 days</option>
                      <option value={90}>Last 90 days</option>
                    </select>
                    <button onClick={() => selectedClient && fetchChanges(selectedClient.id, changesDays)}
                      className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-3 py-1.5">↻ Refresh</button>
                    <span className="text-xs text-gray-400 ml-auto">{changes.length} events</span>
                  </div>

                  {loadingTab ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm py-8"><div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/><span>Loading…</span></div>
                  ) : changes.length === 0 ? (
                    <div className="text-gray-500 text-sm py-8 text-center">No changes recorded in this period.</div>
                  ) : (
                    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-700/50 text-xs text-gray-400 uppercase">
                          <tr>
                            <th className="px-4 py-3 text-left">Asset</th>
                            <th className="px-4 py-3 text-left">Change</th>
                            <th className="px-4 py-3 text-left">Old</th>
                            <th className="px-4 py-3 text-left">New</th>
                            <th className="px-4 py-3 text-left">Detected</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-700/50">
                          {changes.map((c) => (
                            <tr key={c.id} className="hover:bg-gray-700/30">
                              <td className="px-4 py-2.5 font-mono text-xs text-blue-300 max-w-xs truncate">{c.asset_value}</td>
                              <td className="px-4 py-2.5">
                                <span className={`text-xs px-2 py-0.5 rounded-full ${
                                  c.change_type === "new" ? "bg-green-900/50 text-green-300" :
                                  c.change_type === "removed" ? "bg-red-900/50 text-red-300" :
                                  (c.change_type ?? "").includes("open") ? "bg-orange-900/50 text-orange-300" :
                                  "bg-gray-700 text-gray-300"}`}>
                                   {(c.change_type ?? "unknown").replace(/_/g, " ")}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-xs text-gray-500 font-mono truncate max-w-xs">{c.old_value ?? "—"}</td>
                              <td className="px-4 py-2.5 text-xs text-gray-300 font-mono truncate max-w-xs">{c.new_value ?? "—"}</td>
                              <td className="px-4 py-2.5 text-xs text-gray-500 whitespace-nowrap">{fmtTs(c.detected_at)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* ── Dark Web ─────────────────────────────────────────────── */}
              {tab === "darkweb" && (
                <div className="space-y-4 max-w-5xl">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-gray-400">Correlated against:</span>
                    {(darkweb?.terms ?? []).slice(0, 12).map((t) => (
                      <span key={t} className="text-xs px-2 py-0.5 rounded-full bg-purple-900/40 text-purple-200 border border-purple-700/50">{t}</span>
                    ))}
                    {!darkweb?.watchlist_id && (
                      <span className="text-xs text-gray-500 italic">no linked watchlist — using client name + domains only</span>
                    )}
                    <button onClick={() => selectedClient && fetchDarkweb(selectedClient.id)}
                      className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-3 py-1.5 ml-auto">↻ Refresh</button>
                  </div>

                  {loadingTab ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm py-8"><div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/><span>Searching dark-web sources…</span></div>
                  ) : (!darkweb || (darkweb.posts.length === 0 && darkweb.ioc_hits.length === 0)) ? (
                    <div className="text-gray-500 text-sm py-8 text-center border border-gray-700 rounded-lg bg-gray-800/40">
                      No dark-web mentions or threat-intel hits matched this client&apos;s terms yet.
                      <div className="text-xs text-gray-600 mt-1">Dark-web crawls run on the watchlist schedule; results appear here once a crawl matches.</div>
                    </div>
                  ) : (
                    <>
                      {/* Crawled dark-web posts — full content */}
                      {darkweb.posts.length > 0 && (
                        <div className="space-y-3">
                          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                            Dark-Web Crawl Results
                            <span className="bg-gray-700 text-gray-300 text-xs rounded-full px-2 py-0.5">{darkweb.total_posts}</span>
                          </h3>
                          {darkweb.posts.map((p) => (
                            <div key={p._id ?? p.url} className="bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-2">
                              <div className="flex items-start justify-between gap-3">
                                <div className="font-medium text-white text-sm">{p.title || "(untitled)"}</div>
                                <div className="flex items-center gap-2 flex-shrink-0">
                                  {p.severity && (
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                                      p.severity === "critical" ? "bg-red-900/60 text-red-200" :
                                      p.severity === "high" ? "bg-orange-900/60 text-orange-200" :
                                      p.severity === "medium" ? "bg-yellow-900/50 text-yellow-200" :
                                      "bg-gray-700 text-gray-300"}`}>{p.severity}</span>
                                  )}
                                  <span className="text-xs text-gray-500 whitespace-nowrap">{fmtTs(p.discovered_at ?? null)}</span>
                                </div>
                              </div>
                              {p.body_text && (
                                <p className="text-sm text-gray-300 whitespace-pre-wrap break-words">{p.body_text}</p>
                              )}
                              {p.url && (
                                <div className="text-xs font-mono text-blue-300 break-all bg-gray-900/60 rounded px-2 py-1.5">{p.url}</div>
                              )}
                              {(p.onion_links?.length || p.emails_found?.length || p.domains_found?.length || p.ips_found?.length) ? (
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-xs">
                                  {(p.onion_links ?? []).length > 0 && (
                                    <div><span className="text-gray-500">Onion links: </span><span className="font-mono text-purple-300 break-all">{(p.onion_links ?? []).join(", ")}</span></div>
                                  )}
                                  {(p.emails_found ?? []).length > 0 && (
                                    <div><span className="text-gray-500">Emails: </span><span className="font-mono text-red-300 break-all">{(p.emails_found ?? []).join(", ")}</span></div>
                                  )}
                                  {(p.domains_found ?? []).length > 0 && (
                                    <div><span className="text-gray-500">Domains: </span><span className="font-mono text-gray-300 break-all">{(p.domains_found ?? []).join(", ")}</span></div>
                                  )}
                                  {(p.ips_found ?? []).length > 0 && (
                                    <div><span className="text-gray-500">IPs: </span><span className="font-mono text-gray-300 break-all">{(p.ips_found ?? []).join(", ")}</span></div>
                                  )}
                                </div>
                              ) : null}
                              <div className="flex items-center gap-2 flex-wrap pt-1">
                                {p.source && <span className="text-xs px-2 py-0.5 rounded bg-gray-700/70 text-gray-300">{p.source}</span>}
                                {p.crawl_query && <span className="text-xs text-gray-500">matched query: <span className="text-gray-400">{p.crawl_query}</span></span>}
                                {(p.tags ?? []).map((tg) => (
                                  <span key={tg} className="text-xs px-1.5 py-0.5 rounded bg-purple-900/30 text-purple-300">{tg}</span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Threat-intel indicators referencing the client's domains */}
                      {darkweb.ioc_hits.length > 0 && (
                        <div className="space-y-2">
                          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
                            Threat-Intel Indicators
                            <span className="bg-gray-700 text-gray-300 text-xs rounded-full px-2 py-0.5">{darkweb.total_ioc_hits}</span>
                          </h3>
                          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                            <table className="w-full text-sm">
                              <thead className="bg-gray-700/50 text-xs text-gray-400 uppercase">
                                <tr>
                                  <th className="px-4 py-3 text-left">Indicator</th>
                                  <th className="px-4 py-3 text-left">Type</th>
                                  <th className="px-4 py-3 text-left">Threat</th>
                                  <th className="px-4 py-3 text-left">Source</th>
                                  <th className="px-4 py-3 text-left">Last Seen</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-gray-700/50">
                                {darkweb.ioc_hits.map((h) => (
                                  <tr key={h._id ?? h.indicator} className="hover:bg-gray-700/30">
                                    <td className="px-4 py-2.5 font-mono text-xs text-blue-300 break-all max-w-md">{h.indicator}</td>
                                    <td className="px-4 py-2.5 text-xs text-gray-400">{h.indicator_type ?? "—"}</td>
                                    <td className="px-4 py-2.5 text-xs text-gray-300">{h.threat_type ?? "—"}</td>
                                    <td className="px-4 py-2.5 text-xs text-gray-400">{h.source ?? "—"}</td>
                                    <td className="px-4 py-2.5 text-xs text-gray-500 whitespace-nowrap">{fmtTs(h.last_seen ?? null)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}

              {/* ── Security Posture ─────────────────────────────────────── */}
              {tab === "security" && (
                <div className="space-y-5 max-w-3xl">
                  <div>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">Security Posture Check</h3>
                    <p className="text-xs text-gray-400 mb-3">
                      Checks email security (SPF/DKIM/DMARC), DNS takeover risk, SSL/TLS quality, and HTTP security headers.
                    </p>
                    <div className="flex gap-2">
                      <input
                        type="text" value={secCheckDomain}
                        onChange={(e) => setSecCheckDomain(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") runSecurityCheck(); }}
                        placeholder="Enter domain e.g. safaricom.co.ke"
                        className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                      />
                      <button
                        onClick={runSecurityCheck}
                        disabled={loadingSecCheck || !secCheckDomain.trim()}
                        className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors flex-shrink-0"
                      >
                        {loadingSecCheck ? "Checking…" : "Run Check"}
                      </button>
                    </div>
                  </div>

                  {loadingSecCheck && (
                    <div className="flex items-center gap-2 text-blue-400 text-sm">
                      <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"/>
                      Checking security posture for <strong>{secCheckDomain}</strong>…
                    </div>
                  )}

                  {secPosture && (
                    <div className="space-y-4">
                      {/* Score card */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 flex items-center gap-6">
                        <div className="text-center">
                          <div className={`text-5xl font-black ${gradeColor(secPosture.grade)}`}>{secPosture.grade}</div>
                          <div className="text-xs text-gray-400 mt-1">Grade</div>
                        </div>
                        <div className="flex-1">
                          <div className="flex items-end gap-2 mb-1">
                            <span className="text-3xl font-bold text-white">{secPosture.security_score}</span>
                            <span className="text-gray-400 text-sm mb-1">/100</span>
                          </div>
                          <div className="w-full bg-gray-700 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full ${riskBg(100 - secPosture.security_score)}`}
                              style={{ width: `${secPosture.security_score}%` }}
                            />
                          </div>
                          <div className="mt-2 text-xs text-gray-400">
                            {secPosture.total_findings} findings for <span className="font-mono text-blue-300">{secPosture.domain}</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs text-right">
                          {Object.entries(secPosture.by_severity).filter(([, v]) => v > 0).map(([sev, count]) => (
                            <div key={sev}>
                              <span className={`font-bold ${
                                sev === "critical" ? "text-red-400" : sev === "high" ? "text-orange-400" :
                                sev === "medium" ? "text-yellow-400" : "text-blue-400"}`}>{count}</span>
                              <span className="text-gray-500 ml-1">{sev}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Findings */}
                      {secPosture.findings.length === 0 ? (
                        <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-4 text-center text-green-300 text-sm">
                          ✓ No security issues found. This domain has a strong security posture.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {secPosture.findings.map((f, i) => (
                            <div key={i} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                              <div className="flex items-start gap-3">
                                <span className={`text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0 mt-0.5 ${severityColor(f.severity)}`}>
                                  {f.severity.toUpperCase()}
                                </span>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs text-gray-500 capitalize">{f.category.replace(/_/g, " ")}</span>
                                  </div>
                                  <h4 className="text-sm font-semibold text-white mt-0.5">{f.title}</h4>
                                  <p className="text-xs text-gray-400 mt-1">{f.description}</p>
                                  <div className="mt-2 bg-blue-900/20 border border-blue-700/30 rounded p-2 text-xs text-blue-300">
                                    <span className="font-medium">Fix: </span>{f.remediation}
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Checks performed */}
                      <div className="text-xs text-gray-500">
                        Checks performed: {secPosture.checks_performed.join(", ")}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── Discovery Groups ─────────────────────────────────────── */}
              {tab === "groups" && (
                <div className="space-y-4 max-w-3xl">
                  <div className="flex items-start justify-between gap-4">
                    <p className="text-sm text-gray-400">
                      Define what to scan. Add domain seeds, IP ranges, or ASNs. Each group runs independently.
                    </p>
                    <button onClick={() => setShowNewGroup(true)}
                      className="bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium py-1.5 px-4 rounded-lg flex-shrink-0">
                      + Add Group
                    </button>
                  </div>

                  {groups.length === 0 ? (
                    <div className="border border-dashed border-gray-600 rounded-lg p-8 text-center">
                      <p className="text-gray-500 text-sm">No discovery groups yet.</p>
                      <button onClick={() => setShowNewGroup(true)} className="mt-2 text-blue-400 hover:text-blue-300 text-sm">
                        Create your first group →
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {groups.map((g) => (
                        <div key={g.id} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="text-sm font-semibold text-white">{g.name}</h4>
                                <span className={`text-xs px-2 py-0.5 rounded-full flex-shrink-0 ${
                                  g.is_active ? "bg-green-900/50 text-green-300" : "bg-gray-700 text-gray-400"}`}>
                                  {g.is_active ? "Active" : "Paused"}
                                </span>
                              </div>
                              {g.description && <p className="text-xs text-gray-400 mt-1">{g.description}</p>}
                              <div className="mt-2 flex flex-wrap gap-1">
                                {(g.seeds ?? []).length === 0
                                  ? <span className="text-xs text-yellow-500">⚠ No seeds — add seeds to enable scanning</span>
                                  : (g.seeds ?? []).map((s, i) => (
                                      <span key={i} className="text-xs bg-blue-900/40 text-blue-300 border border-blue-800/50 px-2 py-0.5 rounded font-mono">
                                        {s.type !== "domain" && <span className="text-blue-500 mr-1">[{s.type}]</span>}
                                        {s.value}
                                      </span>
                                    ))
                                }
                              </div>
                              <div className="mt-2 flex gap-x-4 gap-y-1 flex-wrap text-xs text-gray-500">
                                {g.include_subdomains && <span>✓ Subdomains</span>}
                                {g.include_ports && <span>✓ Ports</span>}
                                {g.include_ssl && <span>✓ SSL</span>}
                                {g.include_whois && <span>✓ WHOIS</span>}
                                {g.include_ct_logs && <span>✓ CT Logs</span>}
                                {g.include_http_checks && <span>✓ HTTP Headers</span>}
                                {g.include_ti_enrich && <span>✓ TI Enrichment</span>}
                                {g.include_nuclei && <span className="text-orange-400">✓ Nuclei</span>}
                              </div>
                              <div className="mt-1 text-xs text-gray-500">
                                {g.assets_discovered} assets · {g.findings_count} findings
                                {g.last_run_at && ` · Last run: ${fmt(g.last_run_at)}`}
                              </div>
                            </div>
                            <div className="flex gap-2 flex-shrink-0">
                              <button
                                onClick={() => saveGroup(g, { is_active: !g.is_active })}
                                className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-2 py-1">
                                {g.is_active ? "Pause" : "Resume"}
                              </button>
                              <button onClick={() => setShowEditGroup(g)}
                                className="text-xs text-gray-400 hover:text-white border border-gray-600 rounded px-2 py-1">
                                Edit
                              </button>
                              <button onClick={() => deleteGroup(g.id)}
                                className="text-xs text-red-500 hover:text-red-400 border border-red-800/50 rounded px-2 py-1">
                                Delete
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

            </div>
          </>
        )}
      </div>

      {/* ─── Modals ─────────────────────────────────────────────────────── */}

      {/* New Client */}
      {showNewClient && (
        <Modal onClose={() => setShowNewClient(false)} maxWidth="max-w-xl">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-1">Add New Client</h2>
            <p className="text-xs text-gray-400 mb-4">Each client gets an isolated monitoring space with its own asset inventory, findings, and scan schedule.</p>
            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-1">

              {/* Identity */}
              <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider pt-1">Identity</div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Organization Name *</label>
                <input autoFocus type="text" value={ncName} onChange={(e) => setNcName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") createClient(); }}
                  placeholder="e.g. Safaricom PLC"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Industry</label>
                  <input type="text" value={ncIndustry} onChange={(e) => setNcIndustry(e.target.value)}
                    placeholder="Telecom / Banking / Fintech"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Country</label>
                  <input type="text" value={ncCountry} onChange={(e) => setNcCountry(e.target.value.toUpperCase())}
                    placeholder="KE" maxLength={5}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Asset Owner</label>
                  <input type="text" value={ncOwner} onChange={(e) => setNcOwner(e.target.value)}
                    placeholder="CISO / IT Manager name"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Business Unit</label>
                  <input type="text" value={ncBU} onChange={(e) => setNcBU(e.target.value)}
                    placeholder="e.g. Core Banking, Mobile"
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Alert Contact Email</label>
                <input type="email" value={ncEmail} onChange={(e) => setNcEmail(e.target.value)}
                  placeholder="security@client.com"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
              </div>

              {/* Scan schedule */}
              <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider pt-2">Scan Schedule</div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  Automatic scan frequency
                  <span className="text-gray-500 ml-1">— scanner runs whenever the interval elapses</span>
                </label>
                <select value={ncInterval} onChange={(e) => setNcInterval(Number(e.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500">
                  {SCHEDULE_OPTIONS.map((s) => (
                    <option key={s.minutes} value={s.minutes}>{s.label}</option>
                  ))}
                </select>
                {ncInterval > 0 && (
                  <p className="text-xs text-gray-500 mt-1">
                    First scan runs immediately after client is created and seeds are added. You can also trigger scans manually at any time.
                  </p>
                )}
              </div>

              {/* Notes */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">Notes</label>
                <textarea value={ncDesc} onChange={(e) => setNcDesc(e.target.value)} rows={2} placeholder="Optional context…"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500 resize-none" />
              </div>
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setShowNewClient(false)}
                className="flex-1 border border-gray-600 text-gray-300 hover:text-white rounded-lg px-4 py-2 text-sm">Cancel</button>
              <button onClick={createClient} disabled={!ncName.trim()}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-medium rounded-lg px-4 py-2 text-sm">Create Client</button>
            </div>
          </div>
        </Modal>
      )}

      {/* Edit Client */}
      {showEditClient && selectedClient && (
        <Modal onClose={() => setShowEditClient(false)} maxWidth="max-w-xl">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-4">Edit Client: {selectedClient.name}</h2>
            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-1">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Name *</label>
                <input type="text" value={ecName} onChange={(e) => setEcName(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Industry</label>
                  <input type="text" value={ecIndustry} onChange={(e) => setEcIndustry(e.target.value)}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Country</label>
                  <input type="text" value={ecCountry} onChange={(e) => setEcCountry(e.target.value.toUpperCase())} maxLength={5}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Asset Owner</label>
                  <input type="text" value={ecOwner} onChange={(e) => setEcOwner(e.target.value)}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Business Unit</label>
                  <input type="text" value={ecBU} onChange={(e) => setEcBU(e.target.value)}
                    className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Alert Contact Email</label>
                <input type="email" value={ecEmail} onChange={(e) => setEcEmail(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Scan Frequency</label>
                <select value={ecInterval} onChange={(e) => setEcInterval(Number(e.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500">
                  {SCHEDULE_OPTIONS.map((s) => (
                    <option key={s.minutes} value={s.minutes}>{s.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Notes</label>
                <textarea value={ecDesc} onChange={(e) => setEcDesc(e.target.value)} rows={2}
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 resize-none" />
              </div>
            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setShowEditClient(false)}
                className="flex-1 border border-gray-600 text-gray-300 hover:text-white rounded-lg px-4 py-2 text-sm">Cancel</button>
              <button onClick={saveClient} disabled={!ecName.trim()}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-medium rounded-lg px-4 py-2 text-sm">Save Changes</button>
            </div>
          </div>
        </Modal>
      )}

      {/* New Group */}
      {showNewGroup && selectedClient && (
        <Modal onClose={() => setShowNewGroup(false)} maxWidth="max-w-2xl">
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-1">Add Discovery Group</h2>
            <p className="text-xs text-gray-400 mb-4">for <strong className="text-white">{selectedClient.name}</strong></p>
            <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">

              <div>
                <label className="block text-xs text-gray-400 mb-1">Group Name *</label>
                <input autoFocus type="text" value={ngName} onChange={(e) => setNgName(e.target.value)}
                  placeholder="e.g. Primary Domains, Cloud Edge, Acquired Company"
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
              </div>

              {/* Structured seed list */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-xs text-gray-400">
                    Monitoring Targets <span className="text-gray-500">— what to track for this group</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => setNgSeeds((p) => [...p, { type: "domain", value: "" }])}
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    + Add target
                  </button>
                </div>

                <div className="space-y-2">
                  {ngSeeds.map((seed, idx) => (
                    <div key={idx} className="flex gap-2 items-start">
                      <select
                        value={seed.type}
                        onChange={(e) => setNgSeeds((p) => p.map((s, i) => i === idx ? { ...s, type: e.target.value } : s))}
                        className="bg-gray-700 border border-gray-600 rounded px-2 py-2 text-xs text-white focus:outline-none focus:border-blue-500 flex-shrink-0 w-36"
                      >
                        {SEED_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>{t.label}</option>
                        ))}
                      </select>
                      <div className="flex-1">
                        <input
                          type="text"
                          value={seed.value}
                          onChange={(e) => setNgSeeds((p) => p.map((s, i) => i === idx ? { ...s, value: e.target.value } : s))}
                          placeholder={SEED_TYPES.find((t) => t.value === seed.type)?.placeholder ?? ""}
                          className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm font-mono text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                        />
                        <p className="text-xs text-gray-600 mt-0.5">
                          {SEED_TYPES.find((t) => t.value === seed.type)?.hint}
                        </p>
                      </div>
                      {ngSeeds.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setNgSeeds((p) => p.filter((_, i) => i !== idx))}
                          className="text-gray-600 hover:text-red-400 text-lg leading-none pt-1.5 flex-shrink-0"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  ))}
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  {ngSeeds.filter((s) => s.value.trim()).length} of {ngSeeds.length} targets filled in
                </p>
              </div>

              {/* Scan modules */}
              <div>
                <label className="block text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Scan Modules</label>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                  {([
                    { label: "Subdomain Discovery",  hint: "crt.sh + SecurityTrails + Shodan",   val: ngSubdomains, set: setNgSubdomains },
                    { label: "Port Scanning",         hint: "TCP connect scan, common ports",     val: ngPorts,      set: setNgPorts },
                    { label: "SSL/TLS Analysis",      hint: "Cert grab, expiry, key strength",    val: ngSSL,        set: setNgSSL },
                    { label: "WHOIS Lookup",          hint: "Registrar, org, registration date",  val: ngWhois,      set: setNgWhois },
                    { label: "CT Log Monitoring",     hint: "Live certificate transparency stream",val: ngCT,         set: setNgCT },
                    { label: "HTTP Security Headers", hint: "HSTS, CSP, X-Frame-Options, etc.",   val: ngHttp,       set: setNgHttp },
                    { label: "Threat-Intel Enrichment",hint: "Join assets against IOC feed",      val: ngTI,         set: setNgTI },
                  ] as const).map(({ label, hint, val, set }) => (
                    <label key={label} className="flex items-start gap-2 cursor-pointer py-0.5">
                      <input type="checkbox" checked={val} onChange={(e) => (set as (v: boolean) => void)(e.target.checked)}
                        className="mt-0.5 rounded border-gray-500 accent-blue-500 flex-shrink-0" />
                      <div>
                        <div className="text-xs text-gray-200">{label}</div>
                        <div className="text-xs text-gray-600">{hint}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

            </div>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setShowNewGroup(false)}
                className="flex-1 border border-gray-600 text-gray-300 hover:text-white rounded-lg px-4 py-2 text-sm">Cancel</button>
              <button onClick={createGroup} disabled={!ngName.trim() || ngSeeds.every((s) => !s.value.trim())}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-medium rounded-lg px-4 py-2 text-sm">
                Create Group
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Edit Group */}
      {showEditGroup && selectedClient && (
        <Modal onClose={() => setShowEditGroup(null)} maxWidth="max-w-xl">
          <EditGroupModal
            group={showEditGroup}
            onSave={(patch) => saveGroup(showEditGroup, patch)}
            onClose={() => setShowEditGroup(null)}
          />
        </Modal>
      )}

      {/* Delete Confirm */}
      {showDeleteConfirm && selectedClient && (
        <Modal onClose={() => setShowDeleteConfirm(false)} maxWidth="max-w-sm">
          <div className="bg-gray-800 border border-red-800/50 rounded-xl p-6 shadow-2xl">
            <h2 className="text-base font-bold text-white mb-2">Delete Client</h2>
            <p className="text-sm text-gray-300 mb-1">Delete <strong>{selectedClient.name}</strong>?</p>
            <p className="text-xs text-red-400">This removes the client record. Elasticsearch scan data is not purged automatically.</p>
            <div className="flex gap-3 mt-5">
              <button onClick={() => setShowDeleteConfirm(false)}
                className="flex-1 border border-gray-600 text-gray-300 hover:text-white rounded-lg px-4 py-2 text-sm">Cancel</button>
              <button onClick={deleteClient}
                className="flex-1 bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg px-4 py-2 text-sm">Delete</button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ─── EditGroupModal ───────────────────────────────────────────────────────────

function EditGroupModal({
  group, onSave, onClose
}: {
  group: DiscoveryGroup;
  onSave: (patch: Partial<DiscoveryGroup>) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(group.name);
  const [desc, setDesc] = useState(group.description ?? "");
  // Convert existing seeds to structured form; fall back to domain type
  const [seeds, setSeeds] = useState<Array<{ type: string; value: string }>>(
    (group.seeds ?? []).length > 0
      ? group.seeds.map((s) => ({ type: s.type || "domain", value: s.value }))
      : [{ type: "domain", value: "" }]
  );
  const [subdomains, setSubdomains] = useState(group.include_subdomains);
  const [ports, setPorts] = useState(group.include_ports);
  const [ssl, setSsl] = useState(group.include_ssl);
  const [whois, setWhois] = useState(group.include_whois);
  const [ct, setCt] = useState(group.include_ct_logs);
  const [http, setHttp] = useState(group.include_http_checks);
  const [ti, setTi] = useState(group.include_ti_enrich);

  const save = () => {
    const validSeeds = seeds.filter((s) => s.value.trim()).map((s) => ({ type: s.type, value: s.value.trim() }));
    onSave({
      name,
      description: desc || null,
      seeds: validSeeds,
      include_subdomains: subdomains,
      include_ports: ports,
      include_ssl: ssl,
      include_whois: whois,
      include_ct_logs: ct,
      include_http_checks: http,
      include_ti_enrich: ti,
    });
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-2xl">
      <h2 className="text-base font-bold text-white mb-4">Edit Group: {group.name}</h2>
      <div className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Name *</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)}
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500" />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Description</label>
          <input type="text" value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Optional notes…"
            className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-blue-500" />
        </div>

        {/* Structured seeds */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-xs text-gray-400">Monitoring Targets</label>
            <button type="button" onClick={() => setSeeds((p) => [...p, { type: "domain", value: "" }])}
              className="text-xs text-blue-400 hover:text-blue-300">+ Add target</button>
          </div>
          <div className="space-y-2">
            {seeds.map((seed, idx) => (
              <div key={idx} className="flex gap-2 items-start">
                <select
                  value={seed.type}
                  onChange={(e) => setSeeds((p) => p.map((s, i) => i === idx ? { ...s, type: e.target.value } : s))}
                  className="bg-gray-700 border border-gray-600 rounded px-2 py-2 text-xs text-white focus:outline-none focus:border-blue-500 flex-shrink-0 w-36"
                >
                  {SEED_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
                <input
                  type="text"
                  value={seed.value}
                  onChange={(e) => setSeeds((p) => p.map((s, i) => i === idx ? { ...s, value: e.target.value } : s))}
                  placeholder={SEED_TYPES.find((t) => t.value === seed.type)?.placeholder ?? ""}
                  className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm font-mono text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
                {seeds.length > 1 && (
                  <button type="button" onClick={() => setSeeds((p) => p.filter((_, i) => i !== idx))}
                    className="text-gray-600 hover:text-red-400 text-lg leading-none pt-1.5 flex-shrink-0">×</button>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Modules */}
        <div>
          <label className="block text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Scan Modules</label>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2">
            {([
              { label: "Subdomain Discovery",   val: subdomains, set: setSubdomains },
              { label: "Port Scanning",          val: ports,      set: setPorts },
              { label: "SSL/TLS Analysis",       val: ssl,        set: setSsl },
              { label: "WHOIS Lookup",           val: whois,      set: setWhois },
              { label: "CT Log Monitoring",      val: ct,         set: setCt },
              { label: "HTTP Security Headers",  val: http,       set: setHttp },
              { label: "TI Enrichment",          val: ti,         set: setTi },
            ] as const).map(({ label, val, set }) => (
              <label key={label} className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={val} onChange={(e) => (set as (v: boolean) => void)(e.target.checked)}
                  className="rounded border-gray-500 accent-blue-500" />
                <span className="text-xs text-gray-300">{label}</span>
              </label>
            ))}
          </div>
        </div>
      </div>
      <div className="flex gap-3 mt-5">
        <button onClick={onClose}
          className="flex-1 border border-gray-600 text-gray-300 hover:text-white rounded-lg px-4 py-2 text-sm">Cancel</button>
        <button onClick={save} disabled={!name.trim()}
          className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-medium rounded-lg px-4 py-2 text-sm">Save Changes</button>
      </div>
    </div>
  );
}
