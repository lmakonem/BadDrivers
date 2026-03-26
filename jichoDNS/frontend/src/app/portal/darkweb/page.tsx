"use client";

import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "@/lib/fetch";

interface DWItem {
  indicator: string;
  indicator_type?: string;
  threat_type: string;
  source: string;
  risk_score: number;
  country_code?: string;
  ip_address?: string;
  tags?: string[];
  misp_event_id?: string;
  misp_category?: string;
  created_at?: string;
}

interface WatchMatch extends DWItem {
  matched_terms: string[];
}

interface Stats {
  total_threats: number;
  misp_intel: number;
  new_last_24h: number;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
}

interface Watchlist {
  id: number;
  name: string;
  domains: string[];
  brand_terms: string[];
  keywords: string[];
}

interface CredItem {
  email: string;
  domain?: string;
  source: string;
  source_name?: string;
  severity?: string;
  discovered_at?: string;
  country_code?: string;
  tags?: string[];
}

interface CrawlResult {
  url: string;
  title: string;
  body_text: string;
  source: string;
  source_type: string;
  crawl_query?: string;
  discovered_at: string;
  emails_found: string[];
  onion_links: string[];
  domains_found: string[];
  severity: string;
  tags: string[];
}

type Tab = "feed" | "crawl" | "credentials" | "watchlist" | "monitoring";

export default function DarkWebPage() {
  const [tab, setTab] = useState<Tab>("feed");

  // Feed
  const [items, setItems] = useState<DWItem[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [filterType, setFilterType] = useState("");
  const [filterSource, setFilterSource] = useState("");
  const [feedSearch, setFeedSearch] = useState("");

  // Credentials
  const [creds, setCreds] = useState<CredItem[]>([]);
  const [credTotal, setCredTotal] = useState(0);
  const [credPages, setCredPages] = useState(1);
  const [credPage, setCredPage] = useState(1);
  const [credSearch, setCredSearch] = useState("");
  const [credLoading, setCredLoading] = useState(false);

  // Crawl results
  const [crawlResults, setCrawlResults] = useState<CrawlResult[]>([]);
  const [crawlTotal, setCrawlTotal] = useState(0);
  const [crawlPages, setCrawlPages] = useState(1);
  const [crawlPage, setCrawlPage] = useState(1);
  const [crawlSearch, setCrawlSearch] = useState("");
  const [crawlLoading, setCrawlLoading] = useState(false);
  const [crawling, setCrawling] = useState(false);

  // Watchlist
  const [watchMatches, setWatchMatches] = useState<WatchMatch[]>([]);
  const [watchTerms, setWatchTerms] = useState<string[]>([]);
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);

  // Add modal
  const [showModal, setShowModal] = useState(false);
  const [newTerm, setNewTerm] = useState("");
  const [newType, setNewType] = useState<"keyword" | "brand" | "domain">("keyword");

  // ── Data fetching ──────────────────────────────────────────────────────

  const fetchFeed = useCallback(async () => {
    setLoading(true);
    let url = `/api/v1/darkweb-intel/feed?page=${page}&page_size=30`;
    if (filterType) url += `&threat_type=${filterType}`;
    if (filterSource) url += `&source=${filterSource}`;
    if (feedSearch.length >= 2) url += `&search=${encodeURIComponent(feedSearch)}`;
    try {
      const res = await apiFetch(url);
      if (res.ok) {
        const d = await res.json();
        setItems(d.items || []);
        setTotal(d.total || 0);
        setTotalPages(d.pages || 1);
      }
    } catch { /* */ }
    setLoading(false);
  }, [page, filterType, filterSource, feedSearch]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/v1/darkweb-intel/stats`);
      if (res.ok) setStats(await res.json());
    } catch { /* */ }
  }, []);

  const fetchCredentials = useCallback(async () => {
    setCredLoading(true);
    let url = `/api/v1/credentials/search?page=${credPage}&page_size=30`;
    if (credSearch.length >= 2) url += `&q=${encodeURIComponent(credSearch)}`;
    try {
      const res = await apiFetch(url);
      if (res.ok) {
        const d = await res.json();
        setCreds(d.items || []);
        setCredTotal(d.total || 0);
        setCredPages(d.pages || 1);
      }
    } catch { /* */ }
    setCredLoading(false);
  }, [credPage, credSearch]);

  const fetchWatchData = useCallback(async () => {
    try {
      const [mRes, wRes] = await Promise.allSettled([
        apiFetch(`/api/v1/darkweb-intel/watchlist/matches?limit=50`),
        apiFetch(`/api/v1/intel/watchlists`),
      ]);
      if (mRes.status === "fulfilled" && mRes.value.ok) {
        const d = await mRes.value.json();
        setWatchMatches(d.matches || []);
        setWatchTerms(d.watchlist_terms || []);
      }
      if (wRes.status === "fulfilled" && wRes.value.ok) {
        const d = await wRes.value.json();
        setWatchlists(d.items || []);
      }
    } catch { /* */ }
  }, []);

  const fetchCrawlResults = useCallback(async () => {
    setCrawlLoading(true);
    let url = `/api/v1/darkweb-intel/crawl-results?page=${crawlPage}&page_size=30`;
    if (crawlSearch.length >= 2) url += `&search=${encodeURIComponent(crawlSearch)}`;
    try {
      const res = await apiFetch(url);
      if (res.ok) {
        const d = await res.json();
        setCrawlResults(d.items || []);
        setCrawlTotal(d.total || 0);
        setCrawlPages(d.pages || 1);
      }
    } catch { /* */ }
    setCrawlLoading(false);
  }, [crawlPage, crawlSearch]);

  const triggerCrawl = async () => {
    setCrawling(true);
    try {
      await apiFetch(`/api/v1/darkweb-intel/crawl`, { method: "POST" });
      // Wait a bit then refresh
      setTimeout(() => { fetchCrawlResults(); setCrawling(false); }, 5000);
    } catch { setCrawling(false); }
  };

  // Auto-load on mount
  useEffect(() => { fetchStats(); fetchWatchData(); }, [fetchStats, fetchWatchData]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { fetchFeed(); }, [page, filterType, filterSource]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === "credentials") fetchCredentials(); }, [tab, credPage]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (tab === "crawl") fetchCrawlResults(); }, [tab, crawlPage]);

  // ── Add watch term ─────────────────────────────────────────────────────

  const handleAddTerm = async () => {
    if (!newTerm.trim()) return;
    const body = {
      name: "Dark Web Monitor",
      org_name: "My Organization",
      domains: newType === "domain" ? [newTerm.trim()] : [],
      brand_terms: newType === "brand" ? [newTerm.trim()] : [],
      keywords: newType === "keyword" ? [newTerm.trim()] : [],
    };
    try {
      if (watchlists.length > 0) {
        await apiFetch(`/api/v1/intel/watchlists/${watchlists[0].id}`, {
          method: "PATCH", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      } else {
        await apiFetch(`/api/v1/intel/watchlists`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      }
      setNewTerm(""); setShowModal(false);
      fetchWatchData();
    } catch { /* */ }
  };

  // ── Helpers ────────────────────────────────────────────────────────────

  const tc = (t: string) =>
    t === "c2" ? "bg-red-500/20 text-red-400" :
    t === "phishing" ? "bg-orange-500/20 text-orange-400" :
    t === "botnet" ? "bg-purple-500/20 text-purple-400" :
    "bg-blue-500/20 text-blue-400";

  const allTerms = watchlists.flatMap(w => [...(w.domains||[]), ...(w.brand_terms||[]), ...(w.keywords||[])]);

  // ── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dark Web Monitoring</h1>
          <p className="text-gray-400 mt-1">C2 infrastructure, phishing, MISP intel, credential leaks</p>
        </div>
        <button onClick={() => setShowModal(true)} className="px-4 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-xl transition-colors flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          Watch Term
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Dark Web Threats", value: stats.total_threats, color: "text-white" },
            { label: "MISP Intel", value: stats.misp_intel, color: "text-blue-400" },
            { label: "Phishing", value: stats.by_type?.phishing || 0, color: "text-orange-400" },
            { label: "C2 Servers", value: stats.by_type?.c2 || 0, color: "text-red-400" },
            { label: "Watch Alerts", value: watchMatches.length, color: "text-yellow-400" },
          ].map((s) => (
            <div key={s.label} className="bg-card-dark border border-white/10 rounded-xl p-3">
              <p className={`text-xl font-bold ${s.color}`}>{(s.value || 0).toLocaleString()}</p>
              <p className="text-xs text-gray-400">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/10">
        {([
          { id: "feed" as Tab, label: "Threat Feed", ct: total },
          { id: "crawl" as Tab, label: "Dark Web Crawl", ct: crawlTotal },
          { id: "credentials" as Tab, label: "Credential Leaks", ct: credTotal },
          { id: "watchlist" as Tab, label: "Watch Alerts", ct: watchMatches.length },
          { id: "monitoring" as Tab, label: "Monitored Terms", ct: allTerms.length },
        ]).map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors rounded-t-lg ${tab === t.id ? "bg-primary/10 text-primary border-b-2 border-primary" : "text-gray-400 hover:text-white"}`}>
            {t.label} <span className="ml-1 px-1.5 py-0.5 rounded text-xs bg-white/10">{t.ct > 0 ? t.ct.toLocaleString() : "0"}</span>
          </button>
        ))}
      </div>

      {/* ═══ FEED TAB ═══ */}
      {tab === "feed" && (
        <div className="space-y-4">
          <div className="flex gap-2 flex-wrap">
            <input type="text" value={feedSearch} onChange={(e) => setFeedSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { setPage(1); fetchFeed(); } }}
              placeholder="Search C2 IPs, phishing URLs, MISP indicators..."
              className="flex-1 min-w-[200px] px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 text-sm" />
            <select value={filterType} onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-white text-sm cursor-pointer">
              <option value="" className="bg-card-dark">All Types</option>
              <option value="c2" className="bg-card-dark">C2</option>
              <option value="phishing" className="bg-card-dark">Phishing</option>
              <option value="botnet" className="bg-card-dark">Botnet</option>
            </select>
            <select value={filterSource} onChange={(e) => { setFilterSource(e.target.value); setPage(1); }}
              className="px-3 py-2 bg-white/5 border border-white/10 rounded-xl text-white text-sm cursor-pointer">
              <option value="" className="bg-card-dark">All Sources</option>
              <option value="misp" className="bg-card-dark">MISP (AfISAC)</option>
              <option value="phishtank" className="bg-card-dark">PhishTank</option>
              <option value="openphish" className="bg-card-dark">OpenPhish</option>
              <option value="sslbl" className="bg-card-dark">SSLBL</option>
              <option value="feodotracker" className="bg-card-dark">FeodoTracker</option>
            </select>
            <button onClick={() => { setPage(1); fetchFeed(); }} className="px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-xl text-sm font-medium transition-colors">Search</button>
          </div>

          {loading ? (
            <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" /></div>
          ) : items.length === 0 ? (
            <div className="text-center py-16 text-gray-400"><p>No dark web threats found matching your filters.</p></div>
          ) : (
            <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
              <table className="w-full"><thead>
                <tr className="text-left text-xs text-gray-400 border-b border-white/10 bg-white/[0.02]">
                  <th className="px-4 py-3 font-medium">Indicator</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Source</th>
                  <th className="px-4 py-3 font-medium">Country</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Date</th>
                </tr></thead>
                <tbody className="divide-y divide-white/5">
                  {items.map((it, i) => (
                    <tr key={i} className="hover:bg-white/[0.02]">
                      <td className="px-4 py-2.5"><p className="text-white text-sm font-mono truncate max-w-sm" title={it.indicator}>{it.indicator}</p>
                        {it.misp_event_id ? <span className="text-xs text-blue-400">MISP #{it.misp_event_id}</span> : null}</td>
                      <td className="px-4 py-2.5"><span className={`text-xs px-2 py-0.5 rounded font-medium ${tc(it.threat_type)}`}>{it.threat_type}</span></td>
                      <td className="px-4 py-2.5 text-sm text-gray-400">{it.source}</td>
                      <td className="px-4 py-2.5 text-sm text-gray-400">{it.country_code || "—"}</td>
                      <td className="px-4 py-2.5"><div className="flex items-center gap-1"><div className="w-10 h-1.5 bg-white/10 rounded-full overflow-hidden"><div className={`h-full rounded-full ${it.risk_score >= 80 ? "bg-red-500" : it.risk_score >= 60 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${it.risk_score}%` }} /></div><span className="text-xs text-gray-400">{it.risk_score}</span></div></td>
                      <td className="px-4 py-2.5 text-xs text-gray-500">{it.created_at ? new Date(it.created_at).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
                  <p className="text-sm text-gray-400">Page {page}/{totalPages} ({total.toLocaleString()} total)</p>
                  <div className="flex gap-2">
                    <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Prev</button>
                    <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Next</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ DARK WEB CRAWL TAB ═══ */}
      {tab === "crawl" && (
        <div className="space-y-4">
          <div className="flex gap-2 flex-wrap">
            <input type="text" value={crawlSearch} onChange={(e) => setCrawlSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { setCrawlPage(1); fetchCrawlResults(); } }}
              placeholder="Search dark web crawl results..."
              className="flex-1 min-w-[200px] px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 text-sm" />
            <button onClick={() => { setCrawlPage(1); fetchCrawlResults(); }} className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-xl text-sm font-medium transition-colors">Search</button>
            <button onClick={triggerCrawl} disabled={crawling} className="px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors flex items-center gap-2">
              {crawling ? (<><div className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" /> Crawling...</>) : (<><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" /></svg> Crawl Now</>)}
            </button>
          </div>

          {crawlLoading ? (
            <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full animate-spin" /></div>
          ) : crawlResults.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-16 h-16 mx-auto text-purple-500/30 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" /></svg>
              <h3 className="text-lg text-white mb-2">No dark web crawl data yet</h3>
              <p className="text-gray-400 text-sm mb-4">Click &quot;Crawl Now&quot; to search dark web sources (Ahmia, .onion sites) for threats matching your watchlist.</p>
              <button onClick={triggerCrawl} disabled={crawling} className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white font-medium rounded-xl">
                {crawling ? "Crawling..." : "Start First Crawl"}
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {crawlResults.map((r, i) => (
                <div key={i} className="bg-card-dark border border-white/10 rounded-xl p-4 hover:border-purple-500/30 transition-colors">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${r.severity === "critical" ? "bg-red-500/20 text-red-400" : r.severity === "high" ? "bg-orange-500/20 text-orange-400" : "bg-gray-500/20 text-gray-400"}`}>{r.severity}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400">{r.source_type}</span>
                    <span className="text-xs text-gray-500">{r.source}</span>
                    {r.crawl_query ? <span className="text-xs text-gray-500 ml-auto">query: {r.crawl_query}</span> : null}
                  </div>
                  <h3 className="text-white text-sm font-medium mb-1">{r.title || "Untitled"}</h3>
                  <p className="text-gray-400 text-xs mb-2 line-clamp-2">{r.body_text?.slice(0, 200)}</p>
                  <div className="flex flex-wrap gap-2">
                    {r.emails_found?.length > 0 ? <span className="text-xs text-orange-400">{r.emails_found.length} emails</span> : null}
                    {r.onion_links?.length > 0 ? <span className="text-xs text-purple-400">{r.onion_links.length} .onion links</span> : null}
                    {r.domains_found?.length > 0 ? <span className="text-xs text-blue-400">{r.domains_found.length} domains</span> : null}
                    <span className="text-xs text-gray-500 ml-auto">{r.discovered_at ? new Date(r.discovered_at).toLocaleString() : ""}</span>
                  </div>
                </div>
              ))}
              {crawlPages > 1 && (
                <div className="flex items-center justify-between pt-2">
                  <p className="text-sm text-gray-400">Page {crawlPage}/{crawlPages} ({crawlTotal})</p>
                  <div className="flex gap-2">
                    <button onClick={() => setCrawlPage(Math.max(1, crawlPage - 1))} disabled={crawlPage <= 1} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Prev</button>
                    <button onClick={() => setCrawlPage(Math.min(crawlPages, crawlPage + 1))} disabled={crawlPage >= crawlPages} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Next</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ CREDENTIALS TAB ═══ */}
      {tab === "credentials" && (
        <div className="space-y-4">
          <div className="flex gap-2">
            <input type="text" value={credSearch} onChange={(e) => setCredSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { setCredPage(1); fetchCredentials(); } }}
              placeholder="Search by email, domain, or username..."
              className="flex-1 px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 text-sm" />
            <button onClick={() => { setCredPage(1); fetchCredentials(); }} className="px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-xl text-sm font-medium transition-colors">Search Leaks</button>
          </div>

          {credLoading ? (
            <div className="flex justify-center py-16"><div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" /></div>
          ) : creds.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-12 h-12 mx-auto text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
              <h3 className="text-lg text-white mb-2">Search for credential leaks</h3>
              <p className="text-gray-400 text-sm">Enter an email or domain to check for exposed credentials in breach databases and phishing infrastructure.</p>
            </div>
          ) : (
            <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
              <table className="w-full"><thead>
                <tr className="text-left text-xs text-gray-400 border-b border-white/10 bg-white/[0.02]">
                  <th className="px-4 py-3 font-medium">Email / Indicator</th>
                  <th className="px-4 py-3 font-medium">Source</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Country</th>
                  <th className="px-4 py-3 font-medium">Discovered</th>
                </tr></thead>
                <tbody className="divide-y divide-white/5">
                  {creds.map((c, i) => (
                    <tr key={i} className="hover:bg-white/[0.02]">
                      <td className="px-4 py-2.5"><p className="text-white text-sm font-mono truncate max-w-sm">{c.email}</p>
                        {c.domain ? <p className="text-xs text-gray-500">{c.domain}</p> : null}</td>
                      <td className="px-4 py-2.5 text-sm text-gray-400">{c.source_name || c.source}</td>
                      <td className="px-4 py-2.5"><span className={`text-xs px-2 py-0.5 rounded ${c.severity === "critical" ? "bg-red-500/20 text-red-400" : c.severity === "high" ? "bg-orange-500/20 text-orange-400" : "bg-yellow-500/20 text-yellow-400"}`}>{c.severity || "medium"}</span></td>
                      <td className="px-4 py-2.5 text-sm text-gray-400">{c.country_code || "—"}</td>
                      <td className="px-4 py-2.5 text-xs text-gray-500">{c.discovered_at ? new Date(c.discovered_at).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {credPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
                  <p className="text-sm text-gray-400">Page {credPage}/{credPages} ({credTotal.toLocaleString()})</p>
                  <div className="flex gap-2">
                    <button onClick={() => setCredPage(Math.max(1, credPage - 1))} disabled={credPage <= 1} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Prev</button>
                    <button onClick={() => setCredPage(Math.min(credPages, credPage + 1))} disabled={credPage >= credPages} className="px-3 py-1 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg">Next</button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ═══ WATCH ALERTS TAB ═══ */}
      {tab === "watchlist" && (
        <div className="space-y-4">
          {watchTerms.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-12 h-12 mx-auto text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /></svg>
              <h3 className="text-lg text-white mb-2">No watch terms configured</h3>
              <p className="text-gray-400 text-sm mb-4">Add domains, brands, or keywords to get alerted when they appear in dark web data.</p>
              <button onClick={() => setShowModal(true)} className="px-6 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-xl">Add Watch Term</button>
            </div>
          ) : watchMatches.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-12 h-12 mx-auto text-green-500 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <h3 className="text-lg text-white mb-2">All clear</h3>
              <p className="text-gray-400">None of your {watchTerms.length} monitored terms found in current dark web data.</p>
            </div>
          ) : (
            <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-white/10 bg-red-500/5"><p className="text-sm text-red-400 font-medium">{watchMatches.length} threat{watchMatches.length !== 1 ? "s" : ""} match your watch terms</p></div>
              <div className="divide-y divide-white/5">
                {watchMatches.map((m, i) => (
                  <div key={i} className="px-4 py-3 hover:bg-white/[0.02]">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${tc(m.threat_type)}`}>{m.threat_type}</span>
                      {(m.matched_terms || []).map((t) => (
                        <span key={t} className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">matched: {t}</span>
                      ))}
                      <span className="text-xs text-gray-500 ml-auto">{m.source}</span>
                    </div>
                    <p className="text-white text-sm font-mono">{m.indicator}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ═══ MONITORING TAB ═══ */}
      {tab === "monitoring" && (
        <div className="space-y-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl">
            <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
              <h3 className="text-white font-medium">Monitored Terms</h3>
              <button onClick={() => setShowModal(true)} className="text-sm text-primary hover:text-primary-light">+ Add</button>
            </div>
            {allTerms.length === 0 ? (
              <div className="p-8 text-center text-gray-400"><p>No terms monitored yet.</p></div>
            ) : (
              <div className="divide-y divide-white/5">
                {watchlists.map((wl) => (
                  <div key={wl.id} className="p-4">
                    <p className="text-sm font-medium text-white mb-3">{wl.name}</p>
                    <div className="flex flex-wrap gap-2">
                      {(wl.domains || []).map((d) => (<span key={`d-${d}`} className="px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 text-sm border border-blue-500/20">{d} <span className="text-blue-500/50 ml-1 text-xs">domain</span></span>))}
                      {(wl.brand_terms || []).map((b) => (<span key={`b-${b}`} className="px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 text-sm border border-purple-500/20">{b} <span className="text-purple-500/50 ml-1 text-xs">brand</span></span>))}
                      {(wl.keywords || []).map((k) => (<span key={`k-${k}`} className="px-3 py-1.5 rounded-lg bg-gray-500/10 text-gray-300 text-sm border border-gray-500/20">{k} <span className="text-gray-500 ml-1 text-xs">keyword</span></span>))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ═══ ADD MODAL ═══ */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <h2 className="text-xl font-semibold text-white">Add Watch Term</h2>
              <p className="text-sm text-gray-400 mt-1">Get alerted when this appears in dark web data.</p>
            </div>
            <div className="p-6 space-y-4">
              <input type="text" value={newTerm} onChange={(e) => setNewTerm(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleAddTerm(); }}
                placeholder="safaricom, m-pesa, company.co.ke..." autoFocus
                className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50" />
              <select value={newType} onChange={(e) => setNewType(e.target.value as "keyword"|"brand"|"domain")}
                className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white cursor-pointer">
                <option value="keyword" className="bg-card-dark">Keyword</option>
                <option value="brand" className="bg-card-dark">Brand Name</option>
                <option value="domain" className="bg-card-dark">Domain</option>
              </select>
            </div>
            <div className="p-6 border-t border-white/10 flex gap-3">
              <button onClick={() => setShowModal(false)} className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium">Cancel</button>
              <button onClick={handleAddTerm} disabled={!newTerm.trim()} className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover disabled:opacity-50 text-white rounded-xl font-medium">Add &amp; Monitor</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
