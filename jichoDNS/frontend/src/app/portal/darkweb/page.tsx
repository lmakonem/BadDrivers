"use client";

import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "@/lib/fetch";

// ── Types ────────────────────────────────────────────────────────────────────

interface DarkWebItem {
  indicator: string;
  indicator_type: string;
  threat_type: string;
  source: string;
  risk_score: number;
  country_code?: string;
  tags?: string[];
  created_at?: string;
}

interface WatchMatch extends DarkWebItem {
  matched_terms: string[];
  _score: number;
}

interface Stats {
  total_threats: number;
  new_last_24h: number;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
  top_countries: Record<string, number>;
}

interface Watchlist {
  id: number;
  name: string;
  domains: string[];
  brand_terms: string[];
  keywords: string[];
  is_active: boolean;
  created_at: string;
}

// ── Page ─────────────────────────────────────────────────────────────────────

type Tab = "feed" | "watchlist" | "alerts";

export default function DarkWebPage() {
  const [tab, setTab] = useState<Tab>("feed");
  const [items, setItems] = useState<DarkWebItem[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [watchMatches, setWatchMatches] = useState<WatchMatch[]>([]);
  const [watchTerms, setWatchTerms] = useState<string[]>([]);
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  // Filters
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterSource, setFilterSource] = useState("");

  // Add keyword modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [newTerm, setNewTerm] = useState("");
  const [newTermType, setNewTermType] = useState<"domain" | "brand" | "keyword">("keyword");

  // ── Fetch feed ──────────────────────────────────────────────────────────

  const fetchFeed = useCallback(async () => {
    setLoading(true);
    try {
      let url = `/api/v1/darkweb-intel/feed?page=${page}&page_size=30`;
      if (filterType) url += `&threat_type=${filterType}`;
      if (filterSource) url += `&source=${filterSource}`;
      if (search.length >= 2) url += `&search=${encodeURIComponent(search)}`;

      const res = await apiFetch(url);
      if (res.ok) {
        const data = await res.json();
        setItems(data.items || []);
        setTotal(data.total || 0);
        setTotalPages(data.pages || 1);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [page, filterType, filterSource, search]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/v1/darkweb-intel/stats`);
      if (res.ok) setStats(await res.json());
    } catch { /* ignore */ }
  }, []);

  const fetchWatchlistMatches = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/v1/darkweb-intel/watchlist/matches?limit=50`);
      if (res.ok) {
        const data = await res.json();
        setWatchMatches(data.matches || []);
        setWatchTerms(data.watchlist_terms || []);
      }
    } catch { /* ignore */ }
  }, []);

  const fetchWatchlists = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/v1/intel/watchlists`);
      if (res.ok) {
        const data = await res.json();
        setWatchlists(data.items || []);
      }
    } catch { /* ignore */ }
  }, []);

  // Fetch on mount and when page/filter changes (NOT on search keystroke)
  useEffect(() => {
    fetchFeed();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, filterType, filterSource]);

  useEffect(() => {
    fetchStats();
    fetchWatchlists();
    fetchWatchlistMatches();
  }, [fetchStats, fetchWatchlists, fetchWatchlistMatches]);

  // ── Add watch term ──────────────────────────────────────────────────────

  const handleAddTerm = async () => {
    if (!newTerm.trim()) return;
    try {
      if (watchlists.length > 0) {
        const wl = watchlists[0];
        const body: Record<string, unknown> = {
          name: wl.name, org_name: "My Organization",
          domains: newTermType === "domain" ? [newTerm.trim()] : [],
          brand_terms: newTermType === "brand" ? [newTerm.trim()] : [],
          keywords: newTermType === "keyword" ? [newTerm.trim()] : [],
        };
        await apiFetch(`/api/v1/intel/watchlists/${wl.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      } else {
        await apiFetch(`/api/v1/intel/watchlists`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: "Dark Web Monitor", org_name: "My Organization",
            domains: newTermType === "domain" ? [newTerm.trim()] : [],
            brand_terms: newTermType === "brand" ? [newTerm.trim()] : [],
            keywords: newTermType === "keyword" ? [newTerm.trim()] : [],
          }),
        });
      }
      setNewTerm("");
      setShowAddModal(false);
      fetchWatchlists();
      fetchWatchlistMatches();
    } catch { /* ignore */ }
  };

  // ── Helpers ─────────────────────────────────────────────────────────────

  const typeColor = (t: string) =>
    t === "c2" ? "bg-red-500/20 text-red-400" :
    t === "phishing" ? "bg-orange-500/20 text-orange-400" :
    t === "malware" ? "bg-yellow-500/20 text-yellow-400" :
    "bg-blue-500/20 text-blue-400";

  const riskColor = (r: number) =>
    r >= 80 ? "bg-red-500" : r >= 60 ? "bg-yellow-500" : "bg-green-500";

  const allWatchTerms = watchlists.flatMap(wl => [
    ...(wl.domains || []), ...(wl.brand_terms || []), ...(wl.keywords || [])
  ]);

  // ── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dark Web Monitoring</h1>
          <p className="text-gray-400 mt-1">
            Monitor dark web threats, phishing infrastructure, and C2 servers
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-xl transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Watch Term
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-card-dark border border-white/10 rounded-xl p-4">
            <p className="text-2xl font-bold text-white">{(stats.total_threats || 0).toLocaleString()}</p>
            <p className="text-sm text-gray-400">Total Threats</p>
          </div>
          <div className="bg-card-dark border border-white/10 rounded-xl p-4">
            <p className="text-2xl font-bold text-orange-400">{(stats.by_type?.phishing || 0).toLocaleString()}</p>
            <p className="text-sm text-gray-400">Phishing</p>
          </div>
          <div className="bg-card-dark border border-white/10 rounded-xl p-4">
            <p className="text-2xl font-bold text-red-400">{(stats.by_type?.c2 || 0).toLocaleString()}</p>
            <p className="text-sm text-gray-400">C2 Servers</p>
          </div>
          <div className="bg-card-dark border border-white/10 rounded-xl p-4">
            <p className="text-2xl font-bold text-purple-400">{watchMatches.length}</p>
            <p className="text-sm text-gray-400">Watchlist Hits</p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10 pb-1">
        {[
          { id: "feed" as Tab, label: "Threat Feed", count: total },
          { id: "watchlist" as Tab, label: "Watchlist Alerts", count: watchMatches.length },
          { id: "alerts" as Tab, label: "Monitored Terms", count: allWatchTerms.length },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2.5 rounded-t-lg font-medium transition-colors ${
              tab === t.id ? "bg-primary/10 text-primary border-b-2 border-primary" : "text-gray-400 hover:text-white"
            }`}
          >
            {t.label}
            <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-white/10">{t.count}</span>
          </button>
        ))}
      </div>

      {/* ── Feed Tab ──────────────────────────────────────────────────── */}
      {tab === "feed" && (
        <div className="space-y-4">
          {/* Search + Filters */}
          <div className="flex gap-3 flex-wrap">
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              onKeyDown={(e) => { if (e.key === "Enter") fetchFeed(); }}
              placeholder="Search indicators..."
              className="flex-1 min-w-[200px] px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50"
            />
            <select
              value={filterType}
              onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
              className="px-3 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white appearance-none cursor-pointer"
            >
              <option value="" className="bg-card-dark">All Types</option>
              <option value="phishing" className="bg-card-dark">Phishing</option>
              <option value="c2" className="bg-card-dark">C2</option>
              <option value="malware" className="bg-card-dark">Malware</option>
              <option value="botnet" className="bg-card-dark">Botnet</option>
            </select>
            <select
              value={filterSource}
              onChange={(e) => { setFilterSource(e.target.value); setPage(1); }}
              className="px-3 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white appearance-none cursor-pointer"
            >
              <option value="" className="bg-card-dark">All Sources</option>
              <option value="phishtank" className="bg-card-dark">PhishTank</option>
              <option value="urlhaus" className="bg-card-dark">URLhaus</option>
              <option value="misp" className="bg-card-dark">MISP</option>
              <option value="sslbl" className="bg-card-dark">SSLBL</option>
              <option value="threatfox" className="bg-card-dark">ThreatFox</option>
              <option value="openphish" className="bg-card-dark">OpenPhish</option>
            </select>
            <button
              onClick={() => { fetchFeed(); }}
              className="px-5 py-2.5 bg-primary hover:bg-primary-hover text-white rounded-xl font-medium transition-colors"
            >
              Search
            </button>
          </div>

          {/* Results table */}
          {loading ? (
            <div className="flex justify-center py-16">
              <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
            </div>
          ) : items.length === 0 ? (
            <div className="text-center py-16 text-gray-400">
              <p className="text-lg">No threats found</p>
              <p className="text-sm mt-1">Try adjusting your filters</p>
            </div>
          ) : (
            <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-xs text-gray-400 border-b border-white/10 bg-white/[0.02]">
                    <th className="px-4 py-3 font-medium">Indicator</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 font-medium">Source</th>
                    <th className="px-4 py-3 font-medium">Country</th>
                    <th className="px-4 py-3 font-medium">Risk</th>
                    <th className="px-4 py-3 font-medium">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {items.map((item, i) => (
                    <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-3">
                        <p className="text-white text-sm font-mono truncate max-w-sm" title={item.indicator}>
                          {item.indicator}
                        </p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-1 rounded font-medium ${typeColor(item.threat_type)}`}>
                          {item.threat_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">{item.source}</td>
                      <td className="px-4 py-3 text-sm text-gray-400">{item.country_code || "—"}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 bg-white/10 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${riskColor(item.risk_score)}`} style={{ width: `${item.risk_score}%` }} />
                          </div>
                          <span className="text-xs text-gray-400">{item.risk_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500">
                        {item.created_at ? new Date(item.created_at).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
                  <p className="text-sm text-gray-400">
                    Page {page} of {totalPages} ({total.toLocaleString()} total)
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setPage(Math.max(1, page - 1))}
                      disabled={page <= 1}
                      className="px-3 py-1.5 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg transition-colors"
                    >
                      Prev
                    </button>
                    <button
                      onClick={() => setPage(Math.min(totalPages, page + 1))}
                      disabled={page >= totalPages}
                      className="px-3 py-1.5 text-sm bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white rounded-lg transition-colors"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Watchlist Alerts Tab ───────────────────────────────────────── */}
      {tab === "watchlist" && (
        <div className="space-y-4">
          {watchTerms.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-12 h-12 mx-auto text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              <h3 className="text-lg font-medium text-white mb-2">No watch terms configured</h3>
              <p className="text-gray-400 mb-4">Add domains, brands, or keywords to monitor for dark web threats.</p>
              <button
                onClick={() => setShowAddModal(true)}
                className="px-6 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-xl transition-colors"
              >
                Add Your First Watch Term
              </button>
            </div>
          ) : watchMatches.length === 0 ? (
            <div className="text-center py-16 bg-card-dark border border-white/10 rounded-2xl">
              <svg className="w-12 h-12 mx-auto text-green-500 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h3 className="text-lg font-medium text-white mb-2">No matches found</h3>
              <p className="text-gray-400">None of your {watchTerms.length} monitored terms appeared in the current threat data.</p>
            </div>
          ) : (
            <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-white/10 bg-red-500/5">
                <p className="text-sm text-red-400 font-medium">
                  {watchMatches.length} threats match your watchlist terms
                </p>
              </div>
              <div className="divide-y divide-white/5">
                {watchMatches.map((m, i) => (
                  <div key={i} className="px-4 py-3 hover:bg-white/[0.02] transition-colors">
                    <div className="flex items-center gap-3 mb-1">
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${typeColor(m.threat_type)}`}>
                        {m.threat_type}
                      </span>
                      {m.matched_terms?.map((t) => (
                        <span key={t} className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                          matched: {t}
                        </span>
                      ))}
                      <span className="text-xs text-gray-500">{m.source}</span>
                    </div>
                    <p className="text-white text-sm font-mono">{m.indicator}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Monitored Terms Tab ────────────────────────────────────────── */}
      {tab === "alerts" && (
        <div className="space-y-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl">
            <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
              <h3 className="text-white font-medium">Monitored Terms</h3>
              <button
                onClick={() => setShowAddModal(true)}
                className="text-sm text-primary hover:text-primary-light"
              >
                + Add Term
              </button>
            </div>
            {allWatchTerms.length === 0 ? (
              <div className="p-8 text-center text-gray-400">
                <p>No terms being monitored. Click &quot;Add Term&quot; to start.</p>
              </div>
            ) : (
              <div className="divide-y divide-white/5">
                {watchlists.map((wl) => (
                  <div key={wl.id} className="p-4">
                    <p className="text-sm font-medium text-white mb-3">{wl.name}</p>
                    <div className="flex flex-wrap gap-2">
                      {(wl.domains || []).map((d) => (
                        <span key={`d-${d}`} className="px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 text-sm border border-blue-500/20">
                          {d} <span className="text-blue-500/50 ml-1">domain</span>
                        </span>
                      ))}
                      {(wl.brand_terms || []).map((b) => (
                        <span key={`b-${b}`} className="px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 text-sm border border-purple-500/20">
                          {b} <span className="text-purple-500/50 ml-1">brand</span>
                        </span>
                      ))}
                      {(wl.keywords || []).map((k) => (
                        <span key={`k-${k}`} className="px-3 py-1.5 rounded-lg bg-gray-500/10 text-gray-300 text-sm border border-gray-500/20">
                          {k} <span className="text-gray-500 ml-1">keyword</span>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Add Term Modal ─────────────────────────────────────────────── */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <h2 className="text-xl font-semibold text-white">Add Watch Term</h2>
              <p className="text-sm text-gray-400 mt-1">
                Get alerted when this term appears in dark web threat data.
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Term</label>
                <input
                  type="text"
                  value={newTerm}
                  onChange={(e) => setNewTerm(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleAddTerm(); }}
                  placeholder="e.g. safaricom, m-pesa, company.co.ke"
                  className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Type</label>
                <select
                  value={newTermType}
                  onChange={(e) => setNewTermType(e.target.value as "domain" | "brand" | "keyword")}
                  className="w-full px-4 py-2.5 bg-white/5 border border-white/10 rounded-xl text-white appearance-none cursor-pointer"
                >
                  <option value="keyword" className="bg-card-dark">Keyword</option>
                  <option value="brand" className="bg-card-dark">Brand Name</option>
                  <option value="domain" className="bg-card-dark">Domain</option>
                </select>
              </div>
            </div>
            <div className="p-6 border-t border-white/10 flex gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddTerm}
                disabled={!newTerm.trim()}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover disabled:opacity-50 text-white rounded-xl font-medium transition-colors"
              >
                Add & Monitor
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
