"use client";

import { useState, useEffect, useCallback, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { apiFetch } from "@/lib/fetch";

interface SearchResult {
  _id: string;
  _score: number;
  _source_type: string;
  indicator?: string;
  email?: string;
  domain?: string;
  title?: string;
  url?: string;
  data?: string;
  threat_type?: string;
  source?: string;
  severity?: string;
  country_code?: string;
  discovered_at?: string;
  created_at?: string;
  [key: string]: unknown;
}

interface SearchResponse {
  query: string;
  total: number;
  sources_searched: string[];
  results: Record<string, { total: number; items: SearchResult[] }>;
}

function SearchContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const q = searchParams.get("q") || "";

  const [query, setQuery] = useState(q);
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeSource, setActiveSource] = useState<string>("all");

  const doSearch = useCallback(
    async (searchQuery: string) => {
      if (searchQuery.length < 2) return;
      setLoading(true);
      try {
        const sourceParam = activeSource !== "all" ? `&source=${activeSource}` : "";
        const res = await apiFetch(
          `/api/v1/search/search?q=${encodeURIComponent(searchQuery)}&limit=100${sourceParam}`
        );
        if (res.ok) {
          setResults(await res.json());
        }
      } catch (err) {
        console.error("Search error:", err);
      } finally {
        setLoading(false);
      }
    },
    [activeSource]
  );

  useEffect(() => {
    if (q) doSearch(q);
  }, [q, doSearch]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim().length >= 2) {
      router.push(`/portal/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  const sourceLabels: Record<string, string> = {
    iocs: "Threat Indicators",
    darkweb: "Dark Web",
    credentials: "Credential Leaks",
    osint: "OSINT Results",
  };

  const sourceIcons: Record<string, string> = {
    iocs: "text-red-400",
    darkweb: "text-purple-400",
    credentials: "text-orange-400",
    osint: "text-blue-400",
  };

  const allItems: SearchResult[] = results
    ? Object.values(results.results).flatMap((r) => r.items)
    : [];

  return (
    <div className="space-y-6">
      {/* Search bar */}
      <form onSubmit={handleSearch} className="flex gap-3">
        <div className="relative flex-1">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search emails, IPs, domains, hashes, keywords..."
            className="w-full px-5 py-4 pl-12 bg-card-dark border border-white/10 rounded-2xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 text-lg"
          />
          <svg
            className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
        </div>
        <button
          type="submit"
          disabled={loading || query.trim().length < 2}
          className="px-8 py-4 bg-primary hover:bg-primary-hover disabled:opacity-50 text-white font-semibold rounded-2xl transition-colors"
        >
          {loading ? "Searching..." : "Search"}
        </button>
      </form>

      {/* Source filter */}
      {results && (
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setActiveSource("all")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeSource === "all"
                ? "bg-primary text-white"
                : "bg-white/5 text-gray-400 hover:text-white"
            }`}
          >
            All ({results.total})
          </button>
          {Object.entries(results.results).map(([src, data]) => (
            <button
              key={src}
              onClick={() => setActiveSource(src)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeSource === src
                  ? "bg-primary text-white"
                  : "bg-white/5 text-gray-400 hover:text-white"
              }`}
            >
              {sourceLabels[src] || src} ({data.total})
            </button>
          ))}
        </div>
      )}

      {/* Results */}
      {loading && (
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {results && !loading && (
        <div className="space-y-3">
          {results.total === 0 ? (
            <div className="text-center py-20">
              <p className="text-2xl text-gray-400 mb-2">No results found</p>
              <p className="text-gray-500">
                Try a different search term — emails, IPs, domains, or hashes.
              </p>
            </div>
          ) : (
            (activeSource === "all"
              ? allItems
              : results.results[activeSource]?.items || []
            ).map((item, i) => (
              <div
                key={item._id || i}
                className="bg-card-dark border border-white/10 rounded-xl p-5 hover:border-white/20 transition-colors"
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`mt-1 w-2 h-2 rounded-full ${
                      item.severity === "critical"
                        ? "bg-red-500"
                        : item.severity === "high"
                          ? "bg-orange-500"
                          : item.severity === "medium"
                            ? "bg-yellow-500"
                            : "bg-gray-500"
                    }`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={`text-xs font-semibold uppercase ${
                          sourceIcons[item._source_type] || "text-gray-400"
                        }`}
                      >
                        {sourceLabels[item._source_type] || item._source_type}
                      </span>
                      {item.threat_type && (
                        <span className="px-2 py-0.5 bg-red-500/10 text-red-400 rounded text-xs">
                          {item.threat_type}
                        </span>
                      )}
                      {item.country_code && (
                        <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded text-xs">
                          {item.country_code}
                        </span>
                      )}
                    </div>
                    <p className="text-white font-medium truncate">
                      {item.indicator || item.email || item.title || item.data || item.url || "—"}
                    </p>
                    {item.domain && (
                      <p className="text-sm text-gray-400 mt-1">Domain: {item.domain}</p>
                    )}
                    {item.source && (
                      <p className="text-xs text-gray-500 mt-1">Source: {item.source}</p>
                    )}
                  </div>
                  <div className="text-right text-xs text-gray-500 whitespace-nowrap">
                    {item.discovered_at || item.created_at
                      ? new Date(
                          String(item.discovered_at || item.created_at)
                        ).toLocaleDateString()
                      : ""}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {!results && !loading && (
        <div className="text-center py-20">
          <div className="w-20 h-20 mx-auto rounded-full bg-primary/10 flex items-center justify-center mb-6">
            <svg
              className="w-10 h-10 text-primary"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-white mb-3">
            Search Intelligence
          </h2>
          <p className="text-gray-400 max-w-md mx-auto">
            Search across all intelligence sources — threat indicators, dark web
            posts, credential leaks, and OSINT results. Try an email address,
            IP, domain, or hash.
          </p>
        </div>
      )}
    </div>
  );
}

export default function SearchPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-20">
          <div className="w-10 h-10 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <SearchContent />
    </Suspense>
  );
}
