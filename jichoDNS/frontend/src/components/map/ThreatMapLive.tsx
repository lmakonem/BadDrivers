"use client";

import { useState, useCallback, useEffect } from "react";
import dynamic from "next/dynamic";
import { Shield, Activity, Zap, TrendingUp, Filter, X, ChevronDown, Check, Terminal } from "lucide-react";
import { JichoMark } from "@/components/brand/JichoMark";

// Import country list (safe for SSR - no browser APIs)
import { AFRICAN_COUNTRY_LIST } from "./countries";

// Dynamically import map to avoid SSR issues with Leaflet
const RealThreatMap = dynamic(() => import("./RealThreatMap"), {
  ssr: false,
  loading: () => (
    <div className="absolute inset-0 bg-gray-950 flex items-center justify-center">
      <div className="text-center">
        <div className="w-16 h-16 border-4 border-green-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <div className="text-gray-400 text-lg">Loading Real Threat Data...</div>
      </div>
    </div>
  ),
});

interface ThreatIndicator {
  indicator: string;
  indicator_type: string;
  threat_type: string;
  source: string;
  confidence: number;
  risk_score: number;
  country_code?: string;
  asn?: number;
  asn_org?: string;
  ip_address?: string;
}

interface Attack {
  source: { name: string; code?: string };
  target: { name: string; code?: string };
  threatType: string;
  color: string;
  timestamp: Date;
  indicator?: ThreatIndicator;
}

interface AttackStats {
  total: number;
  byType: Record<string, number>;
  bySource: Record<string, number>;
  byTarget: Record<string, number>;
}

const THREAT_LABELS: Record<string, string> = {
  malware: "Malware",
  c2: "C2 Server",
  phishing: "Phishing",
  ddos: "DDoS",
  bruteforce: "Brute Force",
};

const THREAT_COLORS: Record<string, string> = {
  malware: "#ef4444",
  c2: "#f97316",
  phishing: "#a855f7",
  ddos: "#3b82f6",
  bruteforce: "#eab308",
};

export function ThreatMapLive() {
  const [recentAttacks, setRecentAttacks] = useState<Attack[]>([]);
  const [stats, setStats] = useState<AttackStats>({
    total: 0,
    byType: {},
    bySource: {},
    byTarget: {},
  });
  const [attacksPerMinute, setAttacksPerMinute] = useState(0);
  const [startTime] = useState(Date.now());
  
  // Country filter state
  const [selectedCountries, setSelectedCountries] = useState<string[]>([]); // Empty = all countries
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const [filterSearch, setFilterSearch] = useState("");

  // Filter countries by search
  const filteredCountryList = AFRICAN_COUNTRY_LIST.filter(
    (c) => c.name.toLowerCase().includes(filterSearch.toLowerCase()) || 
           c.code.toLowerCase().includes(filterSearch.toLowerCase())
  );

  // Toggle country selection
  const toggleCountry = (code: string) => {
    setSelectedCountries((prev) =>
      prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code]
    );
  };

  // Select all / clear all
  const selectAllCountries = () => {
    setSelectedCountries(AFRICAN_COUNTRY_LIST.map((c) => c.code));
  };

  const clearAllCountries = () => {
    setSelectedCountries([]);
  };

  // Get display text for filter button
  const getFilterButtonText = () => {
    if (selectedCountries.length === 0) return "All Countries";
    if (selectedCountries.length === 1) {
      const country = AFRICAN_COUNTRY_LIST.find((c) => c.code === selectedCountries[0]);
      return country?.name || selectedCountries[0];
    }
    return `${selectedCountries.length} Countries`;
  };

  // Handle new attack
  const handleAttack = useCallback((attack: Attack) => {
    setRecentAttacks((prev) => {
      const updated = [attack, ...prev].slice(0, 15);
      return updated;
    });
  }, []);

  // Handle stats update
  const handleStatsUpdate = useCallback((newStats: AttackStats) => {
    setStats(newStats);
  }, []);

  // Calculate attacks per minute
  useEffect(() => {
    const interval = setInterval(() => {
      const elapsedMinutes = (Date.now() - startTime) / 60000;
      if (elapsedMinutes > 0) {
        setAttacksPerMinute(Math.round(stats.total / elapsedMinutes));
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [stats.total, startTime]);

  // Format time ago
  const formatTimeAgo = (date: Date) => {
    const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
    if (seconds < 5) return "just now";
    if (seconds < 60) return `${seconds}s ago`;
    return `${Math.floor(seconds / 60)}m ago`;
  };

  // Get top items from record
  const getTopItems = (record: Record<string, number>, limit: number) => {
    return Object.entries(record)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit);
  };



  return (
    <div className="relative w-full h-screen bg-gray-950">
      {/* Real Threat Map */}
      <RealThreatMap 
        onAttack={handleAttack} 
        onStatsUpdate={handleStatsUpdate} 
        selectedCountries={selectedCountries}
        apiBaseUrl=""
      />

      {/* Header overlay */}
      <div className="absolute top-0 left-0 right-0 z-[500] bg-gradient-to-b from-gray-950 via-gray-950/80 to-transparent p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <JichoMark size={56} />
            <div>
              <div className="flex items-center gap-3">
                <h1 className="font-display text-2xl font-bold text-white">Jicho Threat Map</h1>
              </div>
              <span className="text-sm text-gray-400">
                Real threat intelligence data
              </span>
            </div>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2 bg-gray-900/80 px-3 py-1.5 rounded-lg border border-gray-800">
              <Activity className="w-4 h-4 text-green-500" />
              <span className="text-green-400 font-mono">{attacksPerMinute}</span>
              <span className="text-gray-500">/min</span>
            </div>
            <div className="flex items-center gap-2 bg-gray-900/80 px-3 py-1.5 rounded-lg border border-gray-800">
              <Zap className="w-4 h-4 text-yellow-500" />
              <span className="text-yellow-400 font-mono">{stats.total.toLocaleString()}</span>
              <span className="text-gray-500">attacks</span>
            </div>
          </div>
        </div>
      </div>

      {/* Stats panel - top left */}
      <div className="absolute top-20 left-4 z-[500] w-64 bg-gray-900/95 backdrop-blur-sm rounded-lg border border-gray-800 overflow-hidden">
        <div className="p-3 border-b border-gray-800">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            Attack Statistics
          </h3>
        </div>
        
        {/* By Threat Type */}
        <div className="p-3 border-b border-gray-800">
          <h4 className="text-xs font-medium text-gray-400 mb-2">By Threat Type</h4>
          <div className="space-y-1.5">
            {getTopItems(stats.byType, 5).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: THREAT_COLORS[type] || "#6b7280" }}
                  />
                  <span className="text-xs text-gray-300">{THREAT_LABELS[type] || type}</span>
                </div>
                <span className="text-xs font-mono text-gray-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Sources */}
        <div className="p-3 border-b border-gray-800">
          <h4 className="text-xs font-medium text-gray-400 mb-2">Top Attack Sources</h4>
          <div className="space-y-1.5">
            {getTopItems(stats.bySource, 5).map(([country, count]) => (
              <div key={country} className="flex items-center justify-between">
                <span className="text-xs text-gray-300">{country}</span>
                <span className="text-xs font-mono text-red-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Targets */}
        <div className="p-3 border-b border-gray-800">
          <h4 className="text-xs font-medium text-gray-400 mb-2">Top Targets</h4>
          <div className="space-y-1.5">
            {getTopItems(stats.byTarget, 5).map(([country, count]) => (
              <div key={country} className="flex items-center justify-between">
                <span className="text-xs text-gray-300">{country}</span>
                <span className="text-xs font-mono text-green-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Country Filter Section */}
        <div className="p-3">
          {/* Filter Toggle Button */}
          <button
            onClick={() => setIsFilterOpen(!isFilterOpen)}
            className="w-full flex items-center justify-between py-1"
          >
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-medium text-gray-400">Filter Countries</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-cyan-400">{getFilterButtonText()}</span>
              <ChevronDown className={`w-3 h-3 text-gray-400 transition-transform ${isFilterOpen ? 'rotate-180' : ''}`} />
            </div>
          </button>

          {/* Filter Dropdown */}
          {isFilterOpen && (
            <div className="mt-2 border-t border-gray-800 pt-2">
              {/* Search Input */}
              <input
                type="text"
                placeholder="Search countries..."
                value={filterSearch}
                onChange={(e) => setFilterSearch(e.target.value)}
                className="w-full px-2 py-1.5 bg-gray-800 border border-gray-700 rounded text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 mb-2"
              />

              {/* Quick Actions */}
              <div className="flex gap-1 mb-2">
                <button
                  onClick={selectAllCountries}
                  className="flex-1 px-2 py-1 text-xs text-cyan-400 hover:bg-gray-800 rounded transition-colors border border-gray-700"
                >
                  Select All
                </button>
                <button
                  onClick={clearAllCountries}
                  className="flex-1 px-2 py-1 text-xs text-gray-400 hover:bg-gray-800 rounded transition-colors border border-gray-700"
                >
                  Clear All
                </button>
              </div>

              {/* Selected Countries Tags */}
              {selectedCountries.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-2">
                  {selectedCountries.slice(0, 4).map((code) => {
                    const country = AFRICAN_COUNTRY_LIST.find((c) => c.code === code);
                    return (
                      <span
                        key={code}
                        className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-cyan-500/20 text-cyan-400 rounded text-xs"
                      >
                        {country?.name || code}
                        <X
                          className="w-3 h-3 cursor-pointer hover:text-cyan-300"
                          onClick={() => toggleCountry(code)}
                        />
                      </span>
                    );
                  })}
                  {selectedCountries.length > 4 && (
                    <span className="px-1.5 py-0.5 text-gray-400 text-xs">
                      +{selectedCountries.length - 4} more
                    </span>
                  )}
                </div>
              )}

              {/* Country List */}
              <div className="max-h-48 overflow-y-auto custom-scrollbar border border-gray-700 rounded">
                {filteredCountryList.map((country) => (
                  <button
                    key={country.code}
                    onClick={() => toggleCountry(country.code)}
                    className={`w-full flex items-center justify-between px-2 py-1.5 text-left text-xs hover:bg-gray-800 transition-colors ${
                      selectedCountries.includes(country.code) ? 'bg-gray-800/50' : ''
                    }`}
                  >
                    <span className={selectedCountries.includes(country.code) ? 'text-cyan-400' : 'text-gray-300'}>
                      {country.name}
                    </span>
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-gray-500">{country.code}</span>
                      {selectedCountries.includes(country.code) && (
                        <Check className="w-3 h-3 text-cyan-400" />
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Live feed - right side */}
      <div className="absolute top-20 right-4 bottom-20 z-[500] w-80 bg-gray-900/95 backdrop-blur-sm rounded-lg border border-gray-800 overflow-hidden flex flex-col">
        <div className="p-3 border-b border-gray-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-400" />
            Live Attack Feed
          </h3>
          <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
        </div>
        <div className="flex-1 overflow-y-auto custom-scrollbar">
          <div className="divide-y divide-gray-800/50">
            {recentAttacks.map((attack, index) => (
              <div
                key={`${attack.timestamp.getTime()}-${index}`}
                className="p-3 hover:bg-gray-800/50 transition-colors animate-fadeIn"
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span
                    className="px-2 py-0.5 rounded text-xs font-medium"
                    style={{
                      backgroundColor: `${attack.color}22`,
                      color: attack.color,
                    }}
                  >
                    {THREAT_LABELS[attack.threatType] || attack.threatType}
                  </span>
                  <span className="text-xs text-gray-500">
                    {formatTimeAgo(attack.timestamp)}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-red-400 font-medium">{attack.source.name}</span>
                  <svg className="w-4 h-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                  <span className="text-green-400 font-medium">{attack.target.name}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Legend - bottom left */}
      <div className="absolute bottom-4 left-4 z-[500] bg-gray-900/95 backdrop-blur-sm rounded-lg border border-gray-800 p-3">
        <h4 className="text-xs font-semibold text-gray-400 mb-2">Threat Types</h4>
        <div className="flex flex-wrap gap-3">
          {Object.entries(THREAT_LABELS).map(([key, label]) => (
            <div key={key} className="flex items-center gap-1.5">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: THREAT_COLORS[key] }}
              />
              <span className="text-xs text-gray-300">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Raw Attack Logs Console - Bottom Center */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 w-[1000px] z-[500] bg-black/95 backdrop-blur-sm rounded-lg border border-gray-800 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-1.5 bg-gray-900/80 border-b border-gray-800">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-green-500" />
            <span className="text-xs font-mono text-green-400">ATTACK_LOG</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <div className="w-2 h-2 rounded-full bg-yellow-500" />
            <div className="w-2 h-2 rounded-full bg-green-500" />
          </div>
        </div>
        <div className="h-32 overflow-y-auto custom-scrollbar p-2 font-mono text-xs">
          {recentAttacks.slice(0, 20).map((attack, index) => {
            const ind = attack.indicator;
            const timestamp = attack.timestamp.toISOString().split('T')[1].split('.')[0];
            return (
              <div 
                key={`log-${attack.timestamp.getTime()}-${index}`}
                className="py-0.5 hover:bg-gray-900/50 animate-fadeIn"
              >
                <span className="text-gray-600">[{timestamp}]</span>
                {" "}
                <span className="text-yellow-500">{attack.threatType.toUpperCase()}</span>
                {" "}
                <span className="text-red-400">{attack.source.code || attack.source.name}</span>
                <span className="text-gray-600">{" -> "}</span>
                <span className="text-green-400">{attack.target.code || attack.target.name}</span>
                {ind && (
                  <>
                    {" "}
                    <span className="text-gray-500">|</span>
                    {" "}
                    <span className="text-cyan-400">{ind.indicator_type}:</span>
                    <span className="text-white">{ind.indicator.length > 45 ? ind.indicator.substring(0, 45) + "..." : ind.indicator}</span>
                    {ind.ip_address && (
                      <>
                        {" "}
                        <span className="text-purple-400">[{ind.ip_address}]</span>
                      </>
                    )}
                    {ind.asn && (
                      <>
                        {" "}
                        <span className="text-orange-400">AS{ind.asn}</span>
                      </>
                    )}
                    {" "}
                    <span className="text-gray-500">risk:</span>
                    <span className={ind.risk_score >= 80 ? "text-red-500" : ind.risk_score >= 50 ? "text-yellow-500" : "text-green-500"}>
                      {ind.risk_score}
                    </span>
                  </>
                )}
              </div>
            );
          })}
          {recentAttacks.length === 0 && (
            <div className="text-gray-600 py-2">
              <span className="text-green-500">$</span> Waiting for threat data...
              <span className="animate-pulse">_</span>
            </div>
          )}
        </div>
      </div>

      {/* Attribution */}
      <div className="absolute bottom-4 right-4 z-[500] text-xs text-gray-600">
        Powered by JichoSec Threat Intelligence
      </div>

      <style jsx global>{`
        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #374151;
          border-radius: 2px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #4b5563;
        }
      `}</style>
    </div>
  );
}
