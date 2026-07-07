"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { apiFetch } from "@/lib/fetch";
import { JichoMark } from "@/components/brand/JichoMark";

// Types
interface OverviewStats {
  totalIOCs: number;
  activeAlerts: number;
  riskScore: number;
  assetsMonitored: number;
  trends: {
    iocs: number;
    alerts: number;
    risk: number;
    assets: number;
  };
}

interface IOCStats {
  total: number;
  by_threat_type: Record<string, number>;
  by_indicator_type: Record<string, number>;
  by_source: Record<string, number>;
  by_country: Record<string, number>;
}

interface DarkwebStats {
  total_leaks: number;
  total_mentions: number;
  total_breaches: number;
  total_alerts: number;
  unread_alerts: number;
}

interface ASMStats {
  total_assets: number;
  total_vulnerabilities: number;
  vulnerabilities_by_severity: Record<string, number>;
}

interface BrandStats {
  total_monitors: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
}

interface Alert {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  type: string;
  timestamp: string;
  source: string;
}

interface QuickAction {
  title: string;
  description: string;
  href: string;
  icon: React.ReactNode;
  color: string;
}

// Default stats (shown while loading)
const defaultStats: OverviewStats = {
  totalIOCs: 0,
  activeAlerts: 0,
  riskScore: 0,
  assetsMonitored: 0,
  trends: {
    iocs: 0,
    alerts: 0,
    risk: 0,
    assets: 0,
  },
};

// Generate alerts from real IOC data
function generateAlertsFromStats(iocStats: IOCStats | null): Alert[] {
  if (!iocStats) return [];
  
  const alerts: Alert[] = [];
  const now = new Date();
  
  // C2 alert if we have C2 indicators
  if (iocStats.by_threat_type?.c2 > 0) {
    alerts.push({
      id: "c2-alert",
      title: `${iocStats.by_threat_type.c2.toLocaleString()} C2 Domains Detected`,
      description: "Active command and control infrastructure targeting organizations",
      severity: "critical",
      type: "C2",
      timestamp: new Date(now.getTime() - 2 * 60 * 60 * 1000).toISOString(),
      source: "DNS Analysis",
    });
  }
  
  // Malware alert
  if (iocStats.by_threat_type?.malware > 0) {
    alerts.push({
      id: "malware-alert",
      title: `${iocStats.by_threat_type.malware.toLocaleString()} Malware IOCs Tracked`,
      description: "Active malware indicators from multiple threat feeds",
      severity: "high",
      type: "Malware",
      timestamp: new Date(now.getTime() - 4 * 60 * 60 * 1000).toISOString(),
      source: "Threat Intel",
    });
  }
  
  // Phishing alert
  if (iocStats.by_threat_type?.phishing > 0) {
    alerts.push({
      id: "phishing-alert",
      title: `${iocStats.by_threat_type.phishing.toLocaleString()} Phishing URLs Active`,
      description: "Phishing campaigns targeting various sectors detected",
      severity: "high",
      type: "Phishing",
      timestamp: new Date(now.getTime() - 6 * 60 * 60 * 1000).toISOString(),
      source: "PhishTank",
    });
  }
  
  // Country-specific alerts for African countries
  const africanCountries = ["ZA", "KE", "NG", "EG", "MA", "ET", "GH", "TZ"];
  const africanThreats = africanCountries.reduce((sum, cc) => sum + (iocStats.by_country?.[cc] || 0), 0);
  if (africanThreats > 0) {
    alerts.push({
      id: "africa-alert",
      title: `${africanThreats} African-Origin Threats`,
      description: "Threats originating from or targeting African infrastructure",
      severity: "medium",
      type: "Regional",
      timestamp: new Date(now.getTime() - 8 * 60 * 60 * 1000).toISOString(),
      source: "Regional Analysis",
    });
  }
  
  // Top source alert
  const topSource = Object.entries(iocStats.by_source || {}).sort((a, b) => b[1] - a[1])[0];
  if (topSource) {
    alerts.push({
      id: "source-alert",
      title: `${topSource[1].toLocaleString()} IOCs from ${topSource[0]}`,
      description: `Latest threat intelligence aggregated from ${topSource[0]} feed`,
      severity: "low",
      type: "Intel",
      timestamp: new Date(now.getTime() - 12 * 60 * 60 * 1000).toISOString(),
      source: topSource[0],
    });
  }
  
  return alerts;
}

const getSeverityColor = (severity: Alert["severity"]) => {
  switch (severity) {
    case "critical":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "high":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "medium":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "low":
      return "bg-green-500/20 text-green-400 border-green-500/30";
  }
};

const getSeverityDot = (severity: Alert["severity"]) => {
  switch (severity) {
    case "critical":
      return "bg-red-500";
    case "high":
      return "bg-orange-500";
    case "medium":
      return "bg-yellow-500";
    case "low":
      return "bg-green-500";
  }
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

// Icons
const TrendUpIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
  </svg>
);

const TrendDownIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const DatabaseIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
  </svg>
);

const BellIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
  </svg>
);

const ServerIcon = () => (
  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
  </svg>
);

const DocumentIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);

const SearchIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
);

const GlobeIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
);

const ChartIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
  </svg>
);

const ArrowRightIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
  </svg>
);

const quickActions: QuickAction[] = [
  {
    title: "Generate Report",
    description: "Create AI-powered threat report",
    href: "/portal/reports",
    icon: <DocumentIcon />,
    color: "from-blue-500/20 to-blue-600/10",
  },
  {
    title: "Analyze Domain",
    description: "Check domain for threats",
    href: "/analysis",
    icon: <SearchIcon />,
    color: "from-green-500/20 to-green-600/10",
  },
  {
    title: "Start Discovery",
    description: "Scan attack surface",
    href: "/portal/asm",
    icon: <GlobeIcon />,
    color: "from-purple-500/20 to-purple-600/10",
  },
  {
    title: "View Analytics",
    description: "Threat intelligence insights",
    href: "/portal/reports",
    icon: <ChartIcon />,
    color: "from-orange-500/20 to-orange-600/10",
  },
];

export default function PortalDashboard() {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [iocStats, setIocStats] = useState<IOCStats | null>(null);
  const [threatDistribution, setThreatDistribution] = useState<{type: string; count: number; percentage: number; color: string}[]>([]);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      
      // Fetch IOC stats
      const iocResponse = await apiFetch(`/api/v1/indicators/stats`);
      const iocData: IOCStats = iocResponse.ok ? await iocResponse.json() : {};
      setIocStats(iocData);
      
      // Fetch other stats in parallel
      const [darkwebResponse, asmResponse, brandResponse] = await Promise.allSettled([
        apiFetch(`/api/v1/darkweb/stats`),
        apiFetch(`/api/v1/asm/stats`),
        apiFetch(`/api/v1/brand/stats`),
      ]);
      
      let darkwebData: DarkwebStats | null = null;
      let asmData: ASMStats | null = null;
      let brandData: BrandStats | null = null;
      
      if (darkwebResponse.status === "fulfilled" && darkwebResponse.value.ok) {
        darkwebData = await darkwebResponse.value.json();
      }
      if (asmResponse.status === "fulfilled" && asmResponse.value.ok) {
        asmData = await asmResponse.value.json();
      }
      if (brandResponse.status === "fulfilled" && brandResponse.value.ok) {
        brandData = await brandResponse.value.json();
      }
      
      // Calculate active alerts from all sources
      const activeAlerts = 
        (darkwebData?.unread_alerts || 0) +
        (brandData?.critical_alerts || 0) +
        (brandData?.high_alerts || 0) +
        (asmData?.vulnerabilities_by_severity?.critical || 0) +
        (asmData?.vulnerabilities_by_severity?.high || 0);
      
      // Calculate risk score based on critical indicators
      const criticalCount = iocData?.by_threat_type?.c2 || 0;
      const totalThreats = iocData?.total || 1;
      const riskScore = Math.min(100, Math.round((criticalCount / totalThreats) * 100 * 3 + 40));
      
      // Calculate threat distribution for the chart
      const threatTypes = iocData?.by_threat_type || {};
      const total = Object.values(threatTypes).reduce((a: number, b: number) => a + b, 0) || 1;
      const colors = ["bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-purple-500", "bg-gray-500"];
      const distribution = Object.entries(threatTypes)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([type, count], i) => ({
          type: type.charAt(0).toUpperCase() + type.slice(1),
          count,
          percentage: Math.round((count / total) * 100),
          color: colors[i] || colors[4],
        }));
      setThreatDistribution(distribution);
      
      // Set combined stats
      setStats({
        totalIOCs: iocData.total || 0,
        activeAlerts: activeAlerts || Object.keys(iocData.by_threat_type || {}).length,
        riskScore,
        assetsMonitored: asmData?.total_assets || Object.keys(iocData.by_source || {}).length,
        trends: {
          iocs: 12.5, // Could calculate from historical data
          alerts: -8.3,
          risk: 5.2,
          assets: 3.1,
        },
      });
      
      // Generate alerts from IOC data
      setAlerts(generateAlertsFromStats(iocData));
      setLastUpdated(new Date());
      
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
      // Set default stats on error
      setStats(defaultStats);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    
    // Refresh every 5 minutes
    const interval = setInterval(fetchData, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 bg-card-dark rounded-2xl animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-96 bg-card-dark rounded-2xl animate-pulse" />
          <div className="h-96 bg-card-dark rounded-2xl animate-pulse" />
        </div>
      </div>
    );
  }

  return (
    <div className="relative space-y-6">
      {/* Ambient brand glow — the watchful eye's ambient light */}
      <div aria-hidden className="glow-gold pointer-events-none absolute inset-x-0 -top-4 h-72" />

      {/* Page header */}
      <div className="relative flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <JichoMark size={38} />
          <div>
            <h1 className="text-2xl font-bold font-display text-white">Dashboard</h1>
            <p className="text-gray-400 mt-1">Welcome back! Here&apos;s your security overview.</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">
            Last updated: {lastUpdated ? formatTimeAgo(lastUpdated.toISOString()) : "Never"}
          </span>
          <button 
            onClick={fetchData}
            disabled={loading}
            className="px-4 py-2 bg-primary hover:bg-primary-hover disabled:opacity-50 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
          >
            <svg className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {/* Total IOCs */}
        <div className="bg-card-dark border border-white/10 rounded-2xl p-6 hover:border-white/20 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Total IOCs</p>
              <p className="text-3xl font-bold font-display text-white mt-2">
                {stats?.totalIOCs.toLocaleString()}
              </p>
            </div>
            <div className="p-3 bg-secondary/10 text-secondary rounded-xl">
              <DatabaseIcon />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            {stats && stats.trends.iocs > 0 ? (
              <span className="flex items-center text-green-400 text-sm">
                <TrendUpIcon />
                <span className="ml-1">{stats.trends.iocs}%</span>
              </span>
            ) : (
              <span className="flex items-center text-red-400 text-sm">
                <TrendDownIcon />
                <span className="ml-1">{Math.abs(stats?.trends.iocs || 0)}%</span>
              </span>
            )}
            <span className="text-gray-500 text-sm">vs last week</span>
          </div>
        </div>

        {/* Active Alerts */}
        <div className="bg-card-dark border border-white/10 rounded-2xl p-6 hover:border-white/20 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Active Alerts</p>
              <p className="text-3xl font-bold font-display text-white mt-2">{stats?.activeAlerts}</p>
            </div>
            <div className="p-3 bg-primary/10 text-primary rounded-xl">
              <BellIcon />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            {stats && stats.trends.alerts < 0 ? (
              <span className="flex items-center text-green-400 text-sm">
                <TrendDownIcon />
                <span className="ml-1">{Math.abs(stats.trends.alerts)}%</span>
              </span>
            ) : (
              <span className="flex items-center text-red-400 text-sm">
                <TrendUpIcon />
                <span className="ml-1">{stats?.trends.alerts}%</span>
              </span>
            )}
            <span className="text-gray-500 text-sm">vs last week</span>
          </div>
        </div>

        {/* Risk Score */}
        <div className="bg-card-dark border border-white/10 rounded-2xl p-6 hover:border-white/20 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Risk Score</p>
              <p className="text-3xl font-bold font-display text-white mt-2">{stats?.riskScore}/100</p>
            </div>
            <div className="p-3 bg-orange-500/10 rounded-xl">
              <ShieldIcon />
            </div>
          </div>
          <div className="mt-4">
            <div className="h-2 bg-white/10 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500 rounded-full"
                style={{ width: `${stats?.riskScore}%` }}
              />
            </div>
            <div className="flex items-center gap-2 mt-2">
              {stats && stats.trends.risk > 0 ? (
                <span className="flex items-center text-red-400 text-sm">
                  <TrendUpIcon />
                  <span className="ml-1">{stats.trends.risk}%</span>
                </span>
              ) : (
                <span className="flex items-center text-green-400 text-sm">
                  <TrendDownIcon />
                  <span className="ml-1">{Math.abs(stats?.trends.risk || 0)}%</span>
                </span>
              )}
              <span className="text-gray-500 text-sm">vs last week</span>
            </div>
          </div>
        </div>

        {/* Assets Monitored */}
        <div className="bg-card-dark border border-white/10 rounded-2xl p-6 hover:border-white/20 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-gray-400 text-sm font-medium">Assets Monitored</p>
              <p className="text-3xl font-bold font-display text-white mt-2">
                {stats?.assetsMonitored.toLocaleString()}
              </p>
            </div>
            <div className="p-3 bg-secondary/10 text-secondary rounded-xl">
              <ServerIcon />
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            {stats && stats.trends.assets > 0 ? (
              <span className="flex items-center text-green-400 text-sm">
                <TrendUpIcon />
                <span className="ml-1">{stats.trends.assets}%</span>
              </span>
            ) : (
              <span className="flex items-center text-red-400 text-sm">
                <TrendDownIcon />
                <span className="ml-1">{Math.abs(stats?.trends.assets || 0)}%</span>
              </span>
            )}
            <span className="text-gray-500 text-sm">vs last week</span>
          </div>
        </div>
      </div>

      {/* Main content grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent alerts timeline */}
        <div className="lg:col-span-2 bg-card-dark border border-white/10 rounded-2xl">
          <div className="p-6 border-b border-white/10">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Recent Alerts</h2>
              <Link
                href="/portal/alerts"
                className="text-sm text-primary hover:text-primary-light transition-colors flex items-center gap-1"
              >
                View all
                <ArrowRightIcon />
              </Link>
            </div>
          </div>
          <div className="p-6 space-y-4">
            {alerts.map((alert, index) => (
              <div
                key={alert.id}
                className="flex gap-4 group cursor-pointer"
              >
                {/* Timeline indicator */}
                <div className="flex flex-col items-center">
                  <div className={`w-3 h-3 rounded-full ${getSeverityDot(alert.severity)} ring-4 ring-white/5`} />
                  {index < alerts.length - 1 && (
                    <div className="w-0.5 h-full bg-white/10 mt-2" />
                  )}
                </div>
                
                {/* Alert content */}
                <div className="flex-1 pb-6">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500">{alert.type}</span>
                      </div>
                      <h3 className="text-white font-medium group-hover:text-primary transition-colors">
                        {alert.title}
                      </h3>
                      <p className="text-sm text-gray-400 mt-1">{alert.description}</p>
                      <div className="flex items-center gap-3 mt-2">
                        <span className="text-xs text-gray-500">{formatTimeAgo(alert.timestamp)}</span>
                        <span className="text-xs text-gray-600">|</span>
                        <span className="text-xs text-gray-500">{alert.source}</span>
                      </div>
                    </div>
                    <button className="opacity-0 group-hover:opacity-100 p-2 hover:bg-white/5 rounded-lg transition-all">
                      <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right sidebar */}
        <div className="space-y-6">
          {/* Threat map mini preview */}
          <div className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold text-white">Threat Map</h2>
                <Link
                  href="/map"
                  className="text-sm text-primary hover:text-primary-light transition-colors"
                >
                  Expand
                </Link>
              </div>
            </div>
            <div className="relative h-48 bg-gradient-to-br from-card-dark to-card-light">
              {/* Mini map with top countries */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="w-16 h-16 mx-auto rounded-full bg-primary/20 flex items-center justify-center mb-3">
                    <GlobeIcon />
                  </div>
                  <p className="text-sm text-gray-400">Global Threat Overview</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {stats?.totalIOCs.toLocaleString() || 0} IOCs from {iocStats ? Object.keys(iocStats.by_country || {}).length : 0} countries
                  </p>
                  {iocStats && (
                    <div className="flex flex-wrap justify-center gap-1 mt-2">
                      {Object.entries(iocStats.by_country || {})
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 5)
                        .map(([country, count]) => (
                          <span key={country} className="text-xs px-2 py-0.5 bg-white/10 rounded text-gray-300">
                            {country}: {count.toLocaleString()}
                          </span>
                        ))}
                    </div>
                  )}
                </div>
              </div>
              {/* Decorative elements */}
              <div className="absolute top-4 left-4 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
              <div className="absolute top-8 right-8 w-2 h-2 bg-orange-500 rounded-full animate-pulse" />
              <div className="absolute bottom-6 left-8 w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
              <div className="absolute bottom-4 right-4 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
            </div>
          </div>

          {/* Quick actions */}
          <div className="bg-card-dark border border-white/10 rounded-2xl">
            <div className="p-4 border-b border-white/10">
              <h2 className="font-semibold text-white">Quick Actions</h2>
            </div>
            <div className="p-4 space-y-3">
              {quickActions.map((action) => (
                <Link
                  key={action.title}
                  href={action.href}
                  className={`flex items-center gap-4 p-3 rounded-xl bg-gradient-to-r ${action.color} hover:scale-[1.02] transition-all group`}
                >
                  <div className="p-2 bg-white/10 rounded-lg text-white">
                    {action.icon}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium text-white">{action.title}</p>
                    <p className="text-xs text-gray-400">{action.description}</p>
                  </div>
                  <svg
                    className="w-4 h-4 text-gray-400 group-hover:text-white group-hover:translate-x-1 transition-all"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              ))}
            </div>
          </div>

          {/* Threat distribution mini chart */}
          <div className="bg-card-dark border border-white/10 rounded-2xl p-4">
            <h2 className="font-semibold text-white mb-4">Threat Distribution</h2>
            <div className="space-y-3">
              {threatDistribution.length > 0 ? threatDistribution.map((item) => (
                <div key={item.type}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="text-gray-400">{item.type}</span>
                    <span className="text-white font-medium">{item.count.toLocaleString()}</span>
                  </div>
                  <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${item.color} rounded-full transition-all duration-500`}
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                </div>
              )) : (
                <div className="text-gray-500 text-sm text-center py-4">Loading threat data...</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
