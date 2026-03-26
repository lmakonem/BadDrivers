"use client";

import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "@/lib/fetch";

// Types
interface Asset {
  id: string;
  asset: string;
  type: "domain" | "subdomain" | "ip" | "port" | "certificate";
  status: "active" | "inactive" | "unknown";
  discoveredAt: string;
  lastSeen: string;
  riskScore: number;
  vulnerabilities: number;
  services: string[];
  tags: string[];
}

interface Vulnerability {
  id: string;
  title: string;
  asset: string;
  severity: "critical" | "high" | "medium" | "low";
  cve?: string;
  description: string;
  discoveredAt: string;
  status: "open" | "in_progress" | "resolved";
  remediation?: string;
}

interface AssetTypeStat {
  type: string;
  count: number;
  percentage: number;
  color: string;
}

interface DiscoveryJob {
  id: string;
  domain: string;
  status: "running" | "completed" | "failed";
  progress: number;
  startedAt: string;
  assetsFound: number;
}

// Mock data
const mockAssets: Asset[] = [
  {
    id: "1",
    asset: "api.company.co.ke",
    type: "subdomain",
    status: "active",
    discoveredAt: "2024-01-10T08:00:00Z",
    lastSeen: "2024-01-15T12:30:00Z",
    riskScore: 85,
    vulnerabilities: 3,
    services: ["HTTPS", "REST API"],
    tags: ["production", "external"],
  },
  {
    id: "2",
    asset: "mail.company.co.ke",
    type: "subdomain",
    status: "active",
    discoveredAt: "2024-01-10T08:00:00Z",
    lastSeen: "2024-01-15T12:30:00Z",
    riskScore: 65,
    vulnerabilities: 1,
    services: ["SMTP", "IMAP"],
    tags: ["production", "internal"],
  },
  {
    id: "3",
    asset: "dev.company.co.ke",
    type: "subdomain",
    status: "active",
    discoveredAt: "2024-01-12T14:20:00Z",
    lastSeen: "2024-01-15T10:00:00Z",
    riskScore: 92,
    vulnerabilities: 5,
    services: ["HTTP", "SSH"],
    tags: ["development", "exposed"],
  },
  {
    id: "4",
    asset: "192.168.1.100",
    type: "ip",
    status: "active",
    discoveredAt: "2024-01-11T09:15:00Z",
    lastSeen: "2024-01-15T11:45:00Z",
    riskScore: 45,
    vulnerabilities: 0,
    services: ["HTTPS"],
    tags: ["internal"],
  },
  {
    id: "5",
    asset: "legacy.company.co.ke",
    type: "subdomain",
    status: "inactive",
    discoveredAt: "2024-01-08T16:00:00Z",
    lastSeen: "2024-01-10T08:00:00Z",
    riskScore: 78,
    vulnerabilities: 2,
    services: ["HTTP"],
    tags: ["deprecated", "needs-decommission"],
  },
  {
    id: "6",
    asset: "cdn.company.co.ke",
    type: "subdomain",
    status: "active",
    discoveredAt: "2024-01-13T11:30:00Z",
    lastSeen: "2024-01-15T12:00:00Z",
    riskScore: 25,
    vulnerabilities: 0,
    services: ["HTTPS", "CDN"],
    tags: ["production", "cloudflare"],
  },
  {
    id: "7",
    asset: "*.company.co.ke",
    type: "certificate",
    status: "active",
    discoveredAt: "2024-01-01T00:00:00Z",
    lastSeen: "2024-01-15T12:30:00Z",
    riskScore: 15,
    vulnerabilities: 0,
    services: ["TLS 1.3"],
    tags: ["wildcard", "lets-encrypt"],
  },
];

const mockVulnerabilities: Vulnerability[] = [
  {
    id: "1",
    title: "Outdated TLS Configuration",
    asset: "api.company.co.ke",
    severity: "high",
    description: "TLS 1.0 and 1.1 are enabled which are known to have security vulnerabilities.",
    discoveredAt: "2024-01-14T10:00:00Z",
    status: "open",
    remediation: "Disable TLS 1.0 and 1.1, enable only TLS 1.2 and 1.3",
  },
  {
    id: "2",
    title: "Missing Security Headers",
    asset: "dev.company.co.ke",
    severity: "medium",
    description: "Security headers like X-Frame-Options, X-Content-Type-Options are missing.",
    discoveredAt: "2024-01-13T14:30:00Z",
    status: "in_progress",
    remediation: "Add security headers to web server configuration",
  },
  {
    id: "3",
    title: "Exposed SSH Port",
    asset: "dev.company.co.ke",
    severity: "critical",
    cve: "N/A",
    description: "SSH port 22 is exposed to the internet without IP restrictions.",
    discoveredAt: "2024-01-12T09:00:00Z",
    status: "open",
    remediation: "Restrict SSH access to VPN or specific IP ranges",
  },
  {
    id: "4",
    title: "SSL Certificate Expiring Soon",
    asset: "mail.company.co.ke",
    severity: "medium",
    description: "SSL certificate expires in 15 days.",
    discoveredAt: "2024-01-15T08:00:00Z",
    status: "open",
    remediation: "Renew SSL certificate before expiration",
  },
  {
    id: "5",
    title: "Exposed Debug Endpoints",
    asset: "dev.company.co.ke",
    severity: "critical",
    description: "Debug endpoints are accessible without authentication.",
    discoveredAt: "2024-01-14T16:45:00Z",
    status: "open",
    remediation: "Disable debug endpoints or add authentication",
  },
];

const mockAssetTypes: AssetTypeStat[] = [
  { type: "Subdomains", count: 45, percentage: 52, color: "bg-blue-500" },
  { type: "IP Addresses", count: 23, percentage: 27, color: "bg-purple-500" },
  { type: "Ports", count: 12, percentage: 14, color: "bg-orange-500" },
  { type: "Certificates", count: 6, percentage: 7, color: "bg-green-500" },
];

const mockDiscoveryJobs: DiscoveryJob[] = [
  {
    id: "1",
    domain: "company.co.ke",
    status: "running",
    progress: 67,
    startedAt: "2024-01-15T12:00:00Z",
    assetsFound: 34,
  },
];

// Icons
const GlobeIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
);

const ServerIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
  </svg>
);

const ShieldExclamationIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const SearchIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
);

const PlayIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const ChartPieIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
  </svg>
);

const ExternalLinkIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
  </svg>
);

const severityColors = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/20 text-green-400 border-green-500/30",
};

const statusColors = {
  active: "bg-green-500/20 text-green-400",
  inactive: "bg-gray-500/20 text-gray-400",
  unknown: "bg-yellow-500/20 text-yellow-400",
};

const vulnStatusColors = {
  open: "bg-red-500/20 text-red-400",
  in_progress: "bg-yellow-500/20 text-yellow-400",
  resolved: "bg-green-500/20 text-green-400",
};

const assetTypeIcons: Record<Asset["type"], React.ReactNode> = {
  domain: <GlobeIcon />,
  subdomain: <GlobeIcon />,
  ip: <ServerIcon />,
  port: <ServerIcon />,
  certificate: <ShieldExclamationIcon />,
};

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const getRiskColor = (score: number) => {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-yellow-400";
  return "text-green-400";
};

const getRiskGradient = (score: number) => {
  if (score >= 80) return "from-red-500 to-red-600";
  if (score >= 60) return "from-orange-500 to-orange-600";
  if (score >= 40) return "from-yellow-500 to-yellow-600";
  return "from-green-500 to-green-600";
};

type TabType = "assets" | "vulnerabilities";

export default function ASMPage() {
  const [activeTab, setActiveTab] = useState<TabType>("assets");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [assetTypes, setAssetTypes] = useState<AssetTypeStat[]>([]);
  const [discoveryJobs, setDiscoveryJobs] = useState<DiscoveryJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDiscoveryModal, setShowDiscoveryModal] = useState(false);
  const [discoveryForm, setDiscoveryForm] = useState({
    domain: "",
    includeSubdomains: true,
    includePorts: true,
    includeCerts: true,
  });
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      
      // Fetch ASM data in parallel
      const [assetsRes, vulnsRes, _statsRes] = await Promise.allSettled([
        apiFetch(`/api/v1/asm/assets?limit=100`),
        apiFetch(`/api/v1/asm/vulnerabilities?limit=100`),
        apiFetch(`/api/v1/asm/stats`),
      ]);
      // Stats response available for future use
      void _statsRes;
      
      // Process assets
      if (assetsRes.status === "fulfilled" && assetsRes.value.ok) {
        const assetsData = await assetsRes.value.json();
        const assetsList = assetsData.assets || assetsData || [];
        setAssets(assetsList.map((asset: Record<string, unknown>) => ({
          id: asset.id || asset._id || Math.random().toString(),
          asset: asset.asset || asset.hostname || asset.ip || asset.value || "Unknown",
          type: asset.type || "domain",
          status: asset.status || "active",
          discoveredAt: asset.discovered_at || asset.discoveredAt || new Date().toISOString(),
          lastSeen: asset.last_seen || asset.lastSeen || new Date().toISOString(),
          riskScore: asset.risk_score || asset.riskScore || 0,
          vulnerabilities: asset.vulnerability_count || asset.vulnerabilities || 0,
          services: asset.services || [],
          tags: asset.tags || [],
        })));
        
        // Calculate asset type stats from real data
        if (assetsData.by_type) {
          const total = Object.values(assetsData.by_type as Record<string, number>).reduce((a: number, b: number) => a + b, 0);
          const colors = ["bg-blue-500", "bg-purple-500", "bg-green-500", "bg-orange-500", "bg-red-500"];
          setAssetTypes(Object.entries(assetsData.by_type as Record<string, number>).map(([type, count], i) => ({
            type,
            count: count as number,
            percentage: Math.round(((count as number) / total) * 100),
            color: colors[i % colors.length],
          })));
        }
      } else {
        // Fall back to mock data
        setAssets(mockAssets);
        setAssetTypes(mockAssetTypes);
      }
      
      // Process vulnerabilities
      if (vulnsRes.status === "fulfilled" && vulnsRes.value.ok) {
        const vulnsData = await vulnsRes.value.json();
        const vulnsList = vulnsData.vulnerabilities || vulnsData || [];
        setVulnerabilities(vulnsList.map((vuln: Record<string, unknown>) => ({
          id: vuln.id || vuln._id || Math.random().toString(),
          title: vuln.title || vuln.name || "Unknown Vulnerability",
          asset: vuln.asset || vuln.asset_id || "Unknown",
          severity: vuln.severity || "medium",
          cve: vuln.cve || vuln.cve_id || undefined,
          description: vuln.description || "",
          discoveredAt: vuln.discovered_at || vuln.discoveredAt || new Date().toISOString(),
          status: vuln.status || "open",
          remediation: vuln.remediation || undefined,
        })));
      } else {
        setVulnerabilities(mockVulnerabilities);
      }
      
      // Keep mock discovery jobs for now
      setDiscoveryJobs(mockDiscoveryJobs);
      
    } catch (error) {
      console.error("Failed to fetch ASM data:", error);
      // Fall back to mock data
      setAssets(mockAssets);
      setVulnerabilities(mockVulnerabilities);
      setAssetTypes(mockAssetTypes);
      setDiscoveryJobs(mockDiscoveryJobs);
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

  const filteredAssets = assets.filter((asset) => {
    const matchesSearch = asset.asset.toLowerCase().includes(searchQuery.toLowerCase()) ||
      asset.tags.some((tag) => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = typeFilter === "all" || asset.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const handleStartDiscovery = async () => {
    if (!discoveryForm.domain.trim()) return;

    const newJob: DiscoveryJob = {
      id: Date.now().toString(),
      domain: discoveryForm.domain.trim(),
      status: "running",
      progress: 0,
      startedAt: new Date().toISOString(),
      assetsFound: 0,
    };

    setDiscoveryJobs([newJob, ...discoveryJobs]);
    setShowDiscoveryModal(false);
    
    // Call the real API to start discovery
    try {
      const response = await apiFetch(`/api/v1/asm/discover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: discoveryForm.domain.trim(),
          include_subdomains: discoveryForm.includeSubdomains,
          include_ports: discoveryForm.includePorts,
          include_ssl: discoveryForm.includeCerts,
        }),
      });
      
      if (response.ok) {
        const result = await response.json();
        // Update the job with results
        setDiscoveryJobs(jobs => jobs.map(j => 
          j.id === newJob.id 
            ? { ...j, status: "completed" as const, progress: 100, assetsFound: result.assets_found || 0 }
            : j
        ));
        // Refresh data to show new assets
        setTimeout(fetchData, 1000);
      } else {
        setDiscoveryJobs(jobs => jobs.map(j => 
          j.id === newJob.id ? { ...j, status: "failed" as const } : j
        ));
      }
    } catch (error) {
      console.error("Discovery failed:", error);
      setDiscoveryJobs(jobs => jobs.map(j => 
        j.id === newJob.id ? { ...j, status: "failed" as const } : j
      ));
    }
    
    setDiscoveryForm({
      domain: "",
      includeSubdomains: true,
      includePorts: true,
      includeCerts: true,
    });
  };

  // Calculate overall risk score
  const overallRiskScore = Math.round(
    assets.reduce((acc, a) => acc + a.riskScore, 0) / (assets.length || 1)
  );

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-64 bg-card-dark rounded animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 bg-card-dark rounded-2xl animate-pulse" />
          ))}
        </div>
        <div className="h-96 bg-card-dark rounded-2xl animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Attack Surface Management</h1>
          <p className="text-gray-400 mt-1">Discover and monitor your external attack surface</p>
        </div>
        <button
          onClick={() => setShowDiscoveryModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
        >
          <PlayIcon />
          Start Discovery
        </button>
      </div>

      {/* Running discovery jobs */}
      {discoveryJobs.filter((j) => j.status === "running").length > 0 && (
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
          {discoveryJobs
            .filter((j) => j.status === "running")
            .map((job) => (
              <div key={job.id} className="flex items-center gap-4">
                <LoadingSpinner />
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-white font-medium">
                      Scanning {job.domain}...
                    </span>
                    <span className="text-sm text-blue-400">{job.assetsFound} assets found</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 rounded-full transition-all duration-500"
                      style={{ width: `${job.progress}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Assets */}
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400">
              <GlobeIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{assets.length}</p>
              <p className="text-sm text-gray-400">Total Assets</p>
            </div>
          </div>
        </div>

        {/* Active Assets */}
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/10 rounded-lg text-green-400">
              <ServerIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {assets.filter((a) => a.status === "active").length}
              </p>
              <p className="text-sm text-gray-400">Active Assets</p>
            </div>
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/10 rounded-lg text-red-400">
              <ShieldExclamationIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {vulnerabilities.filter((v) => v.status === "open").length}
              </p>
              <p className="text-sm text-gray-400">Open Vulnerabilities</p>
            </div>
          </div>
        </div>

        {/* Risk Score Gauge */}
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="relative w-12 h-12">
              <svg className="w-12 h-12 transform -rotate-90">
                <circle
                  cx="24"
                  cy="24"
                  r="20"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="4"
                  className="text-white/10"
                />
                <circle
                  cx="24"
                  cy="24"
                  r="20"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="4"
                  strokeDasharray={`${(overallRiskScore / 100) * 126} 126`}
                  className={getRiskColor(overallRiskScore)}
                />
              </svg>
              <span className={`absolute inset-0 flex items-center justify-center text-sm font-bold ${getRiskColor(overallRiskScore)}`}>
                {overallRiskScore}
              </span>
            </div>
            <div>
              <p className="text-sm text-gray-400">Overall Risk</p>
              <p className={`font-medium ${getRiskColor(overallRiskScore)}`}>
                {overallRiskScore >= 80 ? "Critical" : overallRiskScore >= 60 ? "High" : overallRiskScore >= 40 ? "Medium" : "Low"}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Main content */}
        <div className="lg:col-span-3 bg-card-dark border border-white/10 rounded-2xl">
          {/* Tabs and search */}
          <div className="p-4 border-b border-white/10">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex gap-2">
                <button
                  onClick={() => setActiveTab("assets")}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    activeTab === "assets"
                      ? "bg-primary/10 text-primary"
                      : "text-gray-400 hover:text-white hover:bg-white/5"
                  }`}
                >
                  Assets ({assets.length})
                </button>
                <button
                  onClick={() => setActiveTab("vulnerabilities")}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    activeTab === "vulnerabilities"
                      ? "bg-primary/10 text-primary"
                      : "text-gray-400 hover:text-white hover:bg-white/5"
                  }`}
                >
                  Vulnerabilities ({vulnerabilities.filter((v) => v.status === "open").length})
                </button>
              </div>
              <div className="flex gap-3">
                <div className="relative">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search assets..."
                    className="pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 w-64"
                  />
                  <SearchIcon />
                </div>
                {activeTab === "assets" && (
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white focus:outline-none focus:border-primary/50"
                  >
                    <option value="all">All Types</option>
                    <option value="domain">Domains</option>
                    <option value="subdomain">Subdomains</option>
                    <option value="ip">IP Addresses</option>
                    <option value="certificate">Certificates</option>
                  </select>
                )}
              </div>
            </div>
          </div>

          {/* Tab content */}
          <div className="p-6">
            {/* Assets tab */}
            {activeTab === "assets" && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-sm text-gray-400 border-b border-white/10">
                      <th className="pb-3 font-medium">Asset</th>
                      <th className="pb-3 font-medium">Type</th>
                      <th className="pb-3 font-medium">Status</th>
                      <th className="pb-3 font-medium">Services</th>
                      <th className="pb-3 font-medium">Risk</th>
                      <th className="pb-3 font-medium">Vulns</th>
                      <th className="pb-3 font-medium">Last Seen</th>
                      <th className="pb-3 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id} className="hover:bg-white/[0.02]">
                        <td className="py-4">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-white/5 rounded-lg text-gray-400">
                              {assetTypeIcons[asset.type]}
                            </div>
                            <div>
                              <p className="text-white font-medium">{asset.asset}</p>
                              <div className="flex gap-1 mt-1">
                                {asset.tags.slice(0, 2).map((tag) => (
                                  <span key={tag} className="text-xs px-1.5 py-0.5 bg-white/5 rounded text-gray-400">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="py-4 text-sm text-gray-400 capitalize">{asset.type}</td>
                        <td className="py-4">
                          <span className={`text-xs px-2 py-1 rounded ${statusColors[asset.status]}`}>
                            {asset.status}
                          </span>
                        </td>
                        <td className="py-4">
                          <div className="flex gap-1">
                            {asset.services.slice(0, 2).map((svc) => (
                              <span key={svc} className="text-xs px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded">
                                {svc}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-white/10 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full bg-gradient-to-r ${getRiskGradient(asset.riskScore)}`}
                                style={{ width: `${asset.riskScore}%` }}
                              />
                            </div>
                            <span className={`text-sm font-medium ${getRiskColor(asset.riskScore)}`}>
                              {asset.riskScore}
                            </span>
                          </div>
                        </td>
                        <td className="py-4">
                          {asset.vulnerabilities > 0 ? (
                            <span className="text-sm text-red-400 font-medium">{asset.vulnerabilities}</span>
                          ) : (
                            <span className="text-sm text-gray-500">0</span>
                          )}
                        </td>
                        <td className="py-4 text-sm text-gray-400">{formatDate(asset.lastSeen)}</td>
                        <td className="py-4">
                          <button className="p-2 hover:bg-white/5 rounded-lg text-gray-400 hover:text-white transition-colors">
                            <ExternalLinkIcon />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Vulnerabilities tab */}
            {activeTab === "vulnerabilities" && (
              <div className="space-y-4">
                {vulnerabilities.map((vuln) => (
                  <div
                    key={vuln.id}
                    className="p-4 bg-white/[0.02] border border-white/5 rounded-xl hover:border-white/10 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className={`text-xs px-2 py-1 rounded border ${severityColors[vuln.severity]}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          <span className={`text-xs px-2 py-1 rounded ${vulnStatusColors[vuln.status]}`}>
                            {vuln.status.replace("_", " ").toUpperCase()}
                          </span>
                          {vuln.cve && (
                            <span className="text-xs text-gray-500">{vuln.cve}</span>
                          )}
                        </div>
                        <h3 className="text-lg font-semibold text-white">{vuln.title}</h3>
                        <p className="text-sm text-gray-400 mt-1">
                          <span className="text-gray-500">Asset:</span> {vuln.asset}
                        </p>
                        <p className="text-sm text-gray-400 mt-2">{vuln.description}</p>
                        {vuln.remediation && (
                          <div className="mt-3 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
                            <p className="text-xs text-green-400 font-medium mb-1">Remediation</p>
                            <p className="text-sm text-gray-300">{vuln.remediation}</p>
                          </div>
                        )}
                        <p className="text-xs text-gray-500 mt-3">Discovered {formatDate(vuln.discoveredAt)}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Asset types breakdown */}
          <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
            <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
              <ChartPieIcon />
              Asset Distribution
            </h2>
            <div className="space-y-3">
              {assetTypes.map((type) => (
                <div key={type.type}>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="text-gray-400">{type.type}</span>
                    <span className="text-white font-medium">{type.count}</span>
                  </div>
                  <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${type.color} rounded-full`}
                      style={{ width: `${type.percentage}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Risk score gauge */}
          <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
            <h2 className="font-semibold text-white mb-4">Risk Score</h2>
            <div className="flex flex-col items-center">
              <div className="relative w-32 h-32">
                <svg className="w-32 h-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="8"
                    className="text-white/10"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="8"
                    strokeDasharray={`${(overallRiskScore / 100) * 352} 352`}
                    className={getRiskColor(overallRiskScore)}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={`text-3xl font-bold ${getRiskColor(overallRiskScore)}`}>
                    {overallRiskScore}
                  </span>
                  <span className="text-xs text-gray-400">out of 100</span>
                </div>
              </div>
              <div className="mt-4 text-center">
                <p className={`font-medium ${getRiskColor(overallRiskScore)}`}>
                  {overallRiskScore >= 80 ? "Critical Risk" : overallRiskScore >= 60 ? "High Risk" : overallRiskScore >= 40 ? "Medium Risk" : "Low Risk"}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  Based on {assets.length} assets
                </p>
              </div>
            </div>
          </div>

          {/* Quick stats */}
          <div className="bg-card-dark border border-white/10 rounded-2xl p-6">
            <h2 className="font-semibold text-white mb-4">Vulnerability Summary</h2>
            <div className="space-y-3">
              {[
                { severity: "Critical", count: vulnerabilities.filter((v) => v.severity === "critical" && v.status === "open").length, color: "bg-red-500" },
                { severity: "High", count: vulnerabilities.filter((v) => v.severity === "high" && v.status === "open").length, color: "bg-orange-500" },
                { severity: "Medium", count: vulnerabilities.filter((v) => v.severity === "medium" && v.status === "open").length, color: "bg-yellow-500" },
                { severity: "Low", count: vulnerabilities.filter((v) => v.severity === "low" && v.status === "open").length, color: "bg-green-500" },
              ].map((item) => (
                <div key={item.severity} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${item.color}`} />
                    <span className="text-sm text-gray-400">{item.severity}</span>
                  </div>
                  <span className="text-white font-medium">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Discovery Modal */}
      {showDiscoveryModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                <PlayIcon />
                Start Discovery
              </h2>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Root Domain</label>
                <input
                  type="text"
                  value={discoveryForm.domain}
                  onChange={(e) => setDiscoveryForm({ ...discoveryForm, domain: e.target.value })}
                  placeholder="e.g., company.co.ke"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">Discovery Options</label>
                <div className="space-y-3">
                  {[
                    { key: "includeSubdomains", label: "Discover Subdomains", description: "Find all subdomains via DNS enumeration" },
                    { key: "includePorts", label: "Port Scanning", description: "Scan for open ports and services" },
                    { key: "includeCerts", label: "Certificate Discovery", description: "Find SSL/TLS certificates" },
                  ].map((item) => (
                    <label
                      key={item.key}
                      className="flex items-start gap-3 p-3 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={discoveryForm[item.key as keyof typeof discoveryForm] as boolean}
                        onChange={(e) =>
                          setDiscoveryForm({ ...discoveryForm, [item.key]: e.target.checked })
                        }
                        className="mt-1 w-4 h-4 rounded border-white/20 bg-white/10 text-primary focus:ring-primary/50"
                      />
                      <div>
                        <p className="text-sm text-white font-medium">{item.label}</p>
                        <p className="text-xs text-gray-400">{item.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <div className="p-6 border-t border-white/10 flex gap-3">
              <button
                onClick={() => setShowDiscoveryModal(false)}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleStartDiscovery}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover text-white rounded-xl font-medium transition-colors flex items-center justify-center gap-2"
              >
                <PlayIcon />
                Start Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
