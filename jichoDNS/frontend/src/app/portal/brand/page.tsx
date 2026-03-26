"use client";

import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "@/lib/fetch";

// Types
interface Brand {
  id: string;
  name: string;
  domain: string;
  logo?: string;
  status: "active" | "paused";
  typosquatCount: number;
  phishingCount: number;
  lastScan: string;
  createdAt: string;
}

interface TyposquatDomain {
  id: string;
  domain: string;
  brandId: string;
  brandName: string;
  type: "homograph" | "typo" | "combosquat" | "soundsquat" | "bitsquat";
  similarity: number;
  registeredAt?: string;
  ipAddress?: string;
  hasContent: boolean;
  isPhishing: boolean;
  status: "active" | "taken_down" | "monitoring" | "investigating";
  discoveredAt: string;
  riskScore: number;
}

interface PhishingAlert {
  id: string;
  url: string;
  brandId: string;
  brandName: string;
  targetType: "login" | "payment" | "form" | "download";
  status: "active" | "taken_down" | "investigating";
  discoveredAt: string;
  screenshotUrl?: string;
  similarity: number;
  reportedTo: string[];
}

// Mock data
const mockBrands: Brand[] = [
  {
    id: "1",
    name: "Safaricom",
    domain: "safaricom.co.ke",
    status: "active",
    typosquatCount: 23,
    phishingCount: 5,
    lastScan: "2024-01-15T12:00:00Z",
    createdAt: "2024-01-01T00:00:00Z",
  },
  {
    id: "2",
    name: "M-Pesa",
    domain: "mpesa.com",
    status: "active",
    typosquatCount: 45,
    phishingCount: 12,
    lastScan: "2024-01-15T11:30:00Z",
    createdAt: "2024-01-01T00:00:00Z",
  },
  {
    id: "3",
    name: "KCB Bank",
    domain: "kcbgroup.com",
    status: "active",
    typosquatCount: 18,
    phishingCount: 3,
    lastScan: "2024-01-15T10:45:00Z",
    createdAt: "2024-01-05T00:00:00Z",
  },
  {
    id: "4",
    name: "Equity Bank",
    domain: "equitybankgroup.com",
    status: "active",
    typosquatCount: 15,
    phishingCount: 2,
    lastScan: "2024-01-15T09:00:00Z",
    createdAt: "2024-01-05T00:00:00Z",
  },
  {
    id: "5",
    name: "Airtel Kenya",
    domain: "airtel.co.ke",
    status: "paused",
    typosquatCount: 8,
    phishingCount: 1,
    lastScan: "2024-01-10T14:00:00Z",
    createdAt: "2024-01-08T00:00:00Z",
  },
];

const mockTyposquats: TyposquatDomain[] = [
  {
    id: "1",
    domain: "safar1com.co.ke",
    brandId: "1",
    brandName: "Safaricom",
    type: "homograph",
    similarity: 92,
    registeredAt: "2024-01-10T00:00:00Z",
    ipAddress: "185.123.45.67",
    hasContent: true,
    isPhishing: true,
    status: "active",
    discoveredAt: "2024-01-12T08:00:00Z",
    riskScore: 95,
  },
  {
    id: "2",
    domain: "safariicom.co.ke",
    brandId: "1",
    brandName: "Safaricom",
    type: "typo",
    similarity: 88,
    registeredAt: "2024-01-08T00:00:00Z",
    ipAddress: "192.168.1.1",
    hasContent: false,
    isPhishing: false,
    status: "monitoring",
    discoveredAt: "2024-01-09T14:30:00Z",
    riskScore: 45,
  },
  {
    id: "3",
    domain: "m-pesa-pay.com",
    brandId: "2",
    brandName: "M-Pesa",
    type: "combosquat",
    similarity: 75,
    registeredAt: "2024-01-05T00:00:00Z",
    ipAddress: "45.67.89.12",
    hasContent: true,
    isPhishing: true,
    status: "active",
    discoveredAt: "2024-01-06T10:00:00Z",
    riskScore: 98,
  },
  {
    id: "4",
    domain: "mpeza.com",
    brandId: "2",
    brandName: "M-Pesa",
    type: "typo",
    similarity: 85,
    registeredAt: "2024-01-01T00:00:00Z",
    hasContent: true,
    isPhishing: false,
    status: "monitoring",
    discoveredAt: "2024-01-02T16:45:00Z",
    riskScore: 60,
  },
  {
    id: "5",
    domain: "kcb-online.co.ke",
    brandId: "3",
    brandName: "KCB Bank",
    type: "combosquat",
    similarity: 70,
    registeredAt: "2024-01-11T00:00:00Z",
    ipAddress: "78.90.12.34",
    hasContent: true,
    isPhishing: true,
    status: "investigating",
    discoveredAt: "2024-01-13T09:00:00Z",
    riskScore: 88,
  },
  {
    id: "6",
    domain: "safaricom-rewards.com",
    brandId: "1",
    brandName: "Safaricom",
    type: "combosquat",
    similarity: 65,
    hasContent: false,
    isPhishing: false,
    status: "taken_down",
    discoveredAt: "2024-01-05T11:00:00Z",
    riskScore: 30,
  },
];

const mockPhishingAlerts: PhishingAlert[] = [
  {
    id: "1",
    url: "https://safar1com.co.ke/login",
    brandId: "1",
    brandName: "Safaricom",
    targetType: "login",
    status: "active",
    discoveredAt: "2024-01-15T08:30:00Z",
    similarity: 94,
    reportedTo: ["Google Safe Browsing"],
  },
  {
    id: "2",
    url: "https://m-pesa-pay.com/verify",
    brandId: "2",
    brandName: "M-Pesa",
    targetType: "payment",
    status: "active",
    discoveredAt: "2024-01-14T14:00:00Z",
    similarity: 89,
    reportedTo: ["Google Safe Browsing", "Microsoft SmartScreen"],
  },
  {
    id: "3",
    url: "https://kcb-online.co.ke/secure-login",
    brandId: "3",
    brandName: "KCB Bank",
    targetType: "login",
    status: "investigating",
    discoveredAt: "2024-01-13T10:15:00Z",
    similarity: 86,
    reportedTo: [],
  },
];

// Icons
const ShieldCheckIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const GlobeIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
);

const ExclamationIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const PlusIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
  </svg>
);

const ExternalLinkIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
  </svg>
);

const FlagIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 21v-4m0 0V5a2 2 0 012-2h6.5l1 1H21l-3 6 3 6h-8.5l-1-1H5a2 2 0 00-2 2zm9-13.5V9" />
  </svg>
);

const SearchIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
);

const RefreshIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
  </svg>
);

const typeColors: Record<TyposquatDomain["type"], string> = {
  homograph: "bg-red-500/20 text-red-400",
  typo: "bg-orange-500/20 text-orange-400",
  combosquat: "bg-yellow-500/20 text-yellow-400",
  soundsquat: "bg-blue-500/20 text-blue-400",
  bitsquat: "bg-purple-500/20 text-purple-400",
};

const statusColors = {
  active: "bg-red-500/20 text-red-400",
  taken_down: "bg-green-500/20 text-green-400",
  monitoring: "bg-blue-500/20 text-blue-400",
  investigating: "bg-yellow-500/20 text-yellow-400",
};

const phishingStatusColors = {
  active: "bg-red-500/20 text-red-400",
  taken_down: "bg-green-500/20 text-green-400",
  investigating: "bg-yellow-500/20 text-yellow-400",
};

const targetTypeLabels: Record<PhishingAlert["targetType"], string> = {
  login: "Login Page",
  payment: "Payment Form",
  form: "Data Form",
  download: "Malware Download",
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

type TabType = "brands" | "typosquats" | "phishing";

export default function BrandPage() {
  const [activeTab, setActiveTab] = useState<TabType>("brands");
  const [brands, setBrands] = useState<Brand[]>([]);
  const [typosquats, setTyposquats] = useState<TyposquatDomain[]>([]);
  const [phishingAlerts, setPhishingAlerts] = useState<PhishingAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddBrandModal, setShowAddBrandModal] = useState(false);
  const [brandForm, setBrandForm] = useState({
    name: "",
    domain: "",
    keywords: "",
  });
  const [searchQuery, setSearchQuery] = useState("");
  const [brandFilter, setBrandFilter] = useState<string>("all");

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      
      // Fetch brand data in parallel
      const [monitorsRes, typosquatsRes, alertsRes] = await Promise.allSettled([
        apiFetch(`/api/v1/brand/monitors?limit=50`),
        apiFetch(`/api/v1/brand/typosquats?limit=100`),
        apiFetch(`/api/v1/brand/alerts?limit=50`),
      ]);
      
      // Process brand monitors
      if (monitorsRes.status === "fulfilled" && monitorsRes.value.ok) {
        const monitorsData = await monitorsRes.value.json();
        const monitorsList = monitorsData.brands || monitorsData || [];
        setBrands(monitorsList.map((brand: Record<string, unknown>) => ({
          id: brand.id || brand._id || Math.random().toString(),
          name: brand.name || brand.brand_name || "Unknown",
          domain: brand.domain || brand.primary_domain || "",
          logo: brand.logo || undefined,
          status: brand.status || brand.active ? "active" : "paused",
          typosquatCount: brand.typosquat_count || brand.typosquatCount || 0,
          phishingCount: brand.phishing_count || brand.phishingCount || 0,
          lastScan: brand.last_scan || brand.lastScan || new Date().toISOString(),
          createdAt: brand.created_at || brand.createdAt || new Date().toISOString(),
        })));
      } else {
        setBrands(mockBrands);
      }
      
      // Process typosquats
      if (typosquatsRes.status === "fulfilled" && typosquatsRes.value.ok) {
        const typosquatsData = await typosquatsRes.value.json();
        const typosquatsList = typosquatsData.typosquats || typosquatsData || [];
        setTyposquats(typosquatsList.map((t: Record<string, unknown>) => ({
          id: t.id || t._id || Math.random().toString(),
          domain: t.domain || t.typosquat_domain || "",
          brandId: t.brand_id || t.brandId || "",
          brandName: t.brand_name || t.brandName || "Unknown",
          type: t.type || t.technique || "typo",
          similarity: t.similarity || t.similarity_score || 0,
          registeredAt: t.registered_at || t.registeredAt || undefined,
          ipAddress: t.ip_address || t.ipAddress || undefined,
          hasContent: t.has_content || t.hasContent || false,
          isPhishing: t.is_phishing || t.isPhishing || false,
          status: t.status || "monitoring",
          discoveredAt: t.discovered_at || t.discoveredAt || new Date().toISOString(),
          riskScore: t.risk_score || t.riskScore || 0,
        })));
      } else {
        setTyposquats(mockTyposquats);
      }
      
      // Process phishing alerts
      if (alertsRes.status === "fulfilled" && alertsRes.value.ok) {
        const alertsData = await alertsRes.value.json();
        const alertsList = (alertsData.alerts || alertsData || []).filter(
          (a: Record<string, unknown>) => a.alert_type === "phishing" || a.type === "phishing" || a.is_phishing
        );
        setPhishingAlerts(alertsList.map((a: Record<string, unknown>) => ({
          id: a.id || a._id || Math.random().toString(),
          url: a.url || a.domain || "",
          brandId: a.brand_id || a.brandId || "",
          brandName: a.brand_name || a.brandName || "Unknown",
          targetType: a.target_type || a.targetType || "login",
          status: a.status || "active",
          discoveredAt: a.discovered_at || a.discoveredAt || new Date().toISOString(),
          screenshotUrl: a.screenshot_url || a.screenshotUrl || undefined,
          similarity: a.similarity || 0,
          reportedTo: a.reported_to || a.reportedTo || [],
        })));
      } else {
        setPhishingAlerts(mockPhishingAlerts);
      }
      
    } catch (error) {
      console.error("Failed to fetch brand data:", error);
      setBrands(mockBrands);
      setTyposquats(mockTyposquats);
      setPhishingAlerts(mockPhishingAlerts);
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

  const filteredTyposquats = typosquats.filter((t) => {
    const matchesSearch = t.domain.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesBrand = brandFilter === "all" || t.brandId === brandFilter;
    return matchesSearch && matchesBrand;
  });

  const handleAddBrand = async () => {
    if (!brandForm.name.trim() || !brandForm.domain.trim()) return;

    const newBrand: Brand = {
      id: Date.now().toString(),
      name: brandForm.name.trim(),
      domain: brandForm.domain.trim(),
      status: "active",
      typosquatCount: 0,
      phishingCount: 0,
      lastScan: new Date().toISOString(),
      createdAt: new Date().toISOString(),
    };

    setBrands([newBrand, ...brands]);
    setShowAddBrandModal(false);
    
    // Call the real API to add brand monitor
    try {
      const response = await apiFetch(`/api/v1/brand/monitor`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          brand_name: brandForm.name.trim(),
          primary_domain: brandForm.domain.trim(),
          keywords: brandForm.keywords.split(",").map(k => k.trim()).filter(k => k),
        }),
      });
      
      if (response.ok) {
        // Refresh data to show updated results
        setTimeout(fetchData, 1000);
      }
    } catch (error) {
      console.error("Failed to add brand:", error);
    }
    
    setBrandForm({ name: "", domain: "", keywords: "" });
  };

  const handleToggleBrandStatus = (brandId: string) => {
    setBrands(brands.map((b) =>
      b.id === brandId
        ? { ...b, status: b.status === "active" ? "paused" : "active" }
        : b
    ));
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-64 bg-card-dark rounded animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[...Array(3)].map((_, i) => (
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
          <h1 className="text-2xl font-bold text-white">Brand Protection</h1>
          <p className="text-gray-400 mt-1">Monitor and protect your brands from impersonation</p>
        </div>
        <button
          onClick={() => setShowAddBrandModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
        >
          <PlusIcon />
          Add Brand
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400">
              <ShieldCheckIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{brands.filter((b) => b.status === "active").length}</p>
              <p className="text-sm text-gray-400">Monitored Brands</p>
            </div>
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-500/10 rounded-lg text-orange-400">
              <GlobeIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{typosquats.length}</p>
              <p className="text-sm text-gray-400">Typosquat Domains</p>
            </div>
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/10 rounded-lg text-red-400">
              <ExclamationIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{phishingAlerts.filter((p) => p.status === "active").length}</p>
              <p className="text-sm text-gray-400">Active Phishing</p>
            </div>
          </div>
        </div>
        <div className="bg-card-dark border border-white/10 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/10 rounded-lg text-green-400">
              <FlagIcon />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">
                {typosquats.filter((t) => t.status === "taken_down").length}
              </p>
              <p className="text-sm text-gray-400">Taken Down</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-card-dark border border-white/10 rounded-2xl">
        <div className="border-b border-white/10">
          <div className="flex gap-1 p-2">
            {[
              { id: "brands" as TabType, label: "Monitored Brands", count: brands.filter((b) => b.status === "active").length },
              { id: "typosquats" as TabType, label: "Typosquat Domains", count: typosquats.filter((t) => t.status === "active").length },
              { id: "phishing" as TabType, label: "Phishing Alerts", count: phishingAlerts.filter((p) => p.status === "active").length },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-primary/10 text-primary"
                    : "text-gray-400 hover:text-white hover:bg-white/5"
                }`}
              >
                {tab.label}
                {tab.count > 0 && (
                  <span className={`px-2 py-0.5 rounded-full text-xs ${
                    activeTab === tab.id ? "bg-primary/20 text-primary" : "bg-white/10 text-gray-400"
                  }`}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Tab content */}
        <div className="p-6">
          {/* Brands tab */}
          {activeTab === "brands" && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {brands.map((brand) => (
                <div
                  key={brand.id}
                  className={`p-4 border rounded-xl transition-colors ${
                    brand.status === "active"
                      ? "bg-white/[0.02] border-white/10 hover:border-white/20"
                      : "bg-white/[0.01] border-white/5 opacity-60"
                  }`}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center">
                        <span className="text-lg font-bold text-primary">
                          {brand.name.charAt(0)}
                        </span>
                      </div>
                      <div>
                        <h3 className="text-white font-semibold">{brand.name}</h3>
                        <p className="text-xs text-gray-400">{brand.domain}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => handleToggleBrandStatus(brand.id)}
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        brand.status === "active"
                          ? "bg-green-500/20 text-green-400"
                          : "bg-gray-500/20 text-gray-400"
                      }`}
                    >
                      {brand.status === "active" ? "Active" : "Paused"}
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="p-3 bg-white/5 rounded-lg">
                      <p className="text-lg font-bold text-orange-400">{brand.typosquatCount}</p>
                      <p className="text-xs text-gray-400">Typosquats</p>
                    </div>
                    <div className="p-3 bg-white/5 rounded-lg">
                      <p className="text-lg font-bold text-red-400">{brand.phishingCount}</p>
                      <p className="text-xs text-gray-400">Phishing</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>Last scan: {formatDate(brand.lastScan)}</span>
                    <button className="flex items-center gap-1 text-primary hover:text-primary-light transition-colors">
                      <RefreshIcon />
                      Scan
                    </button>
                  </div>
                </div>
              ))}

              {/* Add brand card */}
              <button
                onClick={() => setShowAddBrandModal(true)}
                className="p-4 border-2 border-dashed border-white/10 rounded-xl hover:border-primary/30 hover:bg-primary/5 transition-colors flex flex-col items-center justify-center min-h-[200px] group"
              >
                <div className="w-12 h-12 rounded-xl bg-white/5 group-hover:bg-primary/10 flex items-center justify-center mb-3 transition-colors">
                  <PlusIcon />
                </div>
                <p className="text-gray-400 group-hover:text-white transition-colors">Add New Brand</p>
              </button>
            </div>
          )}

          {/* Typosquats tab */}
          {activeTab === "typosquats" && (
            <div>
              {/* Filters */}
              <div className="flex flex-col sm:flex-row gap-4 mb-6">
                <div className="relative flex-1">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search domains..."
                    className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-primary/50"
                  />
                  <SearchIcon />
                </div>
                <select
                  value={brandFilter}
                  onChange={(e) => setBrandFilter(e.target.value)}
                  className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white focus:outline-none focus:border-primary/50"
                >
                  <option value="all">All Brands</option>
                  {brands.map((brand) => (
                    <option key={brand.id} value={brand.id}>{brand.name}</option>
                  ))}
                </select>
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-sm text-gray-400 border-b border-white/10">
                      <th className="pb-3 font-medium">Domain</th>
                      <th className="pb-3 font-medium">Brand</th>
                      <th className="pb-3 font-medium">Type</th>
                      <th className="pb-3 font-medium">Similarity</th>
                      <th className="pb-3 font-medium">Risk</th>
                      <th className="pb-3 font-medium">Status</th>
                      <th className="pb-3 font-medium">Discovered</th>
                      <th className="pb-3 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {filteredTyposquats.map((typo) => (
                      <tr key={typo.id} className="hover:bg-white/[0.02]">
                        <td className="py-4">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-medium">{typo.domain}</span>
                            {typo.isPhishing && (
                              <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-xs">
                                Phishing
                              </span>
                            )}
                          </div>
                          {typo.ipAddress && (
                            <p className="text-xs text-gray-500 mt-0.5">{typo.ipAddress}</p>
                          )}
                        </td>
                        <td className="py-4 text-sm text-gray-400">{typo.brandName}</td>
                        <td className="py-4">
                          <span className={`text-xs px-2 py-1 rounded capitalize ${typeColors[typo.type]}`}>
                            {typo.type}
                          </span>
                        </td>
                        <td className="py-4">
                          <div className="flex items-center gap-2">
                            <div className="w-12 h-1.5 bg-white/10 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary rounded-full"
                                style={{ width: `${typo.similarity}%` }}
                              />
                            </div>
                            <span className="text-sm text-gray-400">{typo.similarity}%</span>
                          </div>
                        </td>
                        <td className="py-4">
                          <span className={`text-sm font-medium ${getRiskColor(typo.riskScore)}`}>
                            {typo.riskScore}
                          </span>
                        </td>
                        <td className="py-4">
                          <span className={`text-xs px-2 py-1 rounded ${statusColors[typo.status]}`}>
                            {typo.status.replace("_", " ")}
                          </span>
                        </td>
                        <td className="py-4 text-sm text-gray-400">{formatDate(typo.discoveredAt)}</td>
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
            </div>
          )}

          {/* Phishing tab */}
          {activeTab === "phishing" && (
            <div className="space-y-4">
              {phishingAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="p-4 bg-white/[0.02] border border-white/5 rounded-xl hover:border-white/10 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className={`text-xs px-2 py-1 rounded ${phishingStatusColors[alert.status]}`}>
                          {alert.status.replace("_", " ").toUpperCase()}
                        </span>
                        <span className="text-xs px-2 py-1 bg-purple-500/20 text-purple-400 rounded">
                          {targetTypeLabels[alert.targetType]}
                        </span>
                        <span className="text-xs text-gray-500">{alert.similarity}% match</span>
                      </div>
                      
                      <h3 className="font-semibold text-white mb-2">
                        {alert.brandName} Phishing Detected
                      </h3>
                      
                      <div className="flex items-center gap-2 mb-3">
                        <code className="text-sm text-red-400 bg-red-500/10 px-2 py-1 rounded">
                          {alert.url}
                        </code>
                        <button className="p-1 hover:bg-white/5 rounded text-gray-400 hover:text-white transition-colors">
                          <ExternalLinkIcon />
                        </button>
                      </div>

                      {alert.reportedTo.length > 0 && (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500">Reported to:</span>
                          {alert.reportedTo.map((service) => (
                            <span key={service} className="text-xs px-2 py-0.5 bg-green-500/10 text-green-400 rounded">
                              {service}
                            </span>
                          ))}
                        </div>
                      )}

                      <p className="text-xs text-gray-500 mt-3">
                        Discovered {formatDate(alert.discoveredAt)}
                      </p>
                    </div>

                    <div className="flex flex-col gap-2">
                      {alert.status === "active" && (
                        <>
                          <button className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg text-sm transition-colors flex items-center gap-1">
                            <FlagIcon />
                            Report
                          </button>
                          <button className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-gray-300 rounded-lg text-sm transition-colors">
                            Takedown
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Add Brand Modal */}
      {showAddBrandModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-md">
            <div className="p-6 border-b border-white/10">
              <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                <ShieldCheckIcon />
                Add Brand to Monitor
              </h2>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Brand Name</label>
                <input
                  type="text"
                  value={brandForm.name}
                  onChange={(e) => setBrandForm({ ...brandForm, name: e.target.value })}
                  placeholder="e.g., Safaricom"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Primary Domain</label>
                <input
                  type="text"
                  value={brandForm.domain}
                  onChange={(e) => setBrandForm({ ...brandForm, domain: e.target.value })}
                  placeholder="e.g., safaricom.co.ke"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Additional Keywords (Optional)</label>
                <textarea
                  value={brandForm.keywords}
                  onChange={(e) => setBrandForm({ ...brandForm, keywords: e.target.value })}
                  placeholder="Enter related keywords, one per line"
                  rows={3}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 resize-none"
                />
              </div>
            </div>
            <div className="p-6 border-t border-white/10 flex gap-3">
              <button
                onClick={() => setShowAddBrandModal(false)}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAddBrand}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover text-white rounded-xl font-medium transition-colors"
              >
                Add Brand
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
