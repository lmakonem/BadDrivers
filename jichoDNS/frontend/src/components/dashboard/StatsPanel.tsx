"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { formatNumber } from "@/lib/utils";
import { Shield, Globe, AlertTriangle, Activity } from "lucide-react";

export function StatsPanel() {
  const { data: stats } = useQuery({
    queryKey: ["stats"],
    queryFn: api.getStats,
    refetchInterval: 60000,
  });

  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: api.getHealth,
    refetchInterval: 30000,
  });

  // Calculate stats
  const totalIndicators = stats?.total || 0;
  const activeCountries = Object.keys(stats?.by_country || {}).length;
  const threatTypes = Object.keys(stats?.by_threat_type || {}).length;

  const statCards = [
    {
      label: "Total IOCs",
      value: formatNumber(totalIndicators),
      icon: Shield,
      color: "#3b82f6",
    },
    {
      label: "Countries",
      value: activeCountries.toString(),
      icon: Globe,
      color: "#8b5cf6",
    },
    {
      label: "Threat Types",
      value: threatTypes.toString(),
      icon: AlertTriangle,
      color: "#f97316",
    },
    {
      label: "API Status",
      value: health?.status === "healthy" ? "Online" : "Offline",
      icon: Activity,
      color: health?.status === "healthy" ? "#22c55e" : "#ef4444",
    },
  ];

  return (
    <div className="mb-6">
      <h2 className="text-lg font-semibold text-white mb-4">Overview</h2>
      <div className="grid grid-cols-2 gap-3">
        {statCards.map((stat) => (
          <div
            key={stat.label}
            className="bg-gray-800 rounded-lg p-3 border border-gray-700"
          >
            <div className="flex items-center gap-2 mb-1">
              <stat.icon className="w-4 h-4" style={{ color: stat.color }} />
              <span className="text-xs text-gray-400">{stat.label}</span>
            </div>
            <div className="text-xl font-bold" style={{ color: stat.color }}>
              {stat.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
