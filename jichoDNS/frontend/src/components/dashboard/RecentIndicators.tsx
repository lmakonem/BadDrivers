"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { getThreatColor, getThreatLabel } from "@/lib/utils";
import { ExternalLink, Clock } from "lucide-react";

export function RecentIndicators() {
  const { data, isLoading } = useQuery({
    queryKey: ["recentIndicators"],
    queryFn: () => api.getIndicators({ page_size: 10 }),
    refetchInterval: 30000,
  });

  const indicators = data?.items || [];

  const getThreatTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "c2":
        return "C2";
      case "exfil":
      case "exfiltration":
        return "EX";
      case "phishing":
        return "PH";
      default:
        return "??";
    }
  };

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return "Just now";
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white">Recent Indicators</h2>
        <a
          href="/indicators"
          className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
        >
          View all
          <ExternalLink className="w-3 h-3" />
        </a>
      </div>

      {isLoading ? (
        <div className="text-gray-400 text-sm">Loading...</div>
      ) : indicators.length === 0 ? (
        <div className="text-gray-400 text-sm bg-gray-800 rounded-lg p-4 text-center">
          No indicators found. Feed importers will populate this list.
        </div>
      ) : (
        <div className="space-y-2">
          {indicators.map((indicator) => (
            <div
              key={indicator.id}
              className="bg-gray-800 rounded-lg p-3 border border-gray-700 hover:border-gray-600 transition-colors cursor-pointer"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className="text-xs font-mono px-1.5 py-0.5 rounded"
                      style={{
                        backgroundColor: getThreatColor(indicator.risk_score / 100) + "20",
                        color: getThreatColor(indicator.risk_score / 100),
                      }}
                    >
                      {getThreatTypeIcon(indicator.threat_type)}
                    </span>
                    <span className="text-sm text-white truncate font-mono">
                      {indicator.indicator}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-xs text-gray-400">
                    <span className="capitalize">{indicator.indicator_type}</span>
                    <span>|</span>
                    <span>{indicator.source}</span>
                    {indicator.country_code && (
                      <>
                        <span>|</span>
                        <span>{indicator.country_code}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <span
                    className="text-xs font-semibold"
                    style={{ color: getThreatColor(indicator.risk_score / 100) }}
                  >
                    {getThreatLabel(indicator.risk_score / 100)}
                  </span>
                  <span className="text-xs text-gray-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatTimeAgo(indicator.last_seen)}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
