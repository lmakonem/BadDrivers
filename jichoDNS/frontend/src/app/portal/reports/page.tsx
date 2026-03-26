"use client";

import { useState, useEffect } from "react";

// Types
interface Report {
  id: string;
  title: string;
  description: string;
  type: "weekly" | "monthly" | "incident" | "custom" | "executive";
  severity: "critical" | "high" | "medium" | "low";
  status: "ready" | "generating" | "scheduled";
  createdAt: string;
  generatedBy: string;
  pages: number;
  format: "pdf" | "docx" | "html";
  downloadUrl?: string;
}

type ReportFilter = "all" | "weekly" | "monthly" | "incident" | "custom" | "executive";

// Mock data
const mockReports: Report[] = [
  {
    id: "1",
    title: "Weekly Threat Intelligence Report",
    description: "Comprehensive analysis of threats targeting African networks including C2 activity, phishing campaigns, and emerging malware.",
    type: "weekly",
    severity: "high",
    status: "ready",
    createdAt: "2024-01-15T08:00:00Z",
    generatedBy: "AI Analysis Engine",
    pages: 24,
    format: "pdf",
    downloadUrl: "#",
  },
  {
    id: "2",
    title: "Executive Security Summary - January 2024",
    description: "High-level overview of security posture, key metrics, and strategic recommendations for leadership.",
    type: "executive",
    severity: "medium",
    status: "ready",
    createdAt: "2024-01-14T10:30:00Z",
    generatedBy: "AI Analysis Engine",
    pages: 8,
    format: "pdf",
    downloadUrl: "#",
  },
  {
    id: "3",
    title: "M-Pesa Phishing Campaign Incident Report",
    description: "Detailed analysis of coordinated phishing campaign targeting M-Pesa customers with IOCs and remediation steps.",
    type: "incident",
    severity: "critical",
    status: "ready",
    createdAt: "2024-01-13T14:45:00Z",
    generatedBy: "Security Team",
    pages: 32,
    format: "pdf",
    downloadUrl: "#",
  },
  {
    id: "4",
    title: "December 2023 Monthly Summary",
    description: "Monthly aggregation of threat intelligence, trend analysis, and security metrics.",
    type: "monthly",
    severity: "medium",
    status: "ready",
    createdAt: "2024-01-01T09:00:00Z",
    generatedBy: "AI Analysis Engine",
    pages: 45,
    format: "pdf",
    downloadUrl: "#",
  },
  {
    id: "5",
    title: "Custom ASN Analysis - Safaricom",
    description: "Deep dive analysis of threats specifically targeting Safaricom network infrastructure.",
    type: "custom",
    severity: "high",
    status: "generating",
    createdAt: "2024-01-15T11:00:00Z",
    generatedBy: "AI Analysis Engine",
    pages: 0,
    format: "pdf",
  },
  {
    id: "6",
    title: "Weekly Threat Intelligence Report",
    description: "Comprehensive analysis of threats targeting African networks.",
    type: "weekly",
    severity: "medium",
    status: "scheduled",
    createdAt: "2024-01-22T08:00:00Z",
    generatedBy: "Scheduled",
    pages: 0,
    format: "pdf",
  },
];

const reportTypeLabels: Record<Report["type"], string> = {
  weekly: "Weekly",
  monthly: "Monthly",
  incident: "Incident",
  custom: "Custom",
  executive: "Executive",
};

const reportTypeColors: Record<Report["type"], string> = {
  weekly: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  monthly: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  incident: "bg-red-500/20 text-red-400 border-red-500/30",
  custom: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  executive: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

const severityColors: Record<Report["severity"], string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

const statusColors: Record<Report["status"], string> = {
  ready: "bg-green-500/20 text-green-400",
  generating: "bg-yellow-500/20 text-yellow-400",
  scheduled: "bg-gray-500/20 text-gray-400",
};

// Icons
const DocumentIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);

const DownloadIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
  </svg>
);

const SparklesIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
  </svg>
);

const ClockIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const EyeIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
  </svg>
);

const TrashIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
  </svg>
);

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<ReportFilter>("all");
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [generating, setGenerating] = useState(false);

  // Form state for generating reports
  const [reportForm, setReportForm] = useState({
    type: "custom" as Report["type"],
    title: "",
    description: "",
    includeIOCs: true,
    includeAlerts: true,
    includeASM: true,
    includeDarkWeb: true,
    dateRange: "7d",
    format: "pdf" as "pdf" | "docx" | "html",
  });

  useEffect(() => {
    const fetchReports = async () => {
      try {
        await new Promise((resolve) => setTimeout(resolve, 800));
        setReports(mockReports);
      } catch (error) {
        console.error("Failed to fetch reports:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

  const filteredReports = filter === "all" 
    ? reports 
    : reports.filter((r) => r.type === filter);

  const handleGenerateReport = async () => {
    setGenerating(true);
    try {
      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 2000));
      
      const newReport: Report = {
        id: Date.now().toString(),
        title: reportForm.title || `Custom Report - ${new Date().toLocaleDateString()}`,
        description: reportForm.description || "AI-generated threat intelligence report",
        type: reportForm.type,
        severity: "medium",
        status: "generating",
        createdAt: new Date().toISOString(),
        generatedBy: "AI Analysis Engine",
        pages: 0,
        format: reportForm.format,
      };

      setReports([newReport, ...reports]);
      setShowGenerateModal(false);
      setReportForm({
        type: "custom",
        title: "",
        description: "",
        includeIOCs: true,
        includeAlerts: true,
        includeASM: true,
        includeDarkWeb: true,
        dateRange: "7d",
        format: "pdf",
      });
    } catch (error) {
      console.error("Failed to generate report:", error);
    } finally {
      setGenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-card-dark rounded animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-64 bg-card-dark rounded-2xl animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Reports</h1>
          <p className="text-gray-400 mt-1">AI-powered threat intelligence reports and analysis</p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
        >
          <SparklesIcon />
          Generate Report
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        {(["all", "weekly", "monthly", "incident", "custom", "executive"] as ReportFilter[]).map((type) => (
          <button
            key={type}
            onClick={() => setFilter(type)}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              filter === type
                ? "bg-primary text-white"
                : "bg-card-dark text-gray-400 hover:text-white hover:bg-card-light"
            }`}
          >
            {type === "all" ? "All Reports" : reportTypeLabels[type as Report["type"]]}
          </button>
        ))}
      </div>

      {/* Reports grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredReports.map((report) => (
          <div
            key={report.id}
            className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden hover:border-white/20 transition-all group"
          >
            {/* Report header */}
            <div className="p-6 pb-4">
              <div className="flex items-start justify-between mb-3">
                <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${reportTypeColors[report.type]}`}>
                  {reportTypeLabels[report.type]}
                </span>
                <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${statusColors[report.status]}`}>
                  {report.status === "generating" && <LoadingSpinner />}
                  {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                </span>
              </div>
              
              <h3 className="text-lg font-semibold text-white group-hover:text-primary transition-colors line-clamp-2">
                {report.title}
              </h3>
              
              <p className="text-sm text-gray-400 mt-2 line-clamp-2">
                {report.description}
              </p>
            </div>

            {/* Report meta */}
            <div className="px-6 py-4 border-t border-white/5">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-4 text-gray-400">
                  <span className="flex items-center gap-1">
                    <ClockIcon />
                    {formatDate(report.createdAt)}
                  </span>
                </div>
                <span className={`font-medium ${severityColors[report.severity]}`}>
                  {report.severity.toUpperCase()}
                </span>
              </div>
              
              <div className="flex items-center justify-between mt-3 text-sm text-gray-500">
                <span>{report.generatedBy}</span>
                {report.pages > 0 && <span>{report.pages} pages</span>}
              </div>
            </div>

            {/* Actions */}
            <div className="px-6 py-4 border-t border-white/5 bg-white/[0.02]">
              <div className="flex items-center gap-2">
                {report.status === "ready" && (
                  <>
                    <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-colors">
                      <DownloadIcon />
                      Download {report.format.toUpperCase()}
                    </button>
                    <button className="p-2 hover:bg-white/5 text-gray-400 hover:text-white rounded-lg transition-colors">
                      <EyeIcon />
                    </button>
                    <button className="p-2 hover:bg-white/5 text-gray-400 hover:text-red-400 rounded-lg transition-colors">
                      <TrashIcon />
                    </button>
                  </>
                )}
                {report.status === "generating" && (
                  <div className="flex-1 text-center py-2 text-yellow-400 text-sm">
                    Report is being generated...
                  </div>
                )}
                {report.status === "scheduled" && (
                  <div className="flex-1 text-center py-2 text-gray-400 text-sm">
                    Scheduled for {formatDate(report.createdAt)}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Empty state */}
      {filteredReports.length === 0 && (
        <div className="text-center py-16">
          <DocumentIcon />
          <h3 className="text-lg font-medium text-white mt-4">No reports found</h3>
          <p className="text-gray-400 mt-2">Generate a new report to get started</p>
          <button
            onClick={() => setShowGenerateModal(true)}
            className="mt-4 px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
          >
            Generate Report
          </button>
        </div>
      )}

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-card-dark border border-white/10 rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                  <SparklesIcon />
                  Generate AI Report
                </h2>
                <button
                  onClick={() => setShowGenerateModal(false)}
                  className="p-2 hover:bg-white/5 rounded-lg text-gray-400 hover:text-white transition-colors"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              {/* Report type */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Type</label>
                <select
                  value={reportForm.type}
                  onChange={(e) => setReportForm({ ...reportForm, type: e.target.value as Report["type"] })}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                >
                  <option value="custom">Custom Analysis</option>
                  <option value="weekly">Weekly Summary</option>
                  <option value="monthly">Monthly Summary</option>
                  <option value="incident">Incident Report</option>
                  <option value="executive">Executive Brief</option>
                </select>
              </div>

              {/* Title */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Title (Optional)</label>
                <input
                  type="text"
                  value={reportForm.title}
                  onChange={(e) => setReportForm({ ...reportForm, title: e.target.value })}
                  placeholder="Auto-generated if left empty"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Focus Area (Optional)</label>
                <textarea
                  value={reportForm.description}
                  onChange={(e) => setReportForm({ ...reportForm, description: e.target.value })}
                  placeholder="Describe what you want the report to focus on..."
                  rows={3}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 resize-none"
                />
              </div>

              {/* Include sections */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">Include Sections</label>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { key: "includeIOCs", label: "IOC Analysis" },
                    { key: "includeAlerts", label: "Alert Summary" },
                    { key: "includeASM", label: "Attack Surface" },
                    { key: "includeDarkWeb", label: "Dark Web Intel" },
                  ].map((item) => (
                    <label
                      key={item.key}
                      className="flex items-center gap-3 p-3 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={reportForm[item.key as keyof typeof reportForm] as boolean}
                        onChange={(e) =>
                          setReportForm({ ...reportForm, [item.key]: e.target.checked })
                        }
                        className="w-4 h-4 rounded border-white/20 bg-white/10 text-primary focus:ring-primary/50"
                      />
                      <span className="text-sm text-gray-300">{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Date range */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Date Range</label>
                <select
                  value={reportForm.dateRange}
                  onChange={(e) => setReportForm({ ...reportForm, dateRange: e.target.value })}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50"
                >
                  <option value="24h">Last 24 hours</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                  <option value="90d">Last 90 days</option>
                </select>
              </div>

              {/* Format */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Output Format</label>
                <div className="flex gap-3">
                  {(["pdf", "docx", "html"] as const).map((format) => (
                    <button
                      key={format}
                      onClick={() => setReportForm({ ...reportForm, format })}
                      className={`flex-1 px-4 py-3 rounded-xl font-medium transition-colors ${
                        reportForm.format === format
                          ? "bg-primary text-white"
                          : "bg-white/5 text-gray-400 hover:bg-white/10"
                      }`}
                    >
                      {format.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex gap-3">
              <button
                onClick={() => setShowGenerateModal(false)}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateReport}
                disabled={generating}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover text-white rounded-xl font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {generating ? (
                  <>
                    <LoadingSpinner />
                    Generating...
                  </>
                ) : (
                  <>
                    <SparklesIcon />
                    Generate Report
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
