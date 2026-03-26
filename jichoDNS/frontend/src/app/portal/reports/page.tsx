"use client";

import { useState, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";
import { apiFetch, apiFetchJSON } from "@/lib/fetch";

// ── Types ────────────────────────────────────────────────────────────────────

interface Report {
  id: string;
  title: string;
  type: string;
  status: string;
  severity: string;
  generated_at: string;
  date_range: string;
  description: string;
  stats: { iocs?: number; darkweb?: number; credentials?: number };
  pages: number;
  is_sample?: boolean;
}

interface ReportListResponse {
  reports: Report[];
  total: number;
  page: number;
  page_size: number;
}

interface SamplesResponse {
  reports: Report[];
  total: number;
}

type ReportFilter = "all" | "threat_intelligence" | "incident_summary" | "executive_briefing" | "ioc_analysis" | "dark_web_exposure";

// ── Constants ────────────────────────────────────────────────────────────────

const reportTypeLabels: Record<string, string> = {
  threat_intelligence: "Threat Intel",
  incident_summary: "Incident",
  executive_briefing: "Executive",
  ioc_analysis: "IOC Analysis",
  dark_web_exposure: "Dark Web",
};

const reportTypeColors: Record<string, string> = {
  threat_intelligence: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  incident_summary: "bg-red-500/20 text-red-400 border-red-500/30",
  executive_briefing: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  ioc_analysis: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  dark_web_exposure: "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

const severityColors: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

// ── Icons ────────────────────────────────────────────────────────────────────

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

const PrintIcon = () => (
  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
  </svg>
);

const XIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
  </svg>
);

const formatDate = (dateString: string) => {
  try {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return dateString; }
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [samples, setSamples] = useState<Report[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<ReportFilter>("all");
  const [page, setPage] = useState(1);
  const [showSamples, setShowSamples] = useState(false);

  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [viewingReport, setViewingReport] = useState<Report | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const [reportForm, setReportForm] = useState({
    report_type: "threat_intelligence",
    title: "",
    custom_prompt: "",
    include_iocs: true,
    include_darkweb: true,
    include_credentials: true,
    time_range: "7d",
    output_format: "html",
  });

  // ── Fetch reports ─────────────────────────────────────────────────────
  const fetchReports = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams();
    params.set("page", page.toString());
    params.set("page_size", "20");
    if (filter !== "all") params.set("report_type", filter);

    const data = await apiFetchJSON<ReportListResponse>(`/api/v1/reports?${params}`);
    if (data) { setReports(data.reports); setTotal(data.total); }
    else { setReports([]); setTotal(0); }
    setLoading(false);
  }, [page, filter]);

  // ── Fetch samples ─────────────────────────────────────────────────────
  const fetchSamples = useCallback(async () => {
    const data = await apiFetchJSON<SamplesResponse>("/api/v1/reports/samples");
    if (data) setSamples(data.reports);
  }, []);

  useEffect(() => { fetchReports(); fetchSamples(); }, [fetchReports, fetchSamples]);

  // ── Generate ──────────────────────────────────────────────────────────
  const handleGenerateReport = async () => {
    setGenerating(true); setGenError(null);
    try {
      const res = await apiFetch("/api/v1/reports/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_type: reportForm.report_type,
          title: reportForm.title || undefined,
          time_range: reportForm.time_range,
          include_iocs: reportForm.include_iocs,
          include_darkweb: reportForm.include_darkweb,
          include_credentials: reportForm.include_credentials,
          custom_prompt: reportForm.custom_prompt || undefined,
          output_format: reportForm.output_format,
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Failed (${res.status})`);
      }
      setShowGenerateModal(false);
      setReportForm({ report_type: "threat_intelligence", title: "", custom_prompt: "",
        include_iocs: true, include_darkweb: true, include_credentials: true,
        time_range: "7d", output_format: "html" });
      await fetchReports();
    } catch (err: unknown) {
      setGenError(err instanceof Error ? err.message : "Report generation failed");
    } finally { setGenerating(false); }
  };

  // ── Delete ────────────────────────────────────────────────────────────
  const handleDelete = async (id: string) => {
    if (!confirm("Delete this report permanently?")) return;
    setDeletingId(id);
    try { await apiFetch(`/api/v1/reports/${id}`, { method: "DELETE" }); await fetchReports(); }
    catch { /* swallow */ }
    finally { setDeletingId(null); }
  };

  // ── Download ──────────────────────────────────────────────────────────
  const handleDownload = async (report: Report) => {
    try {
      const res = await apiFetch(`/api/v1/reports/${report.id}/download?format=html`);
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${report.title.replace(/\s+/g, "_")}_${report.id.slice(0, 8)}.html`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch { /* swallow */ }
  };

  // ── Print / PDF ───────────────────────────────────────────────────────
  const handlePrint = (report: Report) => {
    (async () => {
      const res = await apiFetch(`/api/v1/reports/${report.id}/html`);
      if (!res.ok) return;
      const html = await res.text();
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    })();
  };

  // ── Which list to show ────────────────────────────────────────────────
  const displayReports = showSamples ? samples : reports;
  const displayTotal = showSamples ? samples.length : total;

  // ── Loading ───────────────────────────────────────────────────────────
  if (loading && reports.length === 0 && samples.length === 0) {
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

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Reports</h1>
          <p className="text-gray-400 mt-1">
            Generate and view threat intelligence reports from real data
            {displayTotal > 0 && <span className="ml-2 text-gray-500">({displayTotal} reports)</span>}
          </p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
        >
          <SparklesIcon />
          Generate Report
        </button>
      </div>

      {/* Tab bar: My Reports / Sample Reports */}
      <div className="flex gap-1 bg-card-dark rounded-xl p-1 w-fit">
        <button
          onClick={() => setShowSamples(false)}
          className={`px-5 py-2 rounded-lg font-medium text-sm transition-colors ${
            !showSamples ? "bg-primary text-white" : "text-gray-400 hover:text-white"
          }`}
        >
          My Reports {total > 0 && `(${total})`}
        </button>
        <button
          onClick={() => setShowSamples(true)}
          className={`px-5 py-2 rounded-lg font-medium text-sm transition-colors ${
            showSamples ? "bg-primary text-white" : "text-gray-400 hover:text-white"
          }`}
        >
          Sample Reports ({samples.length})
        </button>
      </div>

      {/* Filters (only for My Reports) */}
      {!showSamples && (
        <div className="flex flex-wrap gap-2">
          {([
            ["all", "All Reports"],
            ["threat_intelligence", "Threat Intel"],
            ["incident_summary", "Incident"],
            ["executive_briefing", "Executive"],
            ["ioc_analysis", "IOC Analysis"],
            ["dark_web_exposure", "Dark Web"],
          ] as [ReportFilter, string][]).map(([value, label]) => (
            <button
              key={value}
              onClick={() => { setFilter(value); setPage(1); }}
              className={`px-4 py-2 rounded-lg font-medium transition-colors text-sm ${
                filter === value
                  ? "bg-primary text-white"
                  : "bg-card-dark text-gray-400 hover:text-white hover:bg-card-light"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Reports grid */}
      {displayReports.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {displayReports.map((report) => (
            <div
              key={report.id}
              className="bg-card-dark border border-white/10 rounded-2xl overflow-hidden hover:border-white/20 transition-all group cursor-pointer"
              onClick={() => setViewingReport(report)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setViewingReport(report); }}
            >
              {/* Card header */}
              <div className="p-6 pb-4">
                <div className="flex items-start justify-between mb-3">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${reportTypeColors[report.type] || "bg-gray-500/20 text-gray-400 border-gray-500/30"}`}>
                    {reportTypeLabels[report.type] || report.type}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {report.is_sample && (
                      <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/25">
                        Sample
                      </span>
                    )}
                    <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/20 text-green-400">
                      Ready
                    </span>
                  </div>
                </div>

                <h3 className="text-lg font-semibold text-white group-hover:text-primary transition-colors line-clamp-2">
                  {report.title}
                </h3>

                {/* Description */}
                {report.description && (
                  <p className="text-sm text-gray-400 mt-2 line-clamp-2">{report.description}</p>
                )}

                {/* Stats summary */}
                <div className="flex gap-4 mt-3 text-xs text-gray-400">
                  {report.stats.iocs != null && report.stats.iocs > 0 && (
                    <span>{report.stats.iocs.toLocaleString()} IOCs</span>
                  )}
                  {(report.stats.darkweb ?? 0) > 0 && (
                    <span>{report.stats.darkweb!.toLocaleString()} DW</span>
                  )}
                  {(report.stats.credentials ?? 0) > 0 && (
                    <span>{report.stats.credentials!.toLocaleString()} creds</span>
                  )}
                </div>
              </div>

              {/* Meta */}
              <div className="px-6 py-4 border-t border-white/5">
                <div className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-1 text-gray-400">
                    <ClockIcon />
                    {formatDate(report.generated_at)}
                  </span>
                  <span className={`font-medium ${severityColors[report.severity] || "text-gray-400"}`}>
                    {report.severity?.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-2 text-xs text-gray-500">
                  <span>Period: {report.date_range || "7d"}</span>
                  {report.pages > 0 && <span>{report.pages} pages</span>}
                </div>
              </div>

              {/* Actions — stop propagation so button clicks don't also trigger the card click */}
              <div className="px-6 py-4 border-t border-white/5 bg-white/[0.02]" onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setViewingReport(report)}
                    className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-colors text-sm"
                  >
                    <EyeIcon />
                    View
                  </button>
                  <button
                    onClick={() => handleDownload(report)}
                    className="p-2 hover:bg-white/5 text-gray-400 hover:text-white rounded-lg transition-colors"
                    title="Download HTML"
                  >
                    <DownloadIcon />
                  </button>
                  <button
                    onClick={() => handlePrint(report)}
                    className="p-2 hover:bg-white/5 text-gray-400 hover:text-white rounded-lg transition-colors"
                    title="Open in new tab (print to PDF)"
                  >
                    <PrintIcon />
                  </button>
                  {!report.is_sample && (
                    <button
                      onClick={() => handleDelete(report.id)}
                      disabled={deletingId === report.id}
                      className="p-2 hover:bg-white/5 text-gray-400 hover:text-red-400 rounded-lg transition-colors disabled:opacity-50"
                      title="Delete"
                    >
                      {deletingId === report.id ? <LoadingSpinner /> : <TrashIcon />}
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-16">
          <div className="flex justify-center mb-4 text-gray-600"><DocumentIcon /></div>
          <h3 className="text-lg font-medium text-white">
            {showSamples ? "No sample reports available" : "No reports found"}
          </h3>
          <p className="text-gray-400 mt-2">
            {showSamples ? "Sample reports could not be loaded" : "Generate a new report to get started with real threat data"}
          </p>
          {!showSamples && (
            <div className="flex justify-center gap-3 mt-4">
              <button
                onClick={() => setShowGenerateModal(true)}
                className="px-4 py-2 bg-primary hover:bg-primary-hover text-white rounded-lg font-medium transition-colors"
              >
                Generate Report
              </button>
              <button
                onClick={() => setShowSamples(true)}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 text-gray-300 rounded-lg font-medium transition-colors"
              >
                View Samples
              </button>
            </div>
          )}
        </div>
      )}

      {/* Pagination (My Reports only) */}
      {!showSamples && total > 20 && (
        <div className="flex items-center justify-center gap-3 pt-4">
          <button
            onClick={() => setPage(Math.max(1, page - 1))} disabled={page <= 1}
            className="px-4 py-2 bg-card-dark text-gray-400 rounded-lg disabled:opacity-50 hover:text-white transition-colors"
          >Previous</button>
          <span className="text-gray-400 text-sm">Page {page} of {Math.ceil(total / 20)}</span>
          <button
            onClick={() => setPage(page + 1)} disabled={page * 20 >= total}
            className="px-4 py-2 bg-card-dark text-gray-400 rounded-lg disabled:opacity-50 hover:text-white transition-colors"
          >Next</button>
        </div>
      )}

      {/* ── Report Viewer Modal (portalled to body) ────────────────────── */}
      {viewingReport && typeof document !== "undefined" && createPortal(
        <div className="fixed inset-0 bg-black/80 flex flex-col" style={{ zIndex: 9999 }}>
          <div className="flex items-center justify-between px-6 py-3 bg-[#191A34] border-b border-white/10">
            <div className="flex items-center gap-3 min-w-0">
              <h2 className="text-white font-semibold truncate max-w-md">{viewingReport.title}</h2>
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium border shrink-0 ${reportTypeColors[viewingReport.type] || ""}`}>
                {reportTypeLabels[viewingReport.type] || viewingReport.type}
              </span>
              {viewingReport.is_sample && (
                <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/25 shrink-0">
                  Sample
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button onClick={() => handleDownload(viewingReport)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-gray-300 rounded-lg text-sm transition-colors">
                <DownloadIcon /> Download
              </button>
              <button onClick={() => handlePrint(viewingReport)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 text-gray-300 rounded-lg text-sm transition-colors">
                <PrintIcon /> Print / PDF
              </button>
              <button onClick={() => setViewingReport(null)}
                className="p-2 hover:bg-white/10 text-gray-400 hover:text-white rounded-lg transition-colors">
                <XIcon />
              </button>
            </div>
          </div>
          <div className="flex-1 overflow-hidden">
            <ReportIframe reportId={viewingReport.id} />
          </div>
        </div>,
        document.body,
      )}

      {/* ── Generate Report Modal (portalled to body) ────────────────────── */}
      {showGenerateModal && typeof document !== "undefined" && createPortal(
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4" style={{ zIndex: 9999 }}>
          <div className="bg-[#191A34] border border-white/10 rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                  <SparklesIcon /> Generate Report
                </h2>
                <button onClick={() => { setShowGenerateModal(false); setGenError(null); }}
                  className="p-2 hover:bg-white/5 rounded-lg text-gray-400 hover:text-white transition-colors">
                  <XIcon />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-5">
              {genError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">{genError}</div>
              )}

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Type</label>
                <select value={reportForm.report_type}
                  onChange={(e) => setReportForm({ ...reportForm, report_type: e.target.value })}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50">
                  <option value="threat_intelligence">Threat Intelligence Report</option>
                  <option value="executive_briefing">Executive Briefing</option>
                  <option value="ioc_analysis">IOC Analysis</option>
                  <option value="incident_summary">Incident Summary</option>
                  <option value="dark_web_exposure">Dark Web Exposure</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Title (optional)</label>
                <input type="text" value={reportForm.title}
                  onChange={(e) => setReportForm({ ...reportForm, title: e.target.value })}
                  placeholder="Auto-generated if left empty"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50" />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Focus Area (optional)</label>
                <textarea value={reportForm.custom_prompt}
                  onChange={(e) => setReportForm({ ...reportForm, custom_prompt: e.target.value })}
                  placeholder="e.g. Focus on phishing targeting Kenya banking sector..."
                  rows={3}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 resize-none" />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-3">Include Sections</label>
                <div className="grid grid-cols-2 gap-3">
                  {([
                    { key: "include_iocs", label: "IOC Analysis" },
                    { key: "include_darkweb", label: "Dark Web Intel" },
                    { key: "include_credentials", label: "Credential Exposure" },
                  ] as { key: keyof typeof reportForm; label: string }[]).map((item) => (
                    <label key={item.key}
                      className="flex items-center gap-3 p-3 bg-white/5 rounded-xl cursor-pointer hover:bg-white/10 transition-colors">
                      <input type="checkbox" checked={reportForm[item.key] as boolean}
                        onChange={(e) => setReportForm({ ...reportForm, [item.key]: e.target.checked })}
                        className="w-4 h-4 rounded border-white/20 bg-white/10 text-primary focus:ring-primary/50" />
                      <span className="text-sm text-gray-300">{item.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Date Range</label>
                <select value={reportForm.time_range}
                  onChange={(e) => setReportForm({ ...reportForm, time_range: e.target.value })}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50">
                  <option value="1h">Last Hour</option>
                  <option value="6h">Last 6 Hours</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                  <option value="90d">Last 90 Days</option>
                </select>
              </div>
            </div>

            <div className="p-6 border-t border-white/10 flex gap-3">
              <button onClick={() => { setShowGenerateModal(false); setGenError(null); }}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-gray-300 rounded-xl font-medium transition-colors">
                Cancel
              </button>
              <button onClick={handleGenerateReport} disabled={generating}
                className="flex-1 px-4 py-3 bg-primary hover:bg-primary-hover text-white rounded-xl font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50">
                {generating ? (<><LoadingSpinner /> Generating...</>) : (<><SparklesIcon /> Generate</>)}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}

// ── Report Iframe Component ──────────────────────────────────────────────────

function ReportIframe({ reportId }: { reportId: string }) {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch(`/api/v1/reports/${reportId}/html`);
        if (!res.ok) throw new Error("Failed to load");
        const text = await res.text();
        if (!cancelled) setHtml(text);
      } catch { if (!cancelled) setError(true); }
    })();
    return () => { cancelled = true; };
  }, [reportId]);

  if (error) {
    return <div className="flex items-center justify-center h-full text-red-400">Failed to load report</div>;
  }
  if (!html) {
    return <div className="flex items-center justify-center h-full"><LoadingSpinner /><span className="ml-2 text-gray-400">Loading report...</span></div>;
  }
  return <iframe srcDoc={html} className="w-full h-full border-0" title="Report Preview" sandbox="allow-same-origin" />;
}
