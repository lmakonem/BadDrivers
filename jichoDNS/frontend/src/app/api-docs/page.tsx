"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

const PAID_TIERS = new Set(["professional", "enterprise"]);

function hasPaidAccess(tier?: string, isAdmin?: boolean): boolean {
  if (isAdmin) return true;
  return PAID_TIERS.has(tier || "");
}

export default function APIDocsPage() {
  const { user, loading } = useAuth();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const paid = hasPaidAccess(user?.tier, user?.is_admin);

  if (loading || !mounted) {
    return (
      <div className="min-h-screen bg-ebony-950 flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-ebony-950">
      {/* Header */}
      <header className="border-b border-white/10 bg-card-dark/50 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <span className="text-white font-bold text-sm">JS</span>
            </div>
            <span className="text-lg font-semibold text-white">JichoSec</span>
          </Link>
          <div className="flex items-center gap-4">
            {user ? (
              <Link
                href="/portal"
                className="px-4 py-2 text-sm text-white bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
              >
                Portal
              </Link>
            ) : (
              <>
                <Link
                  href="/login"
                  className="px-4 py-2 text-sm text-gray-300 hover:text-white transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  href="/signup"
                  className="px-4 py-2 text-sm text-white bg-primary hover:bg-primary-hover rounded-lg transition-colors"
                >
                  Sign Up
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {paid ? (
        /* ── Full docs for paying members ────────────────────────── */
        <div className="w-full" style={{ height: "calc(100vh - 64px)" }}>
          <iframe
            src={`${API_BASE}/docs`}
            className="w-full h-full border-0"
            title="JichoSec API Documentation"
          />
        </div>
      ) : (
        /* ── Teaser for non-paying / anonymous users ─────────────── */
        <main className="max-w-4xl mx-auto px-6 py-20">
          <div className="text-center mb-12">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
              <span className="text-sm font-medium text-primary">API Reference</span>
            </div>
            <h1 className="text-4xl lg:text-5xl font-bold text-white mb-6">
              JichoSec <span className="text-primary">REST API</span>
            </h1>
          </div>

          {/* Teaser content */}
          <div className="prose prose-invert max-w-none mb-12">
            <div className="bg-card-dark border border-white/10 rounded-2xl p-8 mb-8">
              <p className="text-lg text-white/70 leading-relaxed">
                The JichoSec API gives your security team programmatic access to
                Africa&apos;s most comprehensive threat intelligence platform.
                Query over 100,000 indicators of compromise in real time, pull
                enriched IOC feeds into your SIEM or SOAR, and automate domain
                analysis with our ML-powered classification engine &mdash; all through
                a clean REST interface with JSON responses and JWT authentication.
              </p>
              <p className="text-lg text-white/70 leading-relaxed mt-4">
                Professional and Enterprise subscribers get full access to every
                endpoint, including live threat feeds, regional risk scores,
                dark-web monitoring hooks, brand-protection alerts, and bulk
                analysis. Rate limits scale with your plan &mdash; from 1,000
                requests/month on the free tier to unlimited on Enterprise.
              </p>
            </div>

            {/* Sample endpoints preview */}
            <div className="bg-card-dark border border-white/10 rounded-2xl p-8 mb-8">
              <h3 className="text-xl font-semibold text-white mb-6">Available Endpoints</h3>
              <div className="space-y-3 font-mono text-sm">
                {[
                  { method: "GET", path: "/api/v1/indicators/stats", desc: "Threat statistics" },
                  { method: "GET", path: "/api/v1/indicators/live/feed", desc: "Live IOC feed" },
                  { method: "GET", path: "/api/v1/regions/countries", desc: "Country risk scores" },
                  { method: "POST", path: "/api/v1/analysis/domain", desc: "Analyze a domain" },
                  { method: "GET", path: "/api/v1/darkweb/stats", desc: "Dark web monitoring" },
                  { method: "GET", path: "/api/v1/brand/alerts", desc: "Brand protection" },
                  { method: "WS", path: "/api/v1/ws/iocs", desc: "Real-time IOC stream" },
                ].map((ep) => (
                  <div key={ep.path} className="flex items-center gap-4 py-2 border-b border-white/5 last:border-0">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                      ep.method === "GET" ? "bg-green-500/20 text-green-400" :
                      ep.method === "POST" ? "bg-blue-500/20 text-blue-400" :
                      "bg-purple-500/20 text-purple-400"
                    }`}>{ep.method}</span>
                    <span className="text-white/60 flex-1">{ep.path}</span>
                    <span className="text-white/30 text-xs">{ep.desc}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 pt-4 border-t border-white/10 text-center">
                <span className="text-white/30 text-sm">
                  + 20 more endpoints available to subscribers
                </span>
              </div>
            </div>
          </div>

          {/* CTA */}
          <div className="text-center bg-gradient-to-r from-primary/10 via-card-dark to-primary/10 border border-primary/20 rounded-2xl p-10">
            <div className="w-16 h-16 mx-auto rounded-full bg-primary/20 flex items-center justify-center mb-6">
              <svg className="w-8 h-8 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-white mb-3">
              Unlock Full API Access
            </h2>
            <p className="text-white/50 mb-8 max-w-md mx-auto">
              {user
                ? "Upgrade to Professional to get full interactive API documentation, code samples, and higher rate limits."
                : "Join JichoSec to get API access. Professional and Enterprise plans include full interactive documentation and generous rate limits."}
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              {user ? (
                <Link
                  href="/pricing"
                  className="px-8 py-3 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-colors shadow-lg shadow-primary/25"
                >
                  Upgrade Now
                </Link>
              ) : (
                <>
                  <Link
                    href="/signup?plan=pro"
                    className="px-8 py-3 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-colors shadow-lg shadow-primary/25"
                  >
                    Start Free Trial
                  </Link>
                  <Link
                    href="/login"
                    className="px-8 py-3 bg-white/5 hover:bg-white/10 text-white font-medium rounded-full border border-white/10 transition-colors"
                  >
                    Sign In
                  </Link>
                </>
              )}
            </div>
          </div>
        </main>
      )}
    </div>
  );
}
