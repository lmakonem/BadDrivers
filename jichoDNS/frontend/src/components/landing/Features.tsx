"use client";

import Link from "next/link";
import { MODULE_ICONS } from "@/components/brand/ModuleIcons";

const modules: Array<{
  id: string;
  href: string;
  title: string;
  subtitle: string;
  description: string;
  features: string[];
  stat: { value: string; label: string };
}> = [
  {
    id: "threat-intelligence",
    href: "/portal",
    title: "Threat Intelligence",
    subtitle: "Live IOC feeds · real-time",
    description:
      "Aggregated indicator feeds covering malicious domains, IPs, URLs, and hashes — enriched with geolocation, malware family, and MITRE ATT&CK context.",
    features: [
      "Malware, C2, phishing & DGA classification",
      "GeoIP + ASN enrichment for African networks",
      "Real-time WebSocket stream + REST API",
      "Elasticsearch-backed IOC search",
    ],
    stat: { value: "9", label: "Live feeds" },
  },
  {
    id: "dark-web",
    href: "/portal/darkweb",
    title: "Dark Web Monitoring",
    subtitle: "Leaks · breaches · forum mentions",
    description:
      "Monitoring for leaked credentials and breach data affecting African organisations — searchable by domain and email, with ownership-scoped results.",
    features: [
      "Credential exposure lookup by domain / email",
      "Breach dataset search",
      "Dark-web crawl & watchlist alerts",
      "Redacted, tenant-scoped results",
    ],
    stat: { value: "24/7", label: "Monitoring" },
  },
  {
    id: "brand-protection",
    href: "/portal/brand",
    title: "Brand Protection",
    subtitle: "Typosquats · lookalikes · CT logs",
    description:
      "Detect domains impersonating African brands — M-Pesa, Safaricom, banks, telcos — via typosquat generation and Certificate Transparency monitoring.",
    features: [
      "DNSTwist typosquat detection engine",
      "Certificate Transparency log monitoring",
      "Live DNS resolution & risk scoring",
      "Per-brand alert feed",
    ],
    stat: { value: "DNS", label: "Typosquat scan" },
  },
  {
    id: "attack-surface",
    href: "/portal/asm",
    title: "Attack Surface Management",
    subtitle: "Assets · exposure · CVEs",
    description:
      "Continuously discover your external footprint — subdomains, open ports, SSL posture, tech stack — and correlate with CVE intelligence.",
    features: [
      "Subdomain & asset discovery (crt.sh)",
      "Active port & exposed-service scanning",
      "SSL/TLS & HTTP security-header checks",
      "EPSS + CISA KEV CVE correlation",
    ],
    stat: { value: "CTEM", label: "Discovery" },
  },
  {
    id: "threat-reports",
    href: "/portal/reports",
    title: "Threat Reports",
    subtitle: "Automated · exportable",
    description:
      "Generate executive briefings, exposure assessments, and IOC analysis from your live threat data — rendered to clean, shareable HTML.",
    features: [
      "One-click report generation",
      "Executive summaries with risk scoring",
      "IOC & external-exposure deep-dives",
      "Owner-scoped, printable output",
    ],
    stat: { value: "Auto", label: "Reports" },
  },
  {
    id: "api-access",
    href: "/docs/api",
    title: "REST API & Integrations",
    subtitle: "REST · WebSocket · MISP",
    description:
      "Programmatic access to indicators and analysis, plus MISP feed integration and real-time streaming for your SIEM and SOAR pipelines.",
    features: [
      "REST endpoints for indicators & analysis",
      "WebSocket real-time IOC stream",
      "MISP event ingestion & correlation",
      "JSON responses for SIEM / SOAR",
    ],
    stat: { value: "REST", label: "API" },
  },
];

export function Features() {
  return (
    <section id="features" className="py-16 lg:py-24">
      <div className="max-w-[1200px] mx-auto px-6 lg:px-8">

        {/* section head — small green label + big left-aligned white title */}
        <div className="max-w-[760px] mb-12 lg:mb-16">
          <p className="font-display text-[13px] font-medium uppercase tracking-[0.16em] text-primary mb-4">
            Six integrated modules
          </p>
          <h2 className="font-display text-[clamp(1.9rem,3.5vw,2.75rem)] font-bold leading-[1.12] tracking-[-0.02em] text-white">
            Everything your SOC needs in one platform.
          </h2>
          <p className="mt-5 text-lg leading-relaxed text-[#94A3B8]">
            Threat intelligence, dark web monitoring, brand protection, attack surface
            management, threat reports, and API access — built for African enterprises.
          </p>
        </div>

        {/* restrained card grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 lg:gap-6">
          {modules.map((m) => {
            const Icon = MODULE_ICONS[m.id];
            return (
              <Link
                key={m.id}
                href={m.href}
                className="group flex flex-col min-w-0 p-6 lg:p-7 rounded-[14px] bg-card-dark border border-[#1E2A3D] transition-all duration-200 hover:border-primary hover:bg-card-hover hover:-translate-y-1"
              >
                {/* top row — green outline icon + subtle stat chip */}
                <div className="flex items-start justify-between mb-5">
                  <span className="text-primary" aria-hidden="true">
                    {Icon ? <Icon className="w-9 h-9" /> : null}
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#1E2A3D] px-2.5 py-1 text-[11px]">
                    <span className="font-semibold text-primary">{m.stat.value}</span>
                    <span className="text-[#94A3B8]">{m.stat.label}</span>
                  </span>
                </div>

                {/* title + subtitle */}
                <h3 className="font-display text-xl font-medium text-white mb-1">
                  {m.title}
                </h3>
                <p className="text-xs text-[#94A3B8] mb-3">{m.subtitle}</p>

                {/* description */}
                <p className="text-[15px] leading-relaxed text-[#94A3B8] mb-4 flex-1">
                  {m.description}
                </p>

                {/* feature bullets */}
                <ul className="space-y-2">
                  {m.features.map((f, i) => (
                    <li key={i} className="flex items-start gap-2 text-[13px] text-[#94A3B8]">
                      <svg className="w-3.5 h-3.5 shrink-0 mt-0.5 text-primary" viewBox="0 0 16 16" fill="currentColor">
                        <path fillRule="evenodd" d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/>
                      </svg>
                      {f}
                    </li>
                  ))}
                </ul>

                {/* learn more link */}
                <div className="mt-6 pt-4 border-t border-[#1E2A3D] flex items-center gap-1.5 font-display text-sm font-medium text-primary">
                  Learn more
                  <svg className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                </div>
              </Link>
            );
          })}
        </div>

        {/* bottom CTA */}
        <div className="mt-14 flex flex-col sm:flex-row items-start sm:items-center gap-4">
          <Link href="/signup" className="btn-primary">
            Get Started Free
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </Link>
          <p className="text-sm text-[#94A3B8]">No credit card required · Community tier always free</p>
        </div>
      </div>
    </section>
  );
}
