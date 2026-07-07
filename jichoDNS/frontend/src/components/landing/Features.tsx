"use client";

import Link from "next/link";
import { MODULE_ICONS } from "@/components/brand/ModuleIcons";

// Two-tone accent system — gold (signal) + cyan (network), no rainbow.
type Tone = "gold" | "cyan";

const tones: Record<
  Tone,
  { glow: string; border: string; iconBg: string; check: string; badge: string; hover: string }
> = {
  gold: {
    glow: "from-primary/12 to-transparent",
    border: "hover:border-primary/40",
    iconBg: "bg-primary/10 text-primary ring-1 ring-primary/20",
    check: "text-primary",
    badge: "bg-primary/15 text-primary border-primary/25",
    hover: "group-hover:text-primary",
  },
  cyan: {
    glow: "from-secondary/12 to-transparent",
    border: "hover:border-secondary/40",
    iconBg: "bg-secondary/10 text-secondary ring-1 ring-secondary/20",
    check: "text-secondary",
    badge: "bg-secondary/15 text-secondary border-secondary/25",
    hover: "group-hover:text-secondary",
  },
};

const modules: Array<{
  id: string;
  href: string;
  title: string;
  subtitle: string;
  description: string;
  features: string[];
  stat: { value: string; label: string };
  tone: Tone;
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
    stat: { value: "12", label: "Live feeds" },
    tone: "gold",
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
    tone: "cyan",
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
    tone: "gold",
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
    tone: "cyan",
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
    tone: "gold",
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
    tone: "cyan",
  },
];

export function Features() {
  return (
    <section id="features" className="relative py-20 bg-body-dark overflow-hidden">
      {/* circuit-board backdrop + ambient glows — the section signature */}
      <div className="absolute inset-0 circuit-grid opacity-40 pointer-events-none" />
      <div className="absolute inset-0 glow-gold pointer-events-none" />
      <div className="absolute inset-0 glow-cyan pointer-events-none" />

      {/* faint PCB trace cluster, top-right */}
      <svg
        className="absolute top-6 right-6 w-72 h-44 opacity-20 pointer-events-none hidden lg:block"
        viewBox="0 0 260 160"
        fill="none"
        aria-hidden="true"
      >
        <g stroke="#38e1d0" strokeWidth="1.2" strokeLinecap="round" className="circuit-trace">
          <path d="M8 22 H96 L118 44 H196" />
          <path d="M8 66 H64 L86 88 H160 L182 110 H252" />
          <path d="M44 140 H128 L150 118 H222" />
        </g>
        <g fill="#f5b62c">
          <circle cx="96" cy="22" r="2" /><circle cx="196" cy="44" r="2" />
          <circle cx="160" cy="88" r="2" /><circle cx="222" cy="118" r="2" />
          <circle cx="128" cy="140" r="2" />
        </g>
      </svg>

      <div className="relative z-10 max-w-[1680px] mx-auto px-6 lg:px-10">

        {/* section header */}
        <div className="text-center max-w-3xl mx-auto mb-12">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20 mb-5">
            <span className="text-sm font-medium text-primary">6 Integrated Modules</span>
          </div>
          <h2 className="font-display text-4xl lg:text-5xl font-bold text-white mb-4">
            Everything Your SOC Needs
            <span className="gradient-text"> in One Platform</span>
          </h2>
          <p className="text-lg text-white/50 leading-relaxed">
            Threat intelligence, dark web monitoring, brand protection, attack surface
            management, threat reports, and API access — built for African enterprises.
          </p>
        </div>

        {/* 3-column grid on large, 2-col on md, 1-col on mobile */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {modules.map((m) => {
            const t = tones[m.tone];
            const Icon = MODULE_ICONS[m.id];
            return (
              <Link
                key={m.id}
                href={m.href}
                className={`group relative flex flex-col min-w-0 p-6 rounded-2xl bg-card-dark border border-white/10 ${t.border} transition-all duration-300 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-black/30`}
              >
                {/* hover gradient overlay */}
                <div className={`absolute inset-0 rounded-2xl bg-gradient-to-br ${t.glow} opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />

                <div className="relative z-10 flex flex-col h-full">
                  {/* top row */}
                  <div className="flex items-start justify-between mb-4">
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${t.iconBg} group-hover:scale-105 transition-transform`}>
                      {Icon ? <Icon className="w-7 h-7" /> : null}
                    </div>
                    <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${t.badge}`}>
                      {m.stat.value} <span className="font-normal opacity-80">{m.stat.label}</span>
                    </span>
                  </div>

                  {/* title */}
                  <h3 className={`font-display text-lg font-semibold text-white mb-0.5 transition-colors ${t.hover}`}>
                    {m.title}
                  </h3>
                  <p className="text-xs text-white/35 mb-3">{m.subtitle}</p>

                  {/* description */}
                  <p className="text-sm text-white/55 leading-relaxed mb-4 flex-1">
                    {m.description}
                  </p>

                  {/* feature bullets */}
                  <ul className="space-y-2">
                    {m.features.map((f, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-white/50">
                        <svg className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${t.check}`} viewBox="0 0 16 16" fill="currentColor">
                          <path fillRule="evenodd" d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/>
                        </svg>
                        {f}
                      </li>
                    ))}
                  </ul>

                  {/* bottom link arrow */}
                  <div className={`mt-5 pt-4 border-t border-white/10 flex items-center gap-1.5 text-xs font-medium text-white/30 transition-colors ${t.hover}`}>
                    Explore module
                    <svg className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                  </div>
                </div>
              </Link>
            );
          })}
        </div>

        {/* bottom CTA */}
        <div className="mt-12 text-center">
          <Link
            href="/signup"
            className="btn-primary rounded-full px-8 py-3.5"
          >
            Get Started Free
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </Link>
          <p className="mt-3 text-sm text-white/30">No credit card required · Community tier always free</p>
        </div>
      </div>
    </section>
  );
}
