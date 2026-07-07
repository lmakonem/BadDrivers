"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Menu, X, ChevronDown } from "lucide-react";
import { JichoMark } from "@/components/brand/JichoMark";

// ── All 6 product modules ────────────────────────────────────────────────────
const PRODUCTS = [
  {
    name: "Threat Intelligence",
    href: "/portal",
    anchorHref: "#threat-intelligence",
    description: "37,000+ IOCs from 15+ feeds. Real-time C2, malware, phishing with full context.",
    badge: "37K+ IOCs",
    badgeColor: "bg-purple-500/15 text-purple-300",
    color: "text-purple-400",
    bg: "bg-purple-500/10 group-hover:bg-purple-500/20",
    subItems: [
      { label: "IOC Search & Lookup",    href: "/portal",          desc: "Query domains, IPs, URLs, hashes" },
      { label: "Threat Feed Browser",    href: "/portal",          desc: "Browse all 15+ source feeds" },
      { label: "Domain Analysis",        href: "/analysis",        desc: "DGA detection, entropy, classification" },
      { label: "API Access",             href: "/docs/api",        desc: "REST API for SIEM/SOAR integration" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    name: "Dark Web Monitoring",
    href: "/portal/darkweb",
    anchorHref: "#dark-web",
    description: "Credential leaks, data breaches, underground forum mentions across Africa.",
    badge: "200+ Leaks",
    badgeColor: "bg-blue-500/15 text-blue-300",
    color: "text-blue-400",
    bg: "bg-blue-500/10 group-hover:bg-blue-500/20",
    subItems: [
      { label: "Credential Leak Monitor", href: "/portal/darkweb", desc: "Search leaked emails & passwords" },
      { label: "Data Breach Tracker",     href: "/portal/darkweb", desc: "Known breaches affecting your org" },
      { label: "Forum & Telegram Watch",  href: "/portal/darkweb", desc: "Threat actor mentions & discussions" },
      { label: "Exposure Check",          href: "/portal/darkweb", desc: "Email exposure lookup" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.8"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" stroke="currentColor" strokeWidth="1.8"/>
        <path d="M2 12h20" stroke="currentColor" strokeWidth="1.8"/>
      </svg>
    ),
  },
  {
    name: "Brand Protection",
    href: "/portal/brand",
    anchorHref: "#brand-protection",
    description: "Typosquat detection, phishing kit monitoring, and takedowns for African brands.",
    badge: "39+ Typosquats",
    badgeColor: "bg-orange-500/15 text-orange-300",
    color: "text-orange-400",
    bg: "bg-orange-500/10 group-hover:bg-orange-500/20",
    subItems: [
      { label: "Typosquat Detection",     href: "/portal/brand", desc: "DNSTwist-powered lookalike domains" },
      { label: "Phishing Kit Monitor",    href: "/portal/brand", desc: "Active phishing pages targeting your brand" },
      { label: "Certificate Transparency",href: "/portal/brand", desc: "CT log monitoring for brand domains" },
      { label: "Takedown Requests",       href: "/portal/brand", desc: "One-click domain takedown workflow" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <path d="M12 3l9 4.5v5c0 4.5-3.9 8.7-9 10-5.1-1.3-9-5.5-9-10v-5L12 3z" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    name: "Attack Surface Management",
    href: "/portal/asm",
    anchorHref: "#attack-surface",
    description: "Automated external asset discovery, CVE correlation, and exposure monitoring.",
    badge: "120+ Assets",
    badgeColor: "bg-green-500/15 text-green-300",
    color: "text-green-400",
    bg: "bg-green-500/10 group-hover:bg-green-500/20",
    subItems: [
      { label: "Asset Discovery",          href: "/portal/asm", desc: "Subdomains, IPs, cloud resources" },
      { label: "Vulnerability Scanning",   href: "/portal/asm", desc: "CVE correlation with CVSS scoring" },
      { label: "Exposed Services",         href: "/portal/asm", desc: "Open ports, SSL issues, misconfigs" },
      { label: "Change Monitoring",        href: "/portal/asm", desc: "Alerts when your attack surface changes" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <circle cx="11" cy="11" r="8" stroke="currentColor" strokeWidth="1.8"/>
        <path d="M21 21l-4.35-4.35" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
        <path d="M11 8v6M8 11h6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    name: "AI Threat Reports",
    href: "/portal/reports",
    anchorHref: "#threat-reports",
    description: "Vertex AI-powered executive briefings, incident summaries, and IOC analysis.",
    badge: "Vertex AI",
    badgeColor: "bg-primary/15 text-red-300",
    color: "text-primary",
    bg: "bg-primary/10 group-hover:bg-primary/20",
    subItems: [
      { label: "Executive Briefings",     href: "/portal/reports", desc: "Board-ready threat summaries" },
      { label: "Incident Reports",        href: "/portal/reports", desc: "AI-generated incident documentation" },
      { label: "IOC Deep-Dives",          href: "/portal/reports", desc: "Full threat actor attribution" },
      { label: "AI Chat Assistant",       href: "/portal/reports", desc: "Q&A against your threat data" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" strokeWidth="1.8"/>
        <path d="M7 8h10M7 12h7M7 16h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    name: "API & Integrations",
    href: "/docs/api",
    anchorHref: "#api-access",
    description: "REST API, SIEM connectors, SOAR playbooks, MISP feeds, and WebSocket streaming.",
    badge: "REST API",
    badgeColor: "bg-teal-500/15 text-teal-300",
    color: "text-teal-400",
    bg: "bg-teal-500/10 group-hover:bg-teal-500/20",
    subItems: [
      { label: "REST API Reference",       href: "/docs/api",         desc: "Full OpenAPI 3.0 documentation" },
      { label: "SIEM Integrations",        href: "/docs/integration", desc: "Splunk, Sentinel, QRadar add-ons" },
      { label: "SOAR Playbooks",           href: "/docs/integration", desc: "Automated response workflows" },
      { label: "WebSocket Live Feed",      href: "/docs/api",         desc: "Real-time IOC streaming" },
    ],
    icon: (
      <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
        <polyline points="4 17 10 11 4 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        <line x1="12" y1="19" x2="20" y2="19" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
      </svg>
    ),
  },
];

// ── Component ────────────────────────────────────────────────────────────────
export function Header() {
  const [isScrolled, setIsScrolled]       = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeProduct, setActiveProduct] = useState<number | null>(null);
  const [productsOpen, setProductsOpen]   = useState(false);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onScroll = () => setIsScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const openMenu = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    setProductsOpen(true);
    if (activeProduct === null) setActiveProduct(0);
  };

  const closeMenu = () => {
    closeTimer.current = setTimeout(() => {
      setProductsOpen(false);
      setActiveProduct(null);
    }, 120);
  };

  const active = activeProduct !== null ? PRODUCTS[activeProduct] : PRODUCTS[0];

  return (
    <header className="fixed top-0 left-0 right-0 z-50">

      {/* ── Top bar ─────────────────────────────────────────────────────────── */}
      <div className="hidden lg:block">
        <div className="max-w-[1680px] mx-auto px-8 py-2 flex justify-end gap-8 text-sm">
          <Link href="/blog"   className="text-white/50 hover:text-white transition-colors">Blog</Link>
          <Link href="/docs"   className="text-white/50 hover:text-white transition-colors">Documentation</Link>
          <Link href="#demo"   className="text-primary font-semibold hover:text-primary-light transition-colors">Request a Demo</Link>
          <Link href="/login"  className="text-white/50 hover:text-white transition-colors">Login</Link>
        </div>
      </div>

      {/* ── Main nav ────────────────────────────────────────────────────────── */}
      <nav className={`transition-all duration-300 ${
        isScrolled ? "bg-ebony-950/95 backdrop-blur-md shadow-lg shadow-black/20" : "bg-transparent"
      }`}>
        <div className="max-w-[1680px] mx-auto px-8 h-[68px] flex items-center justify-between">

          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 shrink-0 group">
            <JichoMark size={38} className="transition-transform group-hover:scale-105" />
            <div className="flex flex-col justify-center">
              <div className="flex items-baseline gap-0.5 leading-none font-display">
                <span className="text-[22px] font-bold text-white tracking-tight">jicho</span>
                <span className="text-[22px] font-bold text-primary tracking-tight">Sec</span>
              </div>
              <span className="text-[9px] font-semibold text-white/40 tracking-[0.2em] uppercase mt-1">
                Africa&apos;s Watchful Eye
              </span>
            </div>
          </Link>

          {/* Desktop nav */}
          <div className="hidden lg:flex items-center gap-0.5">

            {/* Products mega-menu */}
            <div
              className="relative"
              onMouseEnter={openMenu}
              onMouseLeave={closeMenu}
            >
              <button className={`flex items-center gap-1 px-4 py-2 text-[14px] font-medium transition-colors rounded-lg ${
                productsOpen ? "text-white bg-white/5" : "text-white/80 hover:text-white"
              }`}>
                Products
                <ChevronDown className={`w-3.5 h-3.5 transition-transform duration-200 ${productsOpen ? "rotate-180" : ""}`} />
              </button>

              {/* ── Mega menu panel ─────────────────────────────────────────── */}
              {productsOpen && (
                <div
                  className="absolute top-full left-1/2 -translate-x-1/2 pt-3 w-[760px]"
                  onMouseEnter={openMenu}
                  onMouseLeave={closeMenu}
                >
                  <div className="bg-card-dark rounded-2xl border border-white/10 shadow-2xl shadow-black/60 overflow-hidden flex">

                    {/* Left — product list */}
                    <div className="w-[260px] shrink-0 border-r border-white/8 p-3 space-y-0.5">
                      <p className="text-[10px] text-white/30 uppercase tracking-widest px-3 py-2">Platform Modules</p>
                      {PRODUCTS.map((p, i) => (
                        <button
                          key={p.name}
                          onMouseEnter={() => setActiveProduct(i)}
                          onClick={() => { setProductsOpen(false); setActiveProduct(null); }}
                          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-left group ${
                            activeProduct === i ? "bg-white/8" : "hover:bg-white/5"
                          }`}
                        >
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors ${p.bg} ${p.color}`}>
                            {p.icon}
                          </div>
                          <div className="min-w-0">
                            <p className={`text-[13px] font-medium leading-tight transition-colors ${
                              activeProduct === i ? "text-white" : "text-white/70 group-hover:text-white"
                            }`}>{p.name}</p>
                          </div>
                          <ChevronDown className={`w-3 h-3 -rotate-90 ml-auto shrink-0 transition-colors ${
                            activeProduct === i ? "text-white/50" : "text-white/20"
                          }`} />
                        </button>
                      ))}
                    </div>

                    {/* Right — sub-items for active product */}
                    <div className="flex-1 p-5">
                      {/* Active product header */}
                      <div className="flex items-start gap-3 mb-4 pb-4 border-b border-white/8">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${active.bg} ${active.color}`}>
                          {active.icon}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="text-[15px] font-semibold text-white">{active.name}</p>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full ${active.badgeColor}`}>{active.badge}</span>
                          </div>
                          <p className="text-xs text-white/50 mt-0.5 leading-relaxed">{active.description}</p>
                        </div>
                      </div>

                      {/* Sub-items grid */}
                      <div className="grid grid-cols-2 gap-1.5">
                        {active.subItems.map((sub) => (
                          <Link
                            key={sub.label}
                            href={sub.href}
                            onClick={() => { setProductsOpen(false); setActiveProduct(null); }}
                            className="flex flex-col gap-0.5 p-3 rounded-xl hover:bg-white/5 transition-colors group"
                          >
                            <p className="text-[13px] font-medium text-white/80 group-hover:text-white transition-colors">{sub.label}</p>
                            <p className="text-[11px] text-white/35 leading-tight">{sub.desc}</p>
                          </Link>
                        ))}
                      </div>

                      {/* CTA link */}
                      <Link
                        href={active.href}
                        onClick={() => { setProductsOpen(false); setActiveProduct(null); }}
                        className={`mt-4 inline-flex items-center gap-1.5 text-xs font-semibold transition-colors ${active.color}`}
                      >
                        Explore {active.name}
                        <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                      </Link>
                    </div>
                  </div>

                  {/* Bottom bar — quick links to all modules */}
                  <div className="mt-1 bg-card-dark rounded-xl border border-white/8 px-4 py-2.5 flex items-center gap-6">
                    <span className="text-[10px] text-white/25 uppercase tracking-widest shrink-0">Quick access</span>
                    {PRODUCTS.map((p) => (
                      <Link
                        key={p.name}
                        href={p.href}
                        onClick={() => { setProductsOpen(false); setActiveProduct(null); }}
                        className={`text-[12px] text-white/40 hover:text-white transition-colors whitespace-nowrap`}
                      >
                        {p.name.split(" ")[0]}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <Link href="/portal"    className="px-4 py-2 text-[14px] font-medium text-white/80 hover:text-white transition-colors rounded-lg hover:bg-white/5">Portal</Link>
            <Link href="/map" target="_blank" className="px-4 py-2 text-[14px] font-medium text-white/80 hover:text-white transition-colors rounded-lg hover:bg-white/5">Threat Map</Link>
            <Link href="#pricing"   className="px-4 py-2 text-[14px] font-medium text-white/80 hover:text-white transition-colors rounded-lg hover:bg-white/5">Pricing</Link>
            <Link href="/docs/api"  className="px-4 py-2 text-[14px] font-medium text-white/80 hover:text-white transition-colors rounded-lg hover:bg-white/5">API</Link>
            <Link href="/about"     className="px-4 py-2 text-[14px] font-medium text-white/80 hover:text-white transition-colors rounded-lg hover:bg-white/5">About</Link>
          </div>

          {/* CTA */}
          <div className="hidden lg:flex items-center gap-3">
            <Link href="/portal" className="px-4 py-2 text-[13px] font-medium text-white/70 hover:text-white transition-colors border border-white/10 hover:border-white/20 rounded-full">
              Sign In
            </Link>
            <Link href="/signup" className="px-5 py-2 text-[14px] font-semibold text-white bg-primary hover:bg-primary-hover rounded-full transition-all shadow-lg shadow-primary/20">
              Start Free Trial
            </Link>
          </div>

          {/* Mobile hamburger */}
          <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)} className="lg:hidden p-2 text-white/70 hover:text-white">
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* ── Mobile menu ──────────────────────────────────────────────────── */}
        {mobileMenuOpen && (
          <div className="lg:hidden bg-ebony-950 border-t border-white/10 max-h-[80vh] overflow-y-auto">
            <div className="max-w-[1680px] mx-auto px-6 py-5 space-y-5">

              <div>
                <p className="text-[10px] text-white/30 uppercase tracking-widest mb-3">Platform Modules</p>
                <div className="space-y-0.5">
                  {PRODUCTS.map((p) => (
                    <Link
                      key={p.name}
                      href={p.href}
                      onClick={() => setMobileMenuOpen(false)}
                      className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-white/5"
                    >
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${p.bg} ${p.color}`}>
                        {p.icon}
                      </div>
                      <div>
                        <p className="text-[14px] font-medium text-white/80">{p.name}</p>
                        <p className="text-[11px] text-white/40">{p.badge}</p>
                      </div>
                    </Link>
                  ))}
                </div>
              </div>

              <div className="border-t border-white/10 pt-4 space-y-1">
                {[
                  { label: "Portal", href: "/portal" },
                  { label: "Threat Map", href: "/map" },
                  { label: "Pricing", href: "#pricing" },
                  { label: "API Docs", href: "/docs/api" },
                  { label: "About", href: "/about" },
                ].map(l => (
                  <Link key={l.label} href={l.href} onClick={() => setMobileMenuOpen(false)}
                    className="block px-3 py-2 text-[14px] text-white/70 hover:text-white rounded-xl hover:bg-white/5">
                    {l.label}
                  </Link>
                ))}
              </div>

              <div className="border-t border-white/10 pt-4 flex flex-col gap-3">
                <Link href="/login" onClick={() => setMobileMenuOpen(false)}
                  className="block text-center py-2.5 text-white/70 border border-white/10 rounded-full text-[14px]">
                  Sign In
                </Link>
                <Link href="/signup" onClick={() => setMobileMenuOpen(false)}
                  className="block text-center py-3 bg-primary hover:bg-primary-hover text-white rounded-full font-semibold text-[14px]">
                  Start Free Trial
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
}
