"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Menu, X, ChevronDown } from "lucide-react";
import { JichoMark } from "@/components/brand/JichoMark";
import { MODULE_ICONS } from "@/components/brand/ModuleIcons";

// ── Single green accent — opsec restraint, no rainbow ────────────────────────
const ACCENT = { color: "text-primary", bg: "bg-primary/10 group-hover:bg-primary/15", badge: "bg-primary/15 text-primary" };

// ── All 6 product modules (honest copy, shared distinct icons) ───────────────
const PRODUCTS = [
  {
    id: "threat-intelligence",
    name: "Threat Intelligence",
    href: "/portal",
    anchorHref: "#threat-intelligence",
    description: "Aggregated IOC feeds — malicious domains, IPs, URLs, hashes — enriched with GeoIP and MITRE ATT&CK context.",
    badge: "9 feeds",
    tone: ACCENT,
    subItems: [
      { label: "IOC Search & Lookup", href: "/portal",   desc: "Query domains, IPs, URLs, hashes" },
      { label: "Threat Feed Browser", href: "/portal",   desc: "Browse all live source feeds" },
      { label: "Domain Analysis",     href: "/analysis", desc: "DGA detection, entropy, scoring" },
      { label: "API Access",          href: "/docs/api", desc: "REST API for SIEM / SOAR" },
    ],
  },
  {
    id: "dark-web",
    name: "Dark Web Monitoring",
    href: "/portal/darkweb",
    anchorHref: "#dark-web",
    description: "Leaked-credential and breach monitoring for African organisations, searchable by domain and email.",
    badge: "24/7",
    tone: ACCENT,
    subItems: [
      { label: "Credential Leak Monitor", href: "/portal/darkweb", desc: "Search leaked emails & passwords" },
      { label: "Data Breach Tracker",     href: "/portal/darkweb", desc: "Breaches affecting your org" },
      { label: "Forum & Telegram Watch",  href: "/portal/darkweb", desc: "Threat-actor mentions" },
      { label: "Exposure Check",          href: "/portal/darkweb", desc: "Email exposure lookup" },
    ],
  },
  {
    id: "brand-protection",
    name: "Brand Protection",
    href: "/portal/brand",
    anchorHref: "#brand-protection",
    description: "Typosquat detection and Certificate Transparency monitoring for African brands.",
    badge: "DNS",
    tone: ACCENT,
    subItems: [
      { label: "Typosquat Detection",      href: "/portal/brand", desc: "DNSTwist lookalike domains" },
      { label: "Certificate Transparency", href: "/portal/brand", desc: "CT log monitoring" },
      { label: "Risk Scoring",             href: "/portal/brand", desc: "Live DNS resolution & scoring" },
      { label: "Brand Alert Feed",         href: "/portal/brand", desc: "Per-brand alerts" },
    ],
  },
  {
    id: "attack-surface",
    name: "Attack Surface Management",
    href: "/portal/asm",
    anchorHref: "#attack-surface",
    description: "External asset discovery, exposed-service detection, and CVE correlation.",
    badge: "CTEM",
    tone: ACCENT,
    subItems: [
      { label: "Asset Discovery",  href: "/portal/asm", desc: "Subdomains, hosts, services" },
      { label: "Exposed Services", href: "/portal/asm", desc: "Open ports, SSL issues" },
      { label: "CVE Correlation",  href: "/portal/asm", desc: "EPSS + CISA KEV" },
      { label: "Risk Scoring",     href: "/portal/asm", desc: "Per-asset exposure grade" },
    ],
  },
  {
    id: "threat-reports",
    name: "Threat Reports",
    href: "/portal/reports",
    anchorHref: "#threat-reports",
    description: "Executive briefings, exposure assessments, and IOC analysis from your live threat data.",
    badge: "Auto",
    tone: ACCENT,
    subItems: [
      { label: "Executive Briefings", href: "/portal/reports", desc: "Board-ready summaries" },
      { label: "Exposure Reports",    href: "/portal/reports", desc: "External-exposure assessments" },
      { label: "IOC Deep-Dives",      href: "/portal/reports", desc: "Indicator analysis" },
      { label: "Printable Export",    href: "/portal/reports", desc: "Shareable HTML output" },
    ],
  },
  {
    id: "api-access",
    name: "API & Integrations",
    href: "/docs/api",
    anchorHref: "#api-access",
    description: "REST API, WebSocket streaming, and MISP feed integration for your SIEM / SOAR.",
    badge: "REST",
    tone: ACCENT,
    subItems: [
      { label: "REST API Reference", href: "/docs/api",         desc: "Documented endpoints" },
      { label: "WebSocket Live Feed", href: "/docs/api",        desc: "Real-time IOC streaming" },
      { label: "MISP Integration",   href: "/docs/integration", desc: "Event ingestion & correlation" },
      { label: "SIEM / SOAR",        href: "/docs/integration", desc: "JSON for your pipeline" },
    ],
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
  const ActiveIcon = MODULE_ICONS[active.id];

  return (
    <header className="fixed top-0 left-0 right-0 z-50">

      {/* ── Single flat nav row (opsec restraint: transparent → flat #0A0E17) ── */}
      <nav className={`transition-colors duration-300 ${
        isScrolled ? "bg-body-dark border-b border-white/5" : "bg-transparent"
      }`}>
        <div className="max-w-[1680px] mx-auto px-8 h-[68px] flex items-center justify-between">

          {/* Logo */}
          <Link href="/" className="flex items-center gap-3 shrink-0 group">
            <JichoMark size={52} className="transition-transform group-hover:scale-105" />
            <div className="flex flex-col justify-center">
              <div className="flex items-baseline gap-0.5 leading-none font-display">
                <span className="text-[30px] font-bold text-white tracking-tight">jicho</span>
                <span className="text-[30px] font-bold text-primary tracking-tight">Sec</span>
              </div>
              <span className="text-[10px] font-semibold text-white/40 tracking-[0.2em] uppercase mt-1">
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
              <button className={`flex items-center gap-1 px-3 py-2 text-[14px] font-medium transition-colors rounded-lg ${
                productsOpen ? "text-white bg-white/5" : "text-white/70 hover:text-white"
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
                  <div className="bg-card-dark rounded-2xl border border-white/10 shadow-xl shadow-black/30 overflow-hidden flex">

                    {/* Left — product list */}
                    <div className="w-[260px] shrink-0 border-r border-white/8 p-3 space-y-0.5">
                      <p className="text-[10px] text-white/30 uppercase tracking-widest px-3 py-2">Platform Modules</p>
                      {PRODUCTS.map((p, i) => {
                        const Icon = MODULE_ICONS[p.id];
                        return (
                          <button
                            key={p.name}
                            onMouseEnter={() => setActiveProduct(i)}
                            onClick={() => { setProductsOpen(false); setActiveProduct(null); }}
                            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all text-left group ${
                              activeProduct === i ? "bg-white/8" : "hover:bg-white/5"
                            }`}
                          >
                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-colors ${p.tone.bg} ${p.tone.color}`}>
                              {Icon ? <Icon className="w-5 h-5" /> : null}
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
                        );
                      })}
                    </div>

                    {/* Right — sub-items for active product */}
                    <div className="flex-1 p-5">
                      {/* Active product header */}
                      <div className="flex items-start gap-3 mb-4 pb-4 border-b border-white/8">
                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${active.tone.bg} ${active.tone.color}`}>
                          {ActiveIcon ? <ActiveIcon className="w-5 h-5" /> : null}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="text-[15px] font-semibold text-white">{active.name}</p>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full ${active.tone.badge}`}>{active.badge}</span>
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
                        className={`mt-4 inline-flex items-center gap-1.5 text-xs font-semibold transition-colors ${active.tone.color}`}
                      >
                        Explore {active.name}
                        <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                      </Link>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <Link href="/portal"    className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">Portal</Link>
            <Link href="/map" target="_blank" className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">Threat Map</Link>
            <Link href="#pricing"   className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">Pricing</Link>
            <Link href="/docs/api"  className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">API</Link>
            <Link href="/docs"      className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">Docs</Link>
            <Link href="/blog"      className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">Blog</Link>
            <Link href="/about"     className="px-3 py-2 text-[14px] font-medium text-white/70 hover:text-white transition-colors rounded-lg hover:bg-white/5">About</Link>
          </div>

          {/* CTA — one green filled pill, opsec restraint */}
          <div className="hidden lg:flex items-center gap-5">
            <Link href="#demo" className="text-[13px] font-medium text-primary hover:text-primary-light transition-colors">
              Request a Demo
            </Link>
            <Link href="/login" className="text-[13px] font-medium text-white/60 hover:text-white transition-colors">
              Sign in
            </Link>
            <Link href="/signup" className="px-5 py-2 text-[14px] font-semibold text-body-dark bg-primary hover:bg-primary-hover rounded-full transition-colors">
              Start Free
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
                  {PRODUCTS.map((p) => {
                    const Icon = MODULE_ICONS[p.id];
                    return (
                      <Link
                        key={p.name}
                        href={p.href}
                        onClick={() => setMobileMenuOpen(false)}
                        className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-white/5"
                      >
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${p.tone.bg} ${p.tone.color}`}>
                          {Icon ? <Icon className="w-5 h-5" /> : null}
                        </div>
                        <div>
                          <p className="text-[14px] font-medium text-white/80">{p.name}</p>
                          <p className="text-[11px] text-white/40">{p.badge}</p>
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>

              <div className="border-t border-white/10 pt-4 space-y-1">
                {[
                  { label: "Portal", href: "/portal" },
                  { label: "Threat Map", href: "/map" },
                  { label: "Pricing", href: "#pricing" },
                  { label: "API", href: "/docs/api" },
                  { label: "Docs", href: "/docs" },
                  { label: "Blog", href: "/blog" },
                  { label: "About", href: "/about" },
                  { label: "Request a Demo", href: "#demo" },
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
                  className="block text-center py-3 bg-primary hover:bg-primary-hover text-body-dark rounded-full font-semibold text-[14px]">
                  Start Free
                </Link>
              </div>
            </div>
          </div>
        )}
      </nav>
    </header>
  );
}
