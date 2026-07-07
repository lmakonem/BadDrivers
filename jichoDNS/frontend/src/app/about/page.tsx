"use client";

import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import { JichoMark } from "@/components/brand/JichoMark";
import Link from "next/link";

// Decorative PCB-trace field — thin cyan traces with small gold vias.
function CircuitField({ className = "" }: { className?: string }) {
  return (
    <svg
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
      viewBox="0 0 400 200"
      fill="none"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
    >
      <g stroke="#38e1d0" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" opacity="0.4">
        <path className="circuit-trace" d="M-10 44 H78 L110 72 H214 L246 44 H410" />
        <path d="M40 44 V120 H150" />
        <path d="M110 72 V152" />
        <path className="circuit-trace" d="M246 44 V12" />
        <path d="M214 72 H300 L332 102 H410" />
      </g>
      <g fill="#f5b62c">
        <circle cx="78" cy="44" r="1.8" />
        <circle cx="110" cy="72" r="1.8" />
        <circle cx="246" cy="44" r="1.8" />
        <circle cx="150" cy="120" r="1.8" />
        <circle cx="332" cy="102" r="1.8" />
      </g>
    </svg>
  );
}

// What the platform actually does — the six live modules.
const capabilities = [
  {
    title: "Threat Intelligence",
    description:
      "37,000+ indicators aggregated from 15+ premium and open-source feeds — C2, malware, and phishing with full context.",
    icon: (
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    ),
  },
  {
    title: "Dark Web Monitoring",
    description:
      "Credential leaks, data breaches, and underground forum chatter tracked across the African threat landscape.",
    icon: (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M2 12h20" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </>
    ),
  },
  {
    title: "Brand Protection",
    description:
      "Typosquat detection, phishing-kit monitoring, and certificate-transparency watch with a takedown workflow.",
    icon: (
      <>
        <path d="M12 3l9 4.5v5c0 4.5-3.9 8.7-9 10-5.1-1.3-9-5.5-9-10v-5L12 3z" />
        <path d="M9 12l2 2 4-4" />
      </>
    ),
  },
  {
    title: "Attack Surface Management",
    description:
      "External asset discovery, CVE correlation with CVSS scoring, and monitoring for exposed services and misconfigurations.",
    icon: (
      <>
        <circle cx="11" cy="11" r="8" />
        <path d="M21 21l-4.35-4.35" />
        <path d="M11 8v6M8 11h6" />
      </>
    ),
  },
  {
    title: "AI Threat Reports",
    description:
      "Vertex AI-powered executive briefings, incident summaries, and IOC deep-dives generated from your own threat data.",
    icon: (
      <>
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M7 8h10M7 12h7M7 16h5" />
      </>
    ),
  },
  {
    title: "API & Integrations",
    description:
      "REST API, SIEM connectors, SOAR playbooks, MISP feeds, and WebSocket streaming to plug intelligence into your stack.",
    icon: (
      <>
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </>
    ),
  },
];

// Africa-focused coverage — the regional threats the platform is tuned for.
const coverage = [
  {
    title: "Mobile Money Fraud",
    description:
      "Detection tuned for the fraud patterns and social-engineering campaigns targeting mobile-money ecosystems.",
  },
  {
    title: "African Brand Typosquatting",
    description:
      "Lookalike-domain and phishing-kit monitoring focused on the banks, telecoms, and brands operating across the continent.",
  },
  {
    title: "Telecom & Infrastructure Targeting",
    description:
      "Visibility into attacks against the network and DNS infrastructure that African organizations depend on.",
  },
  {
    title: "Regional DNS Measurement",
    description:
      "RIPE Atlas integration provides real-time DNS measurements from African vantage points for regional context.",
  },
];

const values = [
  {
    title: "Security First",
    description:
      "Every African organization deserves world-class protection. Detection quality comes before everything else.",
    icon: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  },
  {
    title: "African Expertise",
    description:
      "Purpose-built for the region's threat landscape — mobile money, regional phishing, and infrastructure targeting.",
    icon: (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M2 12h20" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
      </>
    ),
  },
  {
    title: "Real-Time Response",
    description:
      "Threats don't wait. Feeds refresh every 15 minutes and alerts fire the moment your exposure changes.",
    icon: (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M12 6v6l4 2" />
      </>
    ),
  },
  {
    title: "Open Integration",
    description:
      "Intelligence is only useful where you work. Everything is reachable over an open REST API and standard connectors.",
    icon: (
      <>
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </>
    ),
  },
];

export default function AboutPage() {
  return (
    <main className="min-h-screen bg-body-dark">
      <Header />

      {/* Hero Section */}
      <section className="relative pt-40 pb-20 overflow-hidden">
        {/* Ambient glows + circuit grid */}
        <div className="absolute inset-0 circuit-grid opacity-60" />
        <div className="absolute inset-0 glow-gold" />
        <div className="absolute inset-0 glow-cyan" />

        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <span className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-6">
              <JichoMark size={18} />
              About JichoSec
            </span>
            <h1 className="font-display text-4xl md:text-6xl font-bold text-white mb-6">
              The watchful eye over{" "}
              <span className="gradient-text">African cyberspace</span>
            </h1>
            <p className="text-xl text-white/60 max-w-3xl mx-auto">
              JichoSec is a cyber threat intelligence platform built for African organizations —
              aggregating indicators, watching the dark web, protecting brands, and mapping
              external exposure, all tuned for the region&apos;s threat landscape.
            </p>
          </div>
        </div>
      </section>

      {/* The Jicho / eye story */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-6">
                Why &quot;Jicho&quot;
              </h2>
              <div className="space-y-4 text-white/60 text-lg">
                <p>
                  <span className="text-white font-semibold">Jicho</span> means{" "}
                  <span className="text-secondary font-semibold">&quot;eye&quot;</span> in Swahili.
                  The name captures a single idea: unbroken visibility into the threats moving
                  across African cyberspace.
                </p>
                <p>
                  Our mark makes that literal. The iris is a{" "}
                  <span className="text-primary font-semibold">circuit board</span> — copper
                  traces and vias radiating from a gold pupil — with a cyan sweep that never stops
                  scanning. It is the watchful eye rendered as the infrastructure it protects.
                </p>
                <p>
                  Global threat platforms often overlook the specific risks facing the continent:
                  mobile-money fraud, regional phishing campaigns, and targeting of local telecom
                  and DNS infrastructure. JichoSec exists to close that gap — to give defenders
                  here the same depth of visibility the rest of the world takes for granted.
                </p>
              </div>
            </div>

            {/* Signature: the circuit-eye */}
            <div className="relative rounded-3xl border border-white/10 bg-card-dark p-10 overflow-hidden">
              <div className="absolute inset-0 circuit-grid opacity-70" />
              <div className="absolute inset-0 glow-cyan" />
              <div className="relative z-10 flex flex-col items-center justify-center py-6">
                <JichoMark size={240} />
                <p className="mt-8 font-display text-lg font-semibold text-white">
                  jicho<span className="text-primary">Sec</span>
                </p>
                <p className="text-sm text-white/40 tracking-[0.18em] uppercase mt-1">
                  Africa&apos;s Watchful Eye
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* What the platform does */}
      <section className="relative py-20 bg-card-dark/40 overflow-hidden">
        <CircuitField className="opacity-30" />
        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-4">
              What the platform does
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              Six modules, one watchful eye — the surfaces JichoSec monitors for the
              organizations it protects.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {capabilities.map((cap) => (
              <div
                key={cap.title}
                className="bg-card-dark rounded-2xl border border-white/10 p-8 hover:border-primary/30 transition-colors"
              >
                <div className="w-14 h-14 rounded-2xl bg-primary/10 flex items-center justify-center mb-6">
                  <svg
                    className="w-7 h-7 text-primary"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    {cap.icon}
                  </svg>
                </div>
                <h3 className="font-display text-xl font-semibold text-white mb-3">{cap.title}</h3>
                <p className="text-white/50">{cap.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Mission & Values */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-4">
              What we stand for
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              The principles behind every feed we ingest and every alert we raise.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {values.map((value) => (
              <div
                key={value.title}
                className="bg-card-dark rounded-2xl border border-white/10 p-8 text-center"
              >
                <div className="w-16 h-16 rounded-2xl bg-secondary/10 flex items-center justify-center mx-auto mb-6">
                  <svg
                    className="w-8 h-8 text-secondary"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    {value.icon}
                  </svg>
                </div>
                <h3 className="font-display text-xl font-semibold text-white mb-3">{value.title}</h3>
                <p className="text-white/50">{value.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Africa-focused coverage */}
      <section className="py-20 bg-card-dark/40">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-4">
              Tuned for the region
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              JichoSec is built around the threats African organizations actually face — not a
              generic feed with the continent bolted on.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {coverage.map((item) => (
              <div
                key={item.title}
                className="flex gap-5 bg-card-dark rounded-2xl border border-white/10 p-8"
              >
                <div className="mt-1 flex flex-col items-center shrink-0">
                  <span className="w-3 h-3 rounded-full bg-primary" />
                  <span className="w-0.5 flex-1 bg-white/10 mt-2" />
                </div>
                <div>
                  <h3 className="font-display text-xl font-semibold text-white mb-2">{item.title}</h3>
                  <p className="text-white/55">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="relative p-12 rounded-3xl bg-card-dark border border-white/10 overflow-hidden">
            <div className="absolute inset-0 circuit-grid opacity-60" />
            <div className="absolute inset-0 glow-gold" />
            <div className="absolute inset-0 glow-cyan" />

            <div className="relative z-10 text-center">
              <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-4">
                See the eye at work
              </h2>
              <p className="text-xl text-white/60 max-w-2xl mx-auto mb-8">
                Whether you want to protect your organization or build your career in
                cybersecurity, we&apos;d like to hear from you.
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                <Link href="/contact" className="btn-primary">
                  Contact Us
                </Link>
                <Link href="/careers" className="btn-secondary">
                  View Careers
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
