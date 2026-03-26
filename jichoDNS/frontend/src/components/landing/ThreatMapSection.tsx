"use client";

import Link from "next/link";
import dynamic from "next/dynamic";

// Dynamically import the map to avoid SSR issues
const RealThreatMap = dynamic(
  () => import("@/components/map/RealThreatMap"),
  { 
    ssr: false,
    loading: () => (
      <div className="w-full h-full bg-ebony-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-white/50">Loading threat map...</p>
        </div>
      </div>
    )
  }
);

const liveStats = [
  { label: "C2 Servers", value: "9,839", color: "bg-purple-500" },
  { label: "Malware URLs", value: "25,070", color: "bg-red-500" },
  { label: "Phishing Sites", value: "1,005", color: "bg-orange-500" },
  { label: "Countries", value: "127", color: "bg-green-500" },
];

export function ThreatMapSection() {
  return (
    <section id="threat-map" className="relative py-24 bg-ebony-950">
      {/* Section Header */}
      <div className="max-w-[1680px] mx-auto px-8 mb-12">
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8">
          <div>
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              <span className="text-sm font-medium text-primary">Live Threat Map</span>
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-white mb-4">
              Real-Time Global
              <span className="text-primary"> Threat Visibility</span>
            </h2>
            <p className="text-xl text-white/50 max-w-2xl">
              Watch attacks unfold in real-time. Our threat map visualizes C2 communications, 
              malware distribution, and phishing campaigns as they happen across Africa and globally.
            </p>
          </div>
          
          {/* Stats Pills */}
          <div className="flex flex-wrap gap-3">
            {liveStats.map((stat) => (
              <div
                key={stat.label}
                className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-card-dark border border-white/10"
              >
                <div className={`w-2.5 h-2.5 rounded-full ${stat.color}`} />
                <span className="text-white font-semibold">{stat.value}</span>
                <span className="text-white/40 text-sm">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Map Container */}
      <div className="max-w-[1680px] mx-auto px-8">
        <div className="relative rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/50">
          {/* Map Header Bar */}
          <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-ebony-950 via-ebony-950/80 to-transparent p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                  </span>
                  <span className="text-sm font-medium text-green-400">LIVE</span>
                </div>
                <span className="text-white/40 text-sm">Streaming from 15+ threat intelligence feeds</span>
              </div>
              
              <Link
                href="/map"
                target="_blank"
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-white text-sm font-medium transition-colors border border-white/10"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M15 3h6v6M14 10l6.1-6.1M9 21H3v-6M10 14l-6.1 6.1"/>
                </svg>
                Open Fullscreen
              </Link>
            </div>
          </div>

          {/* Map */}
          <div className="h-[600px] lg:h-[700px]">
            <RealThreatMap />
          </div>

          {/* Legend */}
          <div className="absolute bottom-6 left-6 z-20 p-5 rounded-xl bg-ebony-950/90 backdrop-blur-sm border border-white/10">
            <p className="text-xs text-white/40 mb-4 uppercase tracking-wider font-medium">Threat Types</p>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-purple-500" />
                <span className="text-sm text-white/70">C2 Infrastructure</span>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-orange-500" />
                <span className="text-sm text-white/70">Phishing</span>
              </div>
              <div className="flex items-center gap-3">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-sm text-white/70">Malware</span>
              </div>
            </div>
          </div>

          {/* Source Badge */}
          <div className="absolute bottom-6 right-6 z-20 px-4 py-2 rounded-lg bg-ebony-950/90 backdrop-blur-sm border border-white/10">
            <p className="text-xs text-white/40">
              Sources: URLhaus, ThreatFox, PhishTank, OpenPhish, SSLBL +10 more
            </p>
          </div>
        </div>

        {/* CTA below map */}
        <div className="mt-10 text-center">
          <p className="text-white/40 mb-4">
            Integrate live threat data into your SIEM, SOAR, or security tools
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link
              href="#pricing"
              className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-all shadow-lg shadow-primary/25"
            >
              Get API Access
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M5 12h14M12 5l7 7-7 7"/>
              </svg>
            </Link>
            <Link
              href="/api-docs"
              target="_blank"
              className="inline-flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 text-white font-medium rounded-full border border-white/10 transition-colors"
            >
              View API Docs
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
