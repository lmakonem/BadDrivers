"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import { JichoMark } from "@/components/brand/JichoMark";

const RealThreatMap = dynamic(() => import("@/components/map/RealThreatMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full bg-ebony-950/50 flex items-center justify-center">
      <div className="text-center">
        <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2" />
        <p className="text-white/30 text-xs">Loading threat map…</p>
      </div>
    </div>
  ),
});

// ── types ────────────────────────────────────────────────────────────────────
interface ConsoleEntry {
  id: number; ts: string; type: string;
  indicator: string; source: string; country: string; risk: number;
}

const TYPE_COLOR: Record<string, string> = {
  c2: "text-purple-400", malware: "text-red-400", phishing: "text-orange-400",
  ddos: "text-blue-400", bruteforce: "text-yellow-400",
};
const TYPE_BG: Record<string, string> = {
  c2: "bg-purple-500/15 border-purple-500/30", malware: "bg-red-500/15 border-red-500/30",
  phishing: "bg-orange-500/15 border-orange-500/30", ddos: "bg-blue-500/15 border-blue-500/30",
  bruteforce: "bg-yellow-500/15 border-yellow-500/30",
};
// ── 6 modules — compact pill cards ───────────────────────────────────────────
const MODULES = [
  {
    id: "threat-intelligence",
    href: "/portal",
    label: "Threat Intelligence",
    sublabel: "IOC Feeds & Analysis",
    accent: "#a855f7",          // purple
    accentClass: "text-purple-400",
    borderAccent: "hover:border-purple-500/40",
    glowClass: "group-hover:shadow-purple-500/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    id: "dark-web",
    href: "/portal/darkweb",
    label: "Dark Web Monitor",
    sublabel: "Leaks & Breaches",
    accent: "#3b82f6",          // blue
    accentClass: "text-blue-400",
    borderAccent: "hover:border-blue-500/40",
    glowClass: "group-hover:shadow-blue-500/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" stroke="currentColor" strokeWidth="2"/>
        <path d="M2 12h20" stroke="currentColor" strokeWidth="2"/>
      </svg>
    ),
  },
  {
    id: "brand-protection",
    href: "/portal/brand",
    label: "Brand Protection",
    sublabel: "Typosquats & Phishing",
    accent: "#f97316",          // orange
    accentClass: "text-orange-400",
    borderAccent: "hover:border-orange-500/40",
    glowClass: "group-hover:shadow-orange-500/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <path d="M12 3l9 4.5v5c0 4.5-3.9 8.7-9 10-5.1-1.3-9-5.5-9-10v-5L12 3z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    id: "attack-surface",
    href: "/portal/asm",
    label: "Attack Surface",
    sublabel: "Asset Discovery & CVEs",
    accent: "#22c55e",          // green
    accentClass: "text-green-400",
    borderAccent: "hover:border-green-500/40",
    glowClass: "group-hover:shadow-green-500/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    id: "ai-reports",
    href: "/portal/reports",
    label: "AI Threat Reports",
    sublabel: "AI-Generated Summaries",
    accent: "#f5b62c",          // brand gold
    accentClass: "text-primary",
    borderAccent: "hover:border-primary/40",
    glowClass: "group-hover:shadow-primary/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    id: "api-access",
    href: "/docs/api",
    label: "API & Integrations",
    sublabel: "SIEM · SOAR · MISP",
    accent: "#14b8a6",          // teal
    accentClass: "text-teal-400",
    borderAccent: "hover:border-teal-500/40",
    glowClass: "group-hover:shadow-teal-500/20",
    icon: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none">
        <polyline points="4 17 10 11 4 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        <line x1="12" y1="19" x2="20" y2="19" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
      </svg>
    ),
  },
];

// ── component ─────────────────────────────────────────────────────────────────
export function Hero() {
  const [console_, setConsole]  = useState<ConsoleEntry[]>([]);
  const [wsStatus, setWsStatus] = useState<"live"|"replay"|"idle">("idle");
  const consoleRef              = useRef<HTMLDivElement>(null);
  const counterRef              = useRef(0);



  // live console
  useEffect(() => {
    let ws: WebSocket | null = null;
    let demoTimer: ReturnType<typeof setInterval>;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const addEntry = (e: ConsoleEntry) => {
      setConsole(prev => [e, ...prev].slice(0, 60));
    };

    // Fetch real indicators from the API and replay them as a live-looking feed
    let replayPool: ConsoleEntry[] = [];
    let replayIdx = 0;

    const startReplay = () => {
      setWsStatus("replay");
      // If we already have data, just start replaying
      if (replayPool.length > 0) {
        demoTimer = setInterval(() => {
          const entry = replayPool[replayIdx % replayPool.length];
          addEntry({ ...entry, id: ++counterRef.current, ts: new Date().toTimeString().slice(0, 8) });
          replayIdx++;
        }, 1200);
        return;
      }
      // Fetch real data from API
      const apiBase = process.env.NEXT_PUBLIC_API_URL || `${window.location.protocol}//${window.location.host}`;
      fetch(`${apiBase}/api/v1/indicators/live/feed?limit=200&since_minutes=1440`)
        .then(r => r.json())
        .then(data => {
          const indicators = data.indicators || [];
          if (indicators.length === 0) {
            // No live data available — show an honest idle state, never fabricate.
            setWsStatus("idle");
            return;
          }
          replayPool = indicators.map((ioc: Record<string, unknown>, i: number) => ({
            id: i, ts: "",
            type: String(ioc.threat_type ?? "malware"),
            indicator: String(ioc.indicator ?? ""),
            source: String(ioc.source ?? "feed"),
            country: String(ioc.country_code ?? "??"),
            risk: Number(ioc.risk_score ?? Math.floor(Math.random() * 40 + 60)),
          }));
          // Shuffle for visual variety
          replayPool.sort(() => Math.random() - 0.5);
          demoTimer = setInterval(() => {
            const entry = replayPool[replayIdx % replayPool.length];
            addEntry({ ...entry, id: ++counterRef.current, ts: new Date().toTimeString().slice(0, 8) });
            replayIdx++;
          }, 1200);
        })
        .catch(() => {
          // Network error — show an honest idle state, never fabricate rows.
          setWsStatus("idle");
        });
    };

    const tryWs = () => {
      try {
        const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${wsProto}//${window.location.host}/api/v1/ws/iocs`);
        ws.onopen = () => { setWsStatus("live"); clearInterval(demoTimer); };
        ws.onclose = () => { startReplay(); reconnectTimer = setTimeout(tryWs, 8000); };
        ws.onerror = () => ws?.close();
        ws.onmessage = ev => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "ping") { ws?.send(JSON.stringify({type:"pong"})); return; }
            if (msg.type === "new_iocs" && Array.isArray(msg.data)) {
              setWsStatus("live");
              msg.data.slice(0,3).forEach((ioc: Record<string,unknown>) => addEntry({
                id: ++counterRef.current,
                ts: new Date().toTimeString().slice(0,8),
                type: String(ioc.threat_type ?? "malware"),
                indicator: String(ioc.indicator ?? ""),
                source: String(ioc.source ?? "feed"),
                country: String(ioc.country_code ?? ioc.country ?? "??"),
                risk: Number(ioc.risk_score ?? Math.floor(Math.random()*40+60)),
              }));
            }
          } catch { /* ignore */ }
        };
        setTimeout(() => { if (wsStatus !== "live") { startReplay(); } }, 6000);
      } catch { startReplay(); }
    };

    tryWs();
    return () => { ws?.close(); clearInterval(demoTimer); clearTimeout(reconnectTimer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);



  const statusDot   = wsStatus === "live" ? "bg-green-400" : wsStatus === "replay" ? "bg-yellow-400" : "bg-white/30";
  const statusLabel = wsStatus === "live" ? "LIVE"         : wsStatus === "replay" ? "REPLAY"         : "AWAITING";

  return (
    <section className="relative bg-ebony-950 overflow-hidden">

      {/* branded ambient backdrop — PCB grid + gold/cyan glows */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div
          className="absolute inset-x-0 top-0 h-[620px] circuit-grid opacity-60"
          style={{
            maskImage: "linear-gradient(180deg, rgba(0,0,0,0.7), transparent 82%)",
            WebkitMaskImage: "linear-gradient(180deg, rgba(0,0,0,0.7), transparent 82%)",
          }}
        />
        <div className="absolute inset-0 glow-gold" />
        <div className="absolute inset-0 glow-cyan" />
        <div className="absolute bottom-0 right-0 w-[500px] h-[400px] bg-secondary/[0.04] rounded-full blur-[130px]" />
      </div>

      <div className="relative z-10 max-w-[1680px] mx-auto px-6 lg:px-10">

        {/* ════════════════════════════════════════════════════════════════════
            BLOCK 1 — Platform purpose (top, above the fold)
        ════════════════════════════════════════════════════════════════════ */}
        <div className="pt-28 pb-10">

          {/* headline + brand eye */}
          <div className="text-center max-w-4xl mx-auto mb-6">

            {/* the watchful eye — brand signature */}
            <div className="relative mx-auto mb-7 grid h-32 place-items-center">
              <div
                className="pointer-events-none absolute h-56 w-56 rounded-full"
                style={{ background: "radial-gradient(circle, rgba(245,182,44,0.18), rgba(56,225,208,0.07) 46%, transparent 72%)" }}
              />
              <JichoMark size={122} className="relative drop-shadow-[0_0_26px_rgba(245,182,44,0.35)]" />
            </div>

            {/* eyebrow */}
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-[11px] font-medium tracking-wide text-white/60">
              <span className="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse" />
              The watchful eye over African cyberspace
            </div>

            <h1 className="font-display text-[40px] lg:text-[62px] font-bold leading-[1.05] tracking-tight mb-5">
              <span className="text-white">See the threat</span>
              <br />
              <span className="gradient-text">before it sees you</span>
            </h1>
            <p className="text-base lg:text-lg text-white/50 max-w-3xl mx-auto leading-relaxed">
              Africa-first threat intelligence —{" "}
              <span className="text-purple-400 font-medium">threat intel</span>
              {" · "}
              <span className="text-blue-400 font-medium">dark web</span>
              {" · "}
              <span className="text-orange-400 font-medium">brand protection</span>
              {" · "}
              <span className="text-green-400 font-medium">attack surface</span>
              {" · "}
              <span className="text-primary font-medium">AI reports</span>
              {" · "}
              <span className="text-teal-400 font-medium">API access</span>
              <span className="text-white/40">, unified for your SOC.</span>
            </p>
          </div>

          {/* CTAs */}
          <div className="flex flex-wrap items-center justify-center gap-3 mb-10">
            <Link href="/signup" className="btn-primary group">
              Start Free Trial
              <svg className="w-4 h-4 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </Link>
            <Link href="/portal" className="btn-secondary">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
              Open Portal
            </Link>
            <Link href="#demo"
              className="group inline-flex items-center gap-1.5 px-3 py-3 text-sm font-medium text-white/55 hover:text-secondary transition-colors">
              Request Demo
              <svg className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </Link>
          </div>

          {/* ── 6 module pills ─────────────────────────────────────────────── */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5">
            {MODULES.map(m => (
              <Link key={m.id} href={m.href}
                className={`group relative flex items-center gap-3 px-4 py-3.5 rounded-xl bg-card-dark border border-white/8 ${m.borderAccent} transition-all duration-300 hover:-translate-y-0.5 hover:shadow-lg ${m.glowClass} overflow-hidden`}>
                {/* left accent bar */}
                <div className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-xl transition-opacity duration-300 opacity-60 group-hover:opacity-100"
                  style={{ background: m.accent }} />
                {/* icon */}
                <div className={`shrink-0 ${m.accentClass} opacity-80 group-hover:opacity-100 transition-opacity`}>
                  {m.icon}
                </div>
                {/* text */}
                <div className="min-w-0">
                  <p className="text-[12.5px] font-semibold text-white/85 group-hover:text-white leading-tight transition-colors truncate">
                    {m.label}
                  </p>
                  <p className="text-[10px] text-white/30 mt-0.5 truncate">{m.sublabel}</p>
                </div>
              </Link>
            ))}
          </div>


        </div>

        {/* ════════════════════════════════════════════════════════════════════
            BLOCK 2 — Live threat map + console (context / proof)
        ════════════════════════════════════════════════════════════════════ */}
        <div className="pb-6">
          {/* section label */}
          <div className="flex items-center gap-3 mb-3">
            <div className="h-px flex-1 bg-white/8" />
            <div className="flex items-center gap-2 px-4 py-1 rounded-full bg-white/5 border border-white/8">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
              </span>
              <span className="text-[11px] text-white/50 font-medium">Africa&apos;s Real-Time Cyber Threat Intelligence — Watch attacks unfold live</span>
            </div>
            <div className="h-px flex-1 bg-white/8" />
          </div>

          {/* map + console */}
          <div className="grid lg:grid-cols-[1fr_360px] gap-3 items-stretch">

            {/* MAP */}
            <div className="relative rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/60 bg-ebony-950 min-h-[460px] lg:min-h-[520px]">
              <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-ebony-950/95 to-transparent px-4 pt-3 pb-8 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
                    </span>
                    <span className="text-[11px] font-semibold text-green-400">LIVE</span>
                  </div>
                  <span className="text-white/35 text-xs">Aggregated threat feeds</span>
                </div>
                <Link href="/map" target="_blank"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/8 hover:bg-white/15 text-white text-xs font-medium transition-colors border border-white/10">
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M14 10l6.1-6.1M9 21H3v-6M10 14l-6.1 6.1"/></svg>
                  Fullscreen
                </Link>
              </div>

              <div className="w-full h-full absolute inset-0">
                <RealThreatMap />
              </div>

              <div className="absolute bottom-4 left-4 z-20 flex items-center gap-3 px-3 py-2 rounded-xl bg-ebony-950/90 backdrop-blur border border-white/10">
                {[["bg-purple-500","C2"],["bg-red-500","Malware"],["bg-orange-500","Phishing"],["bg-blue-500","DDoS"]].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${c}`} />
                    <span className="text-[11px] text-white/55">{l}</span>
                  </div>
                ))}
              </div>

              {/* floating cards */}
              <div className="absolute top-14 right-3 z-30 p-3 rounded-xl bg-card-dark border border-white/10 shadow-xl animate-float w-44">
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-lg bg-red-500/20 flex items-center justify-center shrink-0">
                    <svg className="w-3.5 h-3.5 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-white">Mozi Botnet</p>
                    <p className="text-[10px] text-white/40">8,913 active hosts</p>
                  </div>
                </div>
              </div>
              <div className="absolute bottom-14 right-3 z-30 p-3 rounded-xl bg-card-dark border border-white/10 shadow-xl animate-float w-44" style={{animationDelay:"1.8s"}}>
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-lg bg-purple-500/20 flex items-center justify-center shrink-0">
                    <svg className="w-3.5 h-3.5 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-white">AsyncRAT C2</p>
                    <p className="text-[10px] text-white/40">New server detected</p>
                  </div>
                </div>
              </div>
            </div>

            {/* LIVE CONSOLE */}
            <div className="flex flex-col rounded-2xl border border-white/10 bg-card-dark overflow-hidden shadow-2xl shadow-black/40">
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/8 bg-ebony-950/60 shrink-0">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                  <span className="text-sm font-semibold text-white">Threat Console</span>
                </div>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-black/30 border border-white/10">
                  <span className={`w-1.5 h-1.5 rounded-full ${statusDot} animate-pulse`} />
                  <span className="text-[10px] font-mono text-white/50">{statusLabel}</span>
                </div>
              </div>

              <div ref={consoleRef} className="flex-1 overflow-y-auto font-mono text-[11px] p-2.5 space-y-1.5" style={{maxHeight:"450px"}}>
                {console_.length === 0 && (
                  <div className="flex items-center gap-2 text-white/25 p-2">
                    <span className="animate-pulse">▋</span>
                    <span>{wsStatus === "idle" ? "Awaiting live threats…" : "Connecting to threat stream…"}</span>
                  </div>
                )}
                {console_.map(e => (
                  <div key={e.id} className={`flex items-start gap-2 p-2 rounded-lg border ${TYPE_BG[e.type] ?? "bg-white/5 border-white/10"}`}>
                    <span className="text-white/20 shrink-0 mt-0.5">{e.ts}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className={`uppercase font-bold text-[10px] ${TYPE_COLOR[e.type] ?? "text-white/50"}`}>{e.type}</span>
                        <span className="text-white/25">·</span>
                        <span className="text-white/45">{e.country}</span>
                        <span className="text-white/25">·</span>
                        <span className="text-white/35 truncate max-w-[60px]">{e.source}</span>
                        <span className="ml-auto shrink-0 text-[10px] font-bold" style={{color: e.risk>=90?"#ef4444":e.risk>=75?"#f97316":"#eab308"}}>{e.risk}</span>
                      </div>
                      <p className="text-white/65 truncate">{e.indicator}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="border-t border-white/8 bg-ebony-950/60 px-4 py-2.5 flex items-center justify-between shrink-0">
                <span className="text-[10px] text-white/25 font-mono">{console_.length} events</span>
                <Link href="/portal" className="text-[10px] text-primary hover:text-primary-light font-medium transition-colors">
                  View full portal →
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* trust bar */}
        <div className="pb-8 border-t border-white/6 pt-5 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p className="text-[10px] text-white/25 uppercase tracking-widest shrink-0">Trusted by security teams</p>
          <div className="flex items-center gap-6 flex-wrap justify-center opacity-30">
            {["Safaricom","Econet","MTN","Standard Bank","KCB Group","Equity Bank"].map(b => (
              <span key={b} className="text-sm font-semibold text-white">{b}</span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
