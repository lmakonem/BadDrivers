"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import { JichoMark } from "@/components/brand/JichoMark";

const RealThreatMap = dynamic(() => import("@/components/map/RealThreatMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full bg-ebony-900/50 flex items-center justify-center">
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
  c2: "text-primary", malware: "text-red-400", phishing: "text-orange-400",
  ddos: "text-secondary", bruteforce: "text-yellow-400",
};
const TYPE_BG: Record<string, string> = {
  c2: "bg-primary/10 border-primary/25", malware: "bg-red-500/10 border-red-500/25",
  phishing: "bg-orange-500/10 border-orange-500/25", ddos: "bg-secondary/10 border-secondary/25",
  bruteforce: "bg-yellow-500/10 border-yellow-500/25",
};

// ── 6 modules — unified gold / cyan set ──────────────────────────────────────
type Tone = "gold" | "cyan";
const TONE: Record<Tone, { text: string; tile: string; border: string; bar: string }> = {
  gold: { text: "text-primary", tile: "bg-primary/10", border: "hover:border-primary/40", bar: "bg-primary" },
  cyan: { text: "text-secondary", tile: "bg-secondary/10", border: "hover:border-secondary/40", bar: "bg-secondary" },
};
// ── the eye scanner (hero right column) ──────────────────────────────────────
function EyeScanner() {
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[400px] sm:max-w-[520px]">
      {/* ambient halo */}
      <div className="absolute inset-0 rounded-full"
        style={{ background: "radial-gradient(circle, rgba(74,222,128,0.16), rgba(56,189,248,0.06) 45%, transparent 70%)" }} />
      {/* ring frame */}
      <svg viewBox="0 0 440 440" className="absolute inset-0 w-full h-full" fill="none" aria-hidden="true">
        <circle cx="220" cy="220" r="200" stroke="rgba(159,176,201,0.12)" strokeWidth="1" />
        <circle cx="220" cy="220" r="200" stroke="#38BDF8" strokeWidth="1" strokeDasharray="3 10" opacity="0.35" className="jm-sweep" />
        <circle cx="220" cy="220" r="152" stroke="rgba(159,176,201,0.10)" strokeWidth="1" />
        {/* connector traces to the orbit chips */}
        <g stroke="#38BDF8" strokeWidth="1" opacity="0.3">
          <path className="circuit-trace" d="M220 68 L220 40" /><path className="circuit-trace" d="M372 220 L400 220" />
          <path className="circuit-trace" d="M220 372 L220 400" /><path className="circuit-trace" d="M68 220 L40 220" />
        </g>
        <g fill="#4ADE80" opacity="0.8">
          <circle cx="220" cy="40" r="2" /><circle cx="400" cy="220" r="2" /><circle cx="220" cy="400" r="2" /><circle cx="40" cy="220" r="2" />
        </g>
      </svg>
      {/* the mark */}
      <div className="absolute inset-0 grid place-items-center">
        <JichoMark size={270} className="drop-shadow-[0_0_40px_rgba(74,222,128,0.28)]" />
      </div>
      {/* orbit chips — what the eye watches */}
      <OrbitChip className="top-0 left-1/2 -translate-x-1/2 -translate-y-1/2" label="DNS threat feeds" tone="gold" />
      <OrbitChip className="top-1/2 right-0 -translate-y-1/2" label="Dark web" tone="cyan" />
      <OrbitChip className="bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2" label="Attack surface" tone="cyan" />
      <OrbitChip className="top-1/2 left-0 -translate-y-1/2" label="Brand abuse" tone="gold" />
    </div>
  );
}
function OrbitChip({ className, label, tone }: { className: string; label: string; tone: Tone }) {
  const t = TONE[tone];
  return (
    <div className={`absolute ${className} whitespace-nowrap flex items-center gap-1.5 rounded-full border border-white/10 bg-ebony-900/85 backdrop-blur px-3 py-1.5 shadow-lg`}>
      <span className={`h-1.5 w-1.5 rounded-full ${t.bar}`} />
      <span className="text-[11px] font-medium text-white/75">{label}</span>
    </div>
  );
}

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

    let replayPool: ConsoleEntry[] = [];
    let replayIdx = 0;

    const startReplay = () => {
      setWsStatus("replay");
      if (replayPool.length > 0) {
        demoTimer = setInterval(() => {
          const entry = replayPool[replayIdx % replayPool.length];
          addEntry({ ...entry, id: ++counterRef.current, ts: new Date().toTimeString().slice(0, 8) });
          replayIdx++;
        }, 1200);
        return;
      }
      const apiBase = process.env.NEXT_PUBLIC_API_URL || `${window.location.protocol}//${window.location.host}`;
      fetch(`${apiBase}/api/v1/indicators/live/feed?limit=200&since_minutes=1440`)
        .then(r => r.json())
        .then(data => {
          const indicators = data.indicators || [];
          if (indicators.length === 0) { setWsStatus("idle"); return; }
          replayPool = indicators.map((ioc: Record<string, unknown>, i: number) => ({
            id: i, ts: "",
            type: String(ioc.threat_type ?? "malware"),
            indicator: String(ioc.indicator ?? ""),
            source: String(ioc.source ?? "feed"),
            country: String(ioc.country_code ?? "??"),
            risk: Number(ioc.risk_score ?? Math.floor(Math.random() * 40 + 60)),
          }));
          replayPool.sort(() => Math.random() - 0.5);
          demoTimer = setInterval(() => {
            const entry = replayPool[replayIdx % replayPool.length];
            addEntry({ ...entry, id: ++counterRef.current, ts: new Date().toTimeString().slice(0, 8) });
            replayIdx++;
          }, 1200);
        })
        .catch(() => { setWsStatus("idle"); });
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

  const statusDot   = wsStatus === "live" ? "bg-green-400" : wsStatus === "replay" ? "bg-primary" : "bg-white/30";
  const statusLabel = wsStatus === "live" ? "LIVE"         : wsStatus === "replay" ? "REPLAY"     : "AWAITING";

  return (
    <section className="relative bg-body-dark overflow-hidden">

      {/* branded ambient backdrop */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute inset-x-0 top-0 h-[720px] circuit-grid opacity-50"
          style={{ maskImage: "linear-gradient(180deg, rgba(0,0,0,0.7), transparent 80%)", WebkitMaskImage: "linear-gradient(180deg, rgba(0,0,0,0.7), transparent 80%)" }} />
        <div className="absolute inset-0 glow-gold" />
        <div className="absolute inset-0 glow-cyan" />
      </div>

      <div className="relative z-10 max-w-[1320px] mx-auto px-6 lg:px-10">

        {/* ════ TOP HERO — text left, watchful-eye scanner right ════ */}
        <div className="pt-28 lg:pt-32 pb-12 grid grid-cols-1 lg:grid-cols-[1.05fr_0.95fr] gap-12 lg:gap-6 items-center">

          {/* LEFT — copy */}
          <div className="text-center lg:text-left min-w-0">
            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-[11px] font-medium tracking-wide text-white/60 mb-7">
              <span className="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse" />
              The watchful eye over African cyberspace
            </div>

            <h1 className="font-display text-[34px] sm:text-[48px] lg:text-[60px] font-bold leading-[1.05] tracking-tight mb-6">
              <span className="text-white">See the threat</span><br />
              <span className="gradient-gold">before it sees you.</span>
            </h1>

            <p className="text-base lg:text-[17px] text-white/55 max-w-xl mx-auto lg:mx-0 leading-relaxed mb-8">
              Africa-first threat intelligence. JichoSec unifies{" "}
              <span className="text-white/80 font-medium">DNS threat feeds, dark-web monitoring, brand protection, and attack-surface visibility</span>{" "}
              into one watchful view for your SOC.
            </p>

            {/* CTAs */}
            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-3 mb-9">
              <Link href="/signup" className="btn-primary group">
                Start Free Trial
                <svg className="w-4 h-4 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
              </Link>
              <Link href="/portal" className="btn-secondary">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                Open Portal
              </Link>
              <Link href="#demo" className="group inline-flex items-center gap-1.5 px-3 py-3 text-sm font-medium text-white/55 hover:text-secondary transition-colors">
                Request Demo
                <svg className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
              </Link>
            </div>

            {/* honest capability chips */}
            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-x-6 gap-y-2 font-mono text-[12px] text-white/40">
              <span className="flex items-center gap-1.5"><span className="text-primary">▹</span> 12 live threat feeds</span>
              <span className="flex items-center gap-1.5"><span className="text-secondary">▹</span> Real-time WebSocket stream</span>
              <span className="flex items-center gap-1.5"><span className="text-primary">▹</span> REST API for SIEM / SOAR</span>
            </div>
          </div>

          {/* RIGHT — the eye */}
          <div className="relative min-w-0">
            <EyeScanner />
          </div>
        </div>

        {/* ════ PROOF — live threat map + console ════ */}
        <div className="pb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="h-px flex-1 bg-white/8" />
            <div className="flex items-center gap-2 px-4 py-1.5 rounded-full bg-white/5 border border-white/10">
              <span className="relative flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75" />
                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-secondary" />
              </span>
              <span className="text-[11px] text-white/55 font-medium">Live from Africa&apos;s networks — watch indicators resolve in real time</span>
            </div>
            <div className="h-px flex-1 bg-white/8" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-3 items-stretch">

            {/* MAP */}
            <div className="relative min-w-0 rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/60 bg-body-dark min-h-[460px] lg:min-h-[520px]">
              <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-body-dark/95 to-transparent px-4 pt-3 pb-8 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-secondary/10 border border-secondary/20">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-secondary" />
                    </span>
                    <span className="text-[11px] font-semibold text-secondary">LIVE</span>
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

              <div className="absolute bottom-4 left-4 z-20 flex items-center gap-3 px-3 py-2 rounded-xl bg-body-dark/90 backdrop-blur border border-white/10">
                {[["bg-primary","C2"],["bg-red-500","Malware"],["bg-orange-500","Phishing"],["bg-secondary","DDoS"]].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${c}`} />
                    <span className="text-[11px] text-white/55">{l}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* LIVE CONSOLE */}
            <div className="flex flex-col min-w-0 rounded-2xl border border-white/10 bg-card-dark overflow-hidden shadow-2xl shadow-black/40">
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/8 bg-ebony-900/60 shrink-0">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                  <span className="text-sm font-semibold text-white">Threat Console</span>
                </div>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-black/30 border border-white/10">
                  <span className={`w-1.5 h-1.5 rounded-full ${statusDot} animate-pulse`} />
                  <span className="text-[10px] font-mono text-white/50">{statusLabel}</span>
                </div>
              </div>

              <div ref={consoleRef} className="flex-1 overflow-y-auto font-mono text-[11px] p-2.5 space-y-1.5" style={{maxHeight:"470px"}}>
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
                        <span className="ml-auto shrink-0 text-[10px] font-bold" style={{color: e.risk>=90?"#ef4444":e.risk>=75?"#f97316":"#4ADE80"}}>{e.risk}</span>
                      </div>
                      <p className="text-white/65 truncate">{e.indicator}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="border-t border-white/8 bg-ebony-900/60 px-4 py-2.5 flex items-center justify-between shrink-0">
                <span className="text-[10px] text-white/25 font-mono">{console_.length} events</span>
                <Link href="/portal" className="text-[10px] text-primary hover:text-primary-light font-medium transition-colors">
                  View full portal →
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
