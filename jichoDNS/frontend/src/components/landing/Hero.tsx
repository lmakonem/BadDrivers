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

// Colors mirror components/map/RealThreatMap.tsx THREAT_COLORS so the console,
// the map dots, and the legend all agree (c2 = purple, phishing = orange).
const TYPE_COLOR: Record<string, string> = {
  c2: "text-purple-400", malware: "text-red-400", phishing: "text-orange-400",
  ddos: "text-secondary", bruteforce: "text-yellow-400",
};
const TYPE_BG: Record<string, string> = {
  c2: "bg-purple-500/10 border-purple-500/25", malware: "bg-red-500/10 border-red-500/25",
  phishing: "bg-orange-500/10 border-orange-500/25", ddos: "bg-secondary/10 border-secondary/25",
  bruteforce: "bg-yellow-500/10 border-yellow-500/25",
};

// ── the eye — calm brand art (hero right column) ─────────────────────────────
// Restraint pass: the clean JichoMark over a single soft radial glow.
// No orbiting chips, no dashed scanner rings — flat, spacious, opsec-style.
function HeroEye() {
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[380px] lg:max-w-[480px]">
      {/* one soft radial glow — oversized so the right column reads as composed, not empty */}
      <div
        aria-hidden="true"
        className="absolute -inset-[14%] rounded-full"
        style={{ background: "radial-gradient(circle at center, rgba(74,222,128,0.17), rgba(74,222,128,0.05) 46%, transparent 70%)" }}
      />
      <div className="absolute inset-0 grid place-items-center">
        <JichoMark size={430} className="w-[86%] h-auto drop-shadow-[0_0_60px_rgba(74,222,128,0.28)]" />
      </div>
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
            risk: Number(ioc.risk_score ?? 0),
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
                risk: Number(ioc.risk_score ?? 0),
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
    <>
      {/* ════════════════════════════════════════════════════════════════════
          HERO — flat near-black navy, one subtle radial glow top-right.
          Split: copy left, calm eye right. Lots of negative space.
         ════════════════════════════════════════════════════════════════════ */}
      <section className="relative overflow-hidden">
        <div className="relative z-10 mx-auto max-w-[1200px] px-6 lg:px-8 pt-28 lg:pt-32 pb-6 lg:pb-8">
          <div className="grid grid-cols-1 lg:grid-cols-[1.05fr_0.95fr] items-center gap-8 lg:gap-10">

            {/* LEFT — copy */}
            <div className="text-center lg:text-left min-w-0">
              <span className="inline-block font-display text-[0.8rem] font-medium uppercase tracking-[0.16em] text-primary mb-5">
                Africa-first threat intelligence
              </span>

              <h1 className="font-display font-bold text-white leading-[1.06] tracking-tight text-[clamp(2.4rem,4.6vw,3.6rem)]">
                See the threat<br />
                before it <span className="text-primary">sees you.</span>
              </h1>

              <p className="mt-6 text-[1.0625rem] lg:text-lg leading-relaxed text-slate-400 max-w-[50ch] mx-auto lg:mx-0 text-pretty">
                JichoSec unifies{" "}
                <span className="text-white/90 font-medium">DNS threat feeds, dark-web monitoring, brand protection, and attack-surface visibility</span>{" "}
                into one watchful view for your SOC.
              </p>

              <div className="mt-9 flex flex-wrap items-center justify-center lg:justify-start gap-4">
                <Link href="/signup" className="btn-primary group whitespace-nowrap">
                  Get Started
                  <svg className="w-4 h-4 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                </Link>
                <Link href="#demo" className="btn-secondary group whitespace-nowrap">
                  See how it works
                  <span className="transition-transform group-hover:translate-x-0.5">→</span>
                </Link>
              </div>
            </div>

            {/* RIGHT — the calm eye */}
            <div className="relative min-w-0">
              <HeroEye />
            </div>
          </div>
        </div>
      </section>

      {/* ════════════════════════════════════════════════════════════════════
          SEE IT LIVE — restrained section, flat bg (no grid, no glow).
          Live threat map + console. All WebSocket/console logic preserved.
         ════════════════════════════════════════════════════════════════════ */}
      <section id="live" className="relative">
        <div className="mx-auto max-w-[1200px] px-6 lg:px-8 pb-16 lg:pb-24">

          {/* section head — green uppercase label + big Space Grotesk title */}
          <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-4 mb-10 lg:mb-12">
            <div className="min-w-0">
              <span className="inline-block font-display text-[0.8rem] font-medium uppercase tracking-[0.16em] text-primary mb-4">
                See it live
              </span>
              <h2 className="font-display font-bold text-white leading-[1.12] tracking-tight text-[clamp(1.9rem,3.2vw,2.6rem)] whitespace-normal lg:whitespace-nowrap">
                Africa&apos;s threats, resolving in real time.
              </h2>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-card-dark border border-[#1E2A3D]">
              <span className={`w-1.5 h-1.5 rounded-full ${statusDot} animate-pulse`} />
              <span className="text-[11px] font-mono tracking-wide text-slate-400">{statusLabel}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-4 items-stretch">

            {/* MAP */}
            <div className="relative min-w-0 rounded-[14px] overflow-hidden border border-[#1E2A3D] bg-body-dark min-h-[460px] lg:min-h-[520px]">
              <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-body-dark/95 to-transparent px-4 pt-3 pb-8 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-primary/10 border border-primary/20">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                      <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-primary" />
                    </span>
                    <span className="text-[11px] font-semibold text-primary">LIVE</span>
                  </div>
                  <span className="text-slate-400 text-xs">Aggregated threat feeds</span>
                </div>
                <Link href="/map" target="_blank"
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/8 hover:bg-white/15 text-white text-xs font-medium transition-colors border border-[#1E2A3D]">
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M14 10l6.1-6.1M9 21H3v-6M10 14l-6.1 6.1"/></svg>
                  Fullscreen
                </Link>
              </div>

              <div className="w-full h-full absolute inset-0">
                <RealThreatMap />
              </div>

              <div className="absolute bottom-4 left-4 z-20 flex items-center gap-3 px-3 py-2 rounded-xl bg-body-dark/90 backdrop-blur border border-[#1E2A3D]">
                {[["bg-purple-500","C2"],["bg-red-500","Malware"],["bg-orange-500","Phishing"],["bg-secondary","DDoS"]].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${c}`} />
                    <span className="text-[11px] text-slate-400">{l}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* LIVE CONSOLE */}
            <div className="flex flex-col min-w-0 rounded-[14px] border border-[#1E2A3D] bg-card-dark overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-[#1E2A3D] bg-ebony-900/60 shrink-0">
                <div className="flex items-center gap-2">
                  <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                  <span className="text-sm font-semibold text-white">Threat Console</span>
                </div>
                <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-black/30 border border-[#1E2A3D]">
                  <span className={`w-1.5 h-1.5 rounded-full ${statusDot} animate-pulse`} />
                  <span className="text-[10px] font-mono text-slate-400">{statusLabel}</span>
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

              <div className="border-t border-[#1E2A3D] bg-ebony-900/60 px-4 py-2.5 flex items-center justify-between shrink-0">
                <span className="text-[10px] text-white/25 font-mono">{console_.length} events</span>
                <Link href="/portal" className="text-[10px] text-primary hover:text-primary-light font-medium transition-colors">
                  View full portal →
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
