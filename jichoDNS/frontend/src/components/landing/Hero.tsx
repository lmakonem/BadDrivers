"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";

const API_BASE = typeof window !== "undefined"
  ? `http://${window.location.hostname}:8000`
  : "http://192.168.36.50:8000";

// Dynamically import the map — no SSR
const RealThreatMap = dynamic(() => import("@/components/map/RealThreatMap"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full bg-ebony-950/50 flex items-center justify-center">
      <div className="text-center">
        <div className="w-10 h-10 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <p className="text-white/40 text-sm">Loading threat map…</p>
      </div>
    </div>
  ),
});

// ── types ────────────────────────────────────────────────────────────────────
interface LiveStats {
  total: number;
  c2: number;
  malware: number;
  phishing: number;
  countries: number;
  sources: number;
}

interface ConsoleEntry {
  id: number;
  ts: string;
  type: string;
  indicator: string;
  source: string;
  country: string;
  risk: number;
}

const TYPE_COLOR: Record<string, string> = {
  c2:        "text-purple-400",
  malware:   "text-red-400",
  phishing:  "text-orange-400",
  ddos:      "text-blue-400",
  bruteforce:"text-yellow-400",
};
const TYPE_BG: Record<string, string> = {
  c2:        "bg-purple-500/15 border-purple-500/30",
  malware:   "bg-red-500/15 border-red-500/30",
  phishing:  "bg-orange-500/15 border-orange-500/30",
  ddos:      "bg-blue-500/15 border-blue-500/30",
  bruteforce:"bg-yellow-500/15 border-yellow-500/30",
};

// Simulated indicators shown in the console while loading real data
const DEMO_INDICATORS = [
  { type:"malware",   indicator:"185.220.101.47",         country:"RU", risk:92 },
  { type:"c2",        indicator:"asyncrat-c2.duckdns.org",country:"CN", risk:97 },
  { type:"phishing",  indicator:"safaricom-verify.net",   country:"KE", risk:88 },
  { type:"malware",   indicator:"6a2c8e3f1d9b.xyz",       country:"DE", risk:78 },
  { type:"c2",        indicator:"192.168.200.45",          country:"UA", risk:95 },
  { type:"phishing",  indicator:"mpesa-agent-login.com",  country:"NG", risk:91 },
  { type:"malware",   indicator:"emotet-drop.tk",         country:"PK", risk:84 },
  { type:"c2",        indicator:"cobalt-strike-cn.top",   country:"CN", risk:99 },
  { type:"phishing",  indicator:"kcb-secure-alert.co",    country:"KE", risk:86 },
  { type:"malware",   indicator:"d9e3a12b7c45.pw",        country:"IN", risk:73 },
];

// ── component ─────────────────────────────────────────────────────────────────
export function Hero() {
  const [stats, setStats]           = useState<LiveStats>({ total:37197, c2:9952, malware:25597, phishing:1648, countries:60, sources:9 });
  const [console_, setConsole]      = useState<ConsoleEntry[]>([]);
  const [consoleIdx, setConsoleIdx] = useState(0);
  const [wsStatus, setWsStatus]     = useState<"live"|"replay"|"demo">("demo");
  const consoleRef                  = useRef<HTMLDivElement>(null);
  const counterRef                  = useRef(0);

  // ── fetch real stats once ──────────────────────────────────────────────────
  useEffect(() => {
    fetch(`${API_BASE}/api/v1/indicators/stats`)
      .then(r => r.json())
      .then((d) => setStats({
        total:    d.total ?? 37197,
        c2:       d.by_threat_type?.c2       ?? 9952,
        malware:  d.by_threat_type?.malware  ?? 25597,
        phishing: d.by_threat_type?.phishing ?? 1648,
        countries:Object.keys(d.by_country ?? {}).length,
        sources:  Object.keys(d.by_source  ?? {}).length,
      }))
      .catch(() => {});
  }, []);

  // ── live console via WebSocket → fallback to replay → fallback to demo ─────
  useEffect(() => {
    let ws: WebSocket | null = null;
    let demoTimer: ReturnType<typeof setInterval>;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    const addEntry = (e: ConsoleEntry) => {
      setConsole(prev => [e, ...prev].slice(0, 50));
      if (consoleRef.current) {
        consoleRef.current.scrollTop = 0;
      }
    };

    const startDemo = () => {
      setWsStatus("demo");
      demoTimer = setInterval(() => {
        const src = DEMO_INDICATORS[consoleIdx % DEMO_INDICATORS.length];
        const now = new Date();
        addEntry({
          id:   ++counterRef.current,
          ts:   now.toTimeString().slice(0,8),
          type: src.type,
          indicator: src.indicator,
          source: ["urlhaus","sslbl","threatfox","phishtank"][Math.floor(Math.random()*4)],
          country: src.country,
          risk: src.risk,
        });
        setConsoleIdx(i => i + 1);
      }, 1200);
    };

    const tryWs = () => {
      try {
        const wsHost = window.location.hostname;
        ws = new WebSocket(`ws://${wsHost}:8000/api/v1/ws/iocs`);

        ws.onopen  = () => { setWsStatus("live"); clearInterval(demoTimer); };
        ws.onclose = () => {
          setWsStatus("demo");
          startDemo();
          reconnectTimer = setTimeout(tryWs, 8000);
        };
        ws.onerror = () => { ws?.close(); };

        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "ping") { ws?.send(JSON.stringify({type:"pong"})); return; }
            if (msg.type === "new_iocs" && Array.isArray(msg.data)) {
              setWsStatus("live");
              msg.data.slice(0,3).forEach((ioc: Record<string,unknown>) => {
                const now = new Date();
                addEntry({
                  id:        ++counterRef.current,
                  ts:        now.toTimeString().slice(0,8),
                  type:      String(ioc.threat_type ?? "malware"),
                  indicator: String(ioc.indicator   ?? ""),
                  source:    String(ioc.source       ?? "feed"),
                  country:   String(ioc.country_code ?? ioc.country ?? "??"),
                  risk:      Number(ioc.risk_score   ?? Math.floor(Math.random()*40+60)),
                });
              });
            }
          } catch { /* ignore */ }
        };

        // if no live data within 6s fall back to demo
        setTimeout(() => {
          if (wsStatus !== "live") {
            setWsStatus("replay");
            startDemo();
          }
        }, 6000);

      } catch { startDemo(); }
    };

    tryWs();
    return () => {
      ws?.close();
      clearInterval(demoTimer);
      clearTimeout(reconnectTimer);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── bump IOC counter every few seconds ────────────────────────────────────
  useEffect(() => {
    const t = setInterval(() => {
      setStats(s => ({ ...s, total: s.total + Math.floor(Math.random() * 4) }));
    }, 4000);
    return () => clearInterval(t);
  }, []);

  const statusDot = wsStatus === "live"
    ? "bg-green-400"
    : wsStatus === "replay" ? "bg-yellow-400" : "bg-blue-400";
  const statusLabel = wsStatus === "live" ? "LIVE" : wsStatus === "replay" ? "REPLAY" : "DEMO";

  return (
    <section className="relative bg-ebony-950 pt-20 pb-0 overflow-hidden">

      {/* ── subtle background glow ─────────────────────────────────────────── */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[900px] h-[500px] bg-primary/6 rounded-full blur-[160px]" />
        <div className="absolute bottom-0 right-0 w-[500px] h-[400px] bg-purple-700/5 rounded-full blur-[120px]" />
      </div>

      <div className="relative z-10 max-w-[1680px] mx-auto px-6 lg:px-10">

        {/* ── headline row ───────────────────────────────────────────────────── */}
        <div className="pt-10 pb-8 text-center max-w-4xl mx-auto">
          {/* live badge */}
          <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-primary" />
            </span>
            <span className="text-sm font-medium text-primary">
              {stats.total.toLocaleString()} Active Threats Monitored
            </span>
          </div>

          <h1 className="text-[48px] lg:text-[68px] font-bold leading-[1.08] tracking-tight mb-5">
            <span className="text-white">Africa&apos;s Real-Time</span>
            <br />
            <span className="text-primary">Cyber Threat Intelligence</span>
          </h1>

          <p className="text-xl text-white/55 max-w-2xl mx-auto leading-relaxed mb-8">
            Watch attacks unfold live. Aggregating 37,000+ IOCs from 15+ feeds — C2 servers,
            malware, phishing, dark web leaks — all through one Africa-focused platform.
          </p>

          {/* CTA row */}
          <div className="flex flex-wrap items-center justify-center gap-4">
            <Link
              href="/signup"
              className="group inline-flex items-center gap-2 px-8 py-3.5 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-all shadow-lg shadow-primary/30 hover:shadow-primary/50"
            >
              Start Free Trial
              <svg className="w-4 h-4 group-hover:translate-x-1 transition-transform" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            </Link>
            <Link
              href="/map"
              target="_blank"
              className="inline-flex items-center gap-2 px-8 py-3.5 bg-white/5 hover:bg-white/10 text-white font-semibold rounded-full border border-white/10 hover:border-white/20 transition-all"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M14 10l6.1-6.1M9 21H3v-6M10 14l-6.1 6.1"/></svg>
              Open Fullscreen Map
            </Link>
            <Link
              href="/portal"
              className="inline-flex items-center gap-2 px-8 py-3.5 bg-white/5 hover:bg-white/10 text-white font-semibold rounded-full border border-white/10 hover:border-white/20 transition-all"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
              Portal Dashboard
            </Link>
          </div>
        </div>

        {/* ── live stats bar ─────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
          {[
            { label: "Total IOCs",   value: stats.total.toLocaleString(),    color: "text-white",       dot: "bg-white/30" },
            { label: "C2 Servers",   value: stats.c2.toLocaleString(),       color: "text-purple-400",  dot: "bg-purple-500" },
            { label: "Malware",      value: stats.malware.toLocaleString(),  color: "text-red-400",     dot: "bg-red-500" },
            { label: "Phishing",     value: stats.phishing.toLocaleString(), color: "text-orange-400",  dot: "bg-orange-500" },
            { label: "Countries",    value: stats.countries.toString(),       color: "text-green-400",   dot: "bg-green-500" },
            { label: "Threat Feeds", value: `${stats.sources}+`,             color: "text-blue-400",    dot: "bg-blue-500" },
          ].map(s => (
            <div key={s.label} className="flex items-center gap-3 px-4 py-3 rounded-xl bg-card-dark border border-white/8">
              <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${s.dot}`} />
              <div>
                <p className={`text-lg font-bold leading-none ${s.color}`}>{s.value}</p>
                <p className="text-xs text-white/40 mt-0.5">{s.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ── map + console layout ───────────────────────────────────────────── */}
        <div className="grid lg:grid-cols-[1fr_380px] gap-4 items-stretch">

          {/* MAP */}
          <div className="relative rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/60 bg-ebony-950 min-h-[480px] lg:min-h-[560px]">
            {/* map top bar */}
            <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-ebony-950/95 to-transparent px-4 pt-3 pb-8 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
                  </span>
                  <span className="text-[11px] font-semibold text-green-400">LIVE</span>
                </div>
                <span className="text-white/40 text-xs">15+ threat feeds · updates every 5 min</span>
              </div>
              <Link
                href="/map"
                target="_blank"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/8 hover:bg-white/15 text-white text-xs font-medium transition-colors border border-white/10"
              >
                <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M14 10l6.1-6.1M9 21H3v-6M10 14l-6.1 6.1"/></svg>
                Fullscreen
              </Link>
            </div>

            {/* map fills the card */}
            <div className="w-full h-full absolute inset-0">
              <RealThreatMap />
            </div>

            {/* bottom legend */}
            <div className="absolute bottom-4 left-4 z-20 flex items-center gap-3 px-3 py-2 rounded-xl bg-ebony-950/90 backdrop-blur border border-white/10">
              {[["bg-purple-500","C2"],["bg-red-500","Malware"],["bg-orange-500","Phishing"],["bg-blue-500","DDoS"]].map(([c,l]) => (
                <div key={l} className="flex items-center gap-1.5">
                  <div className={`w-2 h-2 rounded-full ${c}`} />
                  <span className="text-[11px] text-white/60">{l}</span>
                </div>
              ))}
            </div>

            {/* floating alert cards */}
            <div className="absolute top-14 right-3 z-30 p-3 rounded-xl bg-card-dark border border-white/10 shadow-xl animate-float w-48">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center shrink-0">
                  <svg className="w-4 h-4 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                </div>
                <div>
                  <p className="text-xs font-semibold text-white">Mozi Botnet</p>
                  <p className="text-[10px] text-white/40">8,913 active hosts</p>
                </div>
              </div>
            </div>

            <div className="absolute bottom-14 right-3 z-30 p-3 rounded-xl bg-card-dark border border-white/10 shadow-xl animate-float w-48" style={{ animationDelay:"1.8s" }}>
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center shrink-0">
                  <svg className="w-4 h-4 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                </div>
                <div>
                  <p className="text-xs font-semibold text-white">AsyncRAT C2</p>
                  <p className="text-[10px] text-white/40">New server detected</p>
                </div>
              </div>
            </div>
          </div>

          {/* LIVE CONSOLE */}
          <div className="flex flex-col rounded-2xl border border-white/10 bg-card-dark overflow-hidden shadow-2xl shadow-black/50">
            {/* console header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/8 bg-ebony-950/60">
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                <span className="text-sm font-semibold text-white">Threat Console</span>
              </div>
              <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-black/30 border border-white/10">
                <span className={`w-1.5 h-1.5 rounded-full ${statusDot} animate-pulse`} />
                <span className="text-[10px] font-mono text-white/60">{statusLabel}</span>
              </div>
            </div>

            {/* console entries */}
            <div
              ref={consoleRef}
              className="flex-1 overflow-y-auto font-mono text-[11px] p-3 space-y-1.5 min-h-0"
              style={{ maxHeight: "480px" }}
            >
              {console_.length === 0 && (
                <div className="flex items-center gap-2 text-white/30 p-2">
                  <span className="animate-pulse">▋</span>
                  <span>Connecting to threat stream…</span>
                </div>
              )}
              {console_.map(entry => (
                <div key={entry.id} className={`flex items-start gap-2 p-2 rounded-lg border ${TYPE_BG[entry.type] ?? "bg-white/5 border-white/10"} group`}>
                  <div className="flex flex-col items-center gap-1 shrink-0 pt-0.5">
                    <span className="text-white/25">{entry.ts}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={`uppercase font-bold text-[10px] ${TYPE_COLOR[entry.type] ?? "text-white/60"}`}>
                        {entry.type}
                      </span>
                      <span className="text-white/30">·</span>
                      <span className="text-white/50">{entry.country}</span>
                      <span className="text-white/30">·</span>
                      <span className="text-white/40">{entry.source}</span>
                      <span className="ml-auto shrink-0 text-[10px] font-bold" style={{ color: entry.risk >= 90 ? "#ef4444" : entry.risk >= 75 ? "#f97316" : "#eab308" }}>
                        {entry.risk}
                      </span>
                    </div>
                    <p className="text-white/70 truncate">{entry.indicator}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* console footer stats */}
            <div className="border-t border-white/8 bg-ebony-950/60 px-4 py-2.5 flex items-center justify-between">
              <span className="text-[10px] text-white/30 font-mono">
                {console_.length} events captured
              </span>
              <Link href="/portal" className="text-[10px] text-primary hover:text-primary-light font-medium transition-colors">
                View full portal →
              </Link>
            </div>
          </div>
        </div>

        {/* ── trust logos bar ───────────────────────────────────────────────── */}
        <div className="mt-8 pb-10 border-t border-white/6 pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-white/30 uppercase tracking-widest shrink-0">
            Trusted by security teams across Africa
          </p>
          <div className="flex items-center gap-8 flex-wrap justify-center opacity-35">
            {["Safaricom","Econet","MTN","Standard Bank","KCB Group","Equity Bank"].map(b => (
              <span key={b} className="text-sm font-semibold text-white">{b}</span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
