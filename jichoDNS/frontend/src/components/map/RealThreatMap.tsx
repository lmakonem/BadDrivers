"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { COUNTRY_COORDS, AFRICAN_TARGETS } from "./countries";

// Re-export for use in other components
export { AFRICAN_COUNTRY_LIST } from "./countries";

const THREAT_COLORS: Record<string, string> = {
  malware: "#ef4444",
  c2: "#a855f7",        // Purple (swapped with phishing)
  phishing: "#f97316",  // Orange (swapped with c2)
  ddos: "#3b82f6",
  bruteforce: "#eab308",
  botnet: "#f97316",
  exfil: "#a855f7",
  unknown: "#6b7280",
};

// JichoSec's African monitoring vantage. Every arc runs from an IOC's REAL
// origin to THIS fixed sensor — the honest claim is "malicious infrastructure
// observed by our African sensors", never a fabricated victim/target country.
const MONITORING_VANTAGE = {
  lat: -1.2864,
  lon: 36.8172,
  name: "Nairobi",
  label: "JichoSec Sensor · Nairobi",
};

interface ThreatIndicator {
  indicator: string;
  indicator_type: string;
  threat_type: string;
  source: string;
  confidence: number;
  risk_score: number;
  country_code?: string;
  asn?: number;
  asn_org?: string;
  ip_address?: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

// A single geolocated IOC. Rendered as an arc from its REAL origin country to
// JichoSec's fixed monitoring sensor (MONITORING_VANTAGE). IOCs have no
// victim/target field, so we never invent a per-threat destination — the arc's
// endpoint is always OUR sensor ("observed by us"), never a fabricated victim.
interface Signal {
  id: number;
  coord: { lat: number; lon: number };
  originName: string;
  originCode: string;
  color: string;
  progress: number;
  type: string;
  indicator: ThreatIndicator;
}

interface RealThreatMapProps {
  onSignal?: (event: {
    origin: { name: string; code: string };
    threatType: string;
    color: string;
    timestamp: Date;
    indicator: ThreatIndicator;
    isReplay?: boolean;
  }) => void;
  onStatsUpdate?: (stats: {
    total: number;
    byType: Record<string, number>;
    byOrigin: Record<string, number>;
  }) => void;
  onConnectionStatus?: (status: "connecting" | "connected" | "disconnected" | "replay") => void;
  selectedCountries?: string[];
  apiBaseUrl?: string;
}

export default function RealThreatMap({
  onSignal,
  onStatsUpdate,
  onConnectionStatus,
  selectedCountries,
  apiBaseUrl,
}: RealThreatMapProps) {
  // Compute API URL on client side only (not during SSR)
  const effectiveApiUrl = useMemo(() => {
    if (apiBaseUrl) return apiBaseUrl;
    
    // Must check window exists (client-side only)
    if (typeof window === "undefined") return "";
    
    const currentHost = window.location.hostname;
    const currentPort = window.location.port;
    
    // If running on port 3000 (Next.js), API is on 8000
    if (currentPort === "3000") {
      return `http://${currentHost}:8000`;
    }
    // Otherwise, assume API is on same origin
    return "";
  }, [apiBaseUrl]);

  // WebSocket URL — derives from API URL or current origin.
  // The /ws/iocs stream is intentionally PUBLIC: it must carry NO credential.
  // Never append a token query param here — that would leak the JWT into the
  // URL (browser history, proxy/access logs, Referer). Connect to the bare path.
  const wsUrl = useMemo(() => {
    if (typeof window === "undefined") return "";
    if (effectiveApiUrl) {
      return effectiveApiUrl.replace(/^http/, "ws") + "/api/v1/ws/iocs";
    }
    // Same-origin: build WS URL from current page location
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/api/v1/ws/iocs`;
  }, [effectiveApiUrl]);

  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<"connecting" | "connected" | "disconnected" | "replay">("connecting");
  const [totalIndicators, setTotalIndicators] = useState(0);

  const stateRef = useRef({
    map: null as L.Map | null,
    signals: [] as Signal[],
    signalId: 0,
    stats: {
      total: 0,
      byType: {} as Record<string, number>,
      byOrigin: {} as Record<string, number>,
    },
    animationId: 0,
    ws: null as WebSocket | null,
    wsReconnectTimeout: null as ReturnType<typeof setTimeout> | null,
    wsReconnectAttempts: 0,   // for exponential backoff
    wsMounted: true,          // false after unmount — blocks zombie reconnects
    selectedCountries:
      selectedCountries && selectedCountries.length > 0
        ? selectedCountries
        : AFRICAN_TARGETS,
    onStatsUpdate,
    onConnectionStatus,
    pendingIndicators: [] as ThreatIndicator[],
    allIndicators: [] as ThreatIndicator[],  // Full pool for replay
    currentReplayIndex: 0,
    connectionStatus: "connecting" as "connecting" | "connected" | "disconnected" | "replay",
    setConnectionStatus: null as ((status: "connecting" | "connected" | "disconnected" | "replay") => void) | null,
    isLiveMode: true,  // Start in live mode, fall back to replay if no data
    liveTimeout: null as ReturnType<typeof setTimeout> | null,  // Timer for fallback to replay
    onSignal,
  });

  // Keep callbacks and selected countries fresh
  useEffect(() => {
    stateRef.current.onSignal = onSignal;
    stateRef.current.onStatsUpdate = onStatsUpdate;
    stateRef.current.onConnectionStatus = onConnectionStatus;
    stateRef.current.setConnectionStatus = setConnectionStatus;
    stateRef.current.selectedCountries =
      selectedCountries && selectedCountries.length > 0
        ? selectedCountries
        : AFRICAN_TARGETS;
  }, [onSignal, onStatsUpdate, onConnectionStatus, selectedCountries]);

  // Notify connection status changes
  useEffect(() => {
    if (stateRef.current.onConnectionStatus) {
      stateRef.current.onConnectionStatus(connectionStatus);
    }
    stateRef.current.connectionStatus = connectionStatus;
  }, [connectionStatus]);

  // Fetch indicators for the replay pool (loaded in background)
  const fetchAllIndicators = useCallback(async () => {
    try {
      // The public feed handler caps limit<=500 and since_minutes<=1440 (24h).
      // Requesting beyond either cap returns HTTP 422 and the map loads 0 IOCs,
      // so we stay strictly within the ceiling here.
      const token = typeof window !== "undefined" ? localStorage.getItem("jichodns_access_token") : null;
      const headers: Record<string, string> = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const response = await fetch(
        `${effectiveApiUrl}/api/v1/indicators/live/feed?limit=500&since_minutes=1440`,
        { headers },
      );

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();

      // Keep only IOCs we can actually geolocate. Un-geolocated indicators are
      // excluded from the map rather than being dropped at a random country —
      // we never fabricate an origin.
      const indicators: ThreatIndicator[] = (data.indicators || []).filter(
        (ind: ThreatIndicator) => ind.country_code && COUNTRY_COORDS[ind.country_code],
      );

      // Reverse to show newest first when replaying
      indicators.reverse();

      setTotalIndicators(indicators.length);
      stateRef.current.allIndicators = indicators;
      stateRef.current.currentReplayIndex = 0;

      // Data is loaded — show the map and start replay immediately
      setIsLoading(false);
      setError(null);
      stateRef.current.isLiveMode = false;
      setConnectionStatus("replay");

      console.log(`Loaded ${indicators.length} geolocated indicators for replay pool`);

    } catch (err) {
      console.error("Failed to fetch indicators for replay:", err);
      // Even on error, stop loading so the map renders. The replay pool stays
      // empty and the live WebSocket feed remains the source of activity.
      setIsLoading(false);
    }
  }, [effectiveApiUrl]);

  // Connect to WebSocket for real-time updates
  const connectWebSocket = useCallback(() => {
    if (!wsUrl) return;
    // Don't (re)connect after the component has unmounted
    if (!stateRef.current.wsMounted) return;

    // Tear down any existing socket WITHOUT letting its handlers fire —
    // otherwise the old socket's onclose would schedule a second reconnect
    // loop and we'd get compounding reconnect storms.
    const existing = stateRef.current.ws;
    if (existing) {
      existing.onopen = null;
      existing.onmessage = null;
      existing.onerror = null;
      existing.onclose = null;
      try { existing.close(); } catch { /* ignore */ }
    }
    // Cancel any pending reconnect timer before opening a fresh socket
    if (stateRef.current.wsReconnectTimeout) {
      clearTimeout(stateRef.current.wsReconnectTimeout);
      stateRef.current.wsReconnectTimeout = null;
    }

    const ws = new WebSocket(wsUrl);
    stateRef.current.ws = ws;

    ws.onopen = () => {
      console.log("WebSocket connected");
      // A clean open resets the backoff sequence
      stateRef.current.wsReconnectAttempts = 0;
      setIsLoading(false);
      setError(null);
      // If we already have replay data loaded, keep replaying — don't block
      // Only enter live-wait mode if we have nothing to show yet
      if (stateRef.current.allIndicators.length === 0) {
        stateRef.current.isLiveMode = true;
        setConnectionStatus("connected");
      }
      // No liveTimeout needed — replay runs continuously,
      // live WS data will interrupt it naturally via pendingIndicators
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === "new_iocs" && data.indicators && data.indicators.length > 0) {
          console.log(`LIVE: Received ${data.indicators.length} new IOCs from ${data.source}`);
          
          // Clear the fallback timer - we have live data!
          if (stateRef.current.liveTimeout) {
            clearTimeout(stateRef.current.liveTimeout);
            stateRef.current.liveTimeout = null;
          }
          
          // Exit initial waiting mode - allow replay after live data is done
          stateRef.current.isLiveMode = false;
          
          // Add to pending queue for animation (these interrupt replay)
          for (const indicator of data.indicators) {
            if (indicator.country_code) {
              stateRef.current.pendingIndicators.push(indicator);
            }
          }
          
          setTotalIndicators(stateRef.current.allIndicators.length);
        } else if (data.type === "ping") {
          // Respond to keep connection alive
          ws.send(JSON.stringify({ type: "pong" }));
        }
      } catch (err) {
        console.error("Failed to parse WebSocket message:", err);
      }
    };
    
    ws.onclose = () => {
      console.log("WebSocket disconnected, replay continues");
      stateRef.current.isLiveMode = false;
      if (stateRef.current.allIndicators.length > 0) {
        setConnectionStatus("replay");
      }
      // Guard: never reschedule after unmount (zombie reconnect)
      if (!stateRef.current.wsMounted) return;

      // Exponential backoff with jitter, capped, with a max-retry ceiling.
      // Replay keeps the map alive, so giving up on live reconnects is fine.
      const MAX_RECONNECT_ATTEMPTS = 8;
      const attempt = stateRef.current.wsReconnectAttempts;
      if (attempt >= MAX_RECONNECT_ATTEMPTS) {
        console.warn(
          `WebSocket reconnect cap reached (${MAX_RECONNECT_ATTEMPTS}); staying in replay mode`,
        );
        return;
      }
      stateRef.current.wsReconnectAttempts = attempt + 1;
      // 1s, 2s, 4s, … capped at 30s, plus up to 30% random jitter
      const backoff = Math.min(30000, 1000 * 2 ** attempt);
      const delay = backoff + Math.random() * 0.3 * backoff;
      stateRef.current.wsReconnectTimeout = setTimeout(() => {
        connectWebSocket();
      }, delay);
    };
    
    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
      // Will trigger onclose
    };
    
  }, [wsUrl]);

  useEffect(() => {
    // (Re)arm the socket lifecycle for this mount
    stateRef.current.wsMounted = true;
    stateRef.current.wsReconnectAttempts = 0;

    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Initialize map
    const map = L.map(container, {
      center: [5, 20],
      zoom: 2.5,
      minZoom: 2,
      maxZoom: 8,
      zoomControl: false,
      attributionControl: false,
    });
    stateRef.current.map = map;

    L.tileLayer(
      "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      {
        subdomains: "abcd",
        maxZoom: 19,
      }
    ).addTo(map);

    L.control.zoom({ position: "bottomright" }).addTo(map);

    // Resize canvas
    const resizeCanvas = () => {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    };
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);
    map.on("move zoom", resizeCanvas);

    // Build an origin ping from a real indicator. Returns null when the
    // indicator has no usable origin geo — we never fabricate a location,
    // and there is no victim/target to invent.
    const createSignal = (indicator: ThreatIndicator): Signal | null => {
      const originCode = indicator.country_code;
      if (!originCode || !COUNTRY_COORDS[originCode]) return null;
      const origin = COUNTRY_COORDS[originCode];

      stateRef.current.signalId++;

      return {
        id: stateRef.current.signalId,
        coord: { lat: origin.lat, lon: origin.lon },
        originName: origin.name,
        originCode,
        color: THREAT_COLORS[indicator.threat_type] || THREAT_COLORS.unknown,
        progress: 0,
        type: indicator.threat_type,
        indicator,
      };
    };

    // Process pending indicators or replay from pool
    // Returns true if processing live data, false if replaying
    const processPendingIndicators = (): boolean => {
      let indicator: ThreatIndicator | undefined;
      let isLive = false;
      
      // Priority 1: Always check for live data first (interrupts replay)
      if (stateRef.current.pendingIndicators.length > 0) {
        indicator = stateRef.current.pendingIndicators.shift();
        isLive = true;
        
        // Update status to LIVE when processing live data
        if (stateRef.current.connectionStatus !== "connected") {
          stateRef.current.connectionStatus = "connected";
          stateRef.current.setConnectionStatus?.("connected");
        }
      }
      // Priority 2: Replay from pool when no live data (and not in initial waiting mode)
      else if (!stateRef.current.isLiveMode && stateRef.current.allIndicators.length > 0) {
        const index = stateRef.current.currentReplayIndex;
        indicator = stateRef.current.allIndicators[index];
        stateRef.current.currentReplayIndex = (index + 1) % stateRef.current.allIndicators.length;
        
        // Update status to REPLAY when processing replay data
        if (stateRef.current.connectionStatus !== "replay") {
          stateRef.current.connectionStatus = "replay";
          stateRef.current.setConnectionStatus?.("replay");
        }
      }
      
      if (!indicator) return false;

      const signal = createSignal(indicator);
      if (signal) {
        stateRef.current.signals.push(signal);

        // Update stats — threat type + ORIGIN country only (no invented victim)
        const stats = stateRef.current.stats;
        stats.total++;
        stats.byType[signal.type] = (stats.byType[signal.type] || 0) + 1;
        stats.byOrigin[signal.originName] =
          (stats.byOrigin[signal.originName] || 0) + 1;

        // Notify callbacks
        if (stateRef.current.onSignal) {
          stateRef.current.onSignal({
            origin: { name: signal.originName, code: signal.originCode },
            threatType: signal.type,
            color: signal.color,
            timestamp: new Date(),
            indicator,
            isReplay: !isLive,
          });
        }
        if (stateRef.current.onStatsUpdate) {
          stateRef.current.onStatsUpdate({ ...stats });
        }
      }

      return isLive;
    };

    // Quadratic bezier point (origin → control → sensor) at parameter u∈[0,1].
    const qbez = (
      o: { x: number; y: number },
      c: { x: number; y: number },
      v: { x: number; y: number },
      u: number,
    ) => {
      const m = 1 - u;
      return {
        x: m * m * o.x + 2 * m * u * c.x + u * u * v.x,
        y: m * m * o.y + 2 * m * u * c.y + u * u * v.y,
      };
    };

    // Draw an animated arc from the IOC's REAL origin to JichoSec's fixed
    // monitoring sensor. The arc asserts "malicious infrastructure observed by
    // our African sensors" — the destination is OUR sensor, not an invented
    // victim. Origin ping at the source, a traveling head, arrival ping at the sensor.
    const drawSignal = (signal: Signal) => {
      const o = map.latLngToContainerPoint([signal.coord.lat, signal.coord.lon]);
      const v = map.latLngToContainerPoint([
        MONITORING_VANTAGE.lat,
        MONITORING_VANTAGE.lon,
      ]);
      const t = Math.min(signal.progress, 1);

      // Control point lifted perpendicular to the origin→sensor line for curvature.
      const dx = v.x - o.x;
      const dy = v.y - o.y;
      const dist = Math.hypot(dx, dy) || 1;
      const lift = Math.min(150, dist * 0.28);
      const ctrl = {
        x: (o.x + v.x) / 2 - (dy / dist) * lift,
        y: (o.y + v.y) / 2 + (dx / dist) * lift,
      };

      // Comet trail: draw the arc from a fading tail up to the traveling head.
      const head = t;
      const tail = Math.max(0, t - 0.55);
      const steps = 26;
      ctx.lineWidth = 1.6;
      for (let i = 0; i < steps; i++) {
        const p0 = qbez(o, ctrl, v, tail + (head - tail) * (i / steps));
        const p1 = qbez(o, ctrl, v, tail + (head - tail) * ((i + 1) / steps));
        const a = Math.round((i / steps) * 210)
          .toString(16)
          .padStart(2, "0");
        ctx.strokeStyle = signal.color + a;
        ctx.beginPath();
        ctx.moveTo(p0.x, p0.y);
        ctx.lineTo(p1.x, p1.y);
        ctx.stroke();
      }

      // Origin: brief expanding ring + core dot ("observed from here").
      if (t < 0.5) {
        const ot = t / 0.5;
        ctx.beginPath();
        ctx.arc(o.x, o.y, 4 + ot * 16, 0, Math.PI * 2);
        ctx.strokeStyle =
          signal.color + Math.round((1 - ot) * 180).toString(16).padStart(2, "0");
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(o.x, o.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = signal.color;
      ctx.fill();

      // Traveling head glow.
      const hp = qbez(o, ctrl, v, head);
      const g = ctx.createRadialGradient(hp.x, hp.y, 0, hp.x, hp.y, 7);
      g.addColorStop(0, signal.color + "ee");
      g.addColorStop(1, signal.color + "00");
      ctx.beginPath();
      ctx.fillStyle = g;
      ctx.arc(hp.x, hp.y, 7, 0, Math.PI * 2);
      ctx.fill();

      // Arrival ping at the sensor as the head lands (fades over progress 0.92→1.25).
      if (signal.progress >= 0.92) {
        const at = Math.min(1, (signal.progress - 0.92) / 0.33);
        ctx.beginPath();
        ctx.arc(v.x, v.y, 6 + at * 20, 0, Math.PI * 2);
        ctx.strokeStyle =
          "#22c55e" + Math.round((1 - at) * 200).toString(16).padStart(2, "0");
        ctx.lineWidth = 2;
        ctx.stroke();
      }
    };

    // Draw JichoSec's monitored African focus regions (highlight only — these
    // markers are NOT claimed to be under attack; they mark coverage).
    const drawMonitoredRegions = (phase: number) => {
      stateRef.current.selectedCountries.forEach((code) => {
        const coord = COUNTRY_COORDS[code];
        if (!coord) return;
        const pt = map.latLngToContainerPoint([coord.lat, coord.lon]);
        const size = 6 + Math.sin(phase) * 2;

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, size + 6, 0, Math.PI * 2);
        const ring = ctx.createRadialGradient(
          pt.x,
          pt.y,
          size,
          pt.x,
          pt.y,
          size + 6
        );
        ring.addColorStop(0, "#22c55e44");
        ring.addColorStop(1, "#22c55e00");
        ctx.fillStyle = ring;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, size, 0, Math.PI * 2);
        ctx.fillStyle = "#22c55e";
        ctx.fill();
      });
    };

    // Draw the fixed JichoSec sensor (arc destination) with a persistent label,
    // so the converging arcs read as "observed by our sensor", not "attack on Kenya".
    const drawVantage = (phase: number) => {
      const p = map.latLngToContainerPoint([
        MONITORING_VANTAGE.lat,
        MONITORING_VANTAGE.lon,
      ]);
      const pulse = 8 + Math.sin(phase) * 2;

      const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, pulse + 12);
      glow.addColorStop(0, "#22c55e88");
      glow.addColorStop(1, "#22c55e00");
      ctx.beginPath();
      ctx.fillStyle = glow;
      ctx.arc(p.x, p.y, pulse + 12, 0, Math.PI * 2);
      ctx.fill();

      ctx.beginPath();
      ctx.arc(p.x, p.y, 5, 0, Math.PI * 2);
      ctx.fillStyle = "#22c55e";
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = "#052e16";
      ctx.stroke();

      ctx.font = "600 11px ui-sans-serif, system-ui, -apple-system, sans-serif";
      ctx.textAlign = "left";
      ctx.fillStyle = "#0a0a0a"; // shadow for legibility over tiles
      ctx.fillText(MONITORING_VANTAGE.label, p.x + 11, p.y + 5);
      ctx.fillStyle = "#86efac";
      ctx.fillText(MONITORING_VANTAGE.label, p.x + 10, p.y + 4);
    };

    // Animation loop
    let lastProcessTime = 0;
    const animate = (currentTime: number) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const phase = (Date.now() / 400) % (Math.PI * 2);
      drawMonitoredRegions(phase);

      // Process indicators - faster for live data (100ms), slower for replay (300ms)
      const hasPendingLive = stateRef.current.pendingIndicators.length > 0;
      const processInterval = hasPendingLive ? 100 : 300;

      if (currentTime - lastProcessTime > processInterval) {
        processPendingIndicators();
        lastProcessTime = currentTime;
      }

      // Advance arcs; keep them briefly past arrival so the sensor ping breathes.
      const activeSignals: Signal[] = [];
      for (const signal of stateRef.current.signals) {
        signal.progress += 0.009;
        if (signal.progress < 1.25) {
          drawSignal(signal);
          activeSignals.push(signal);
        }
      }
      stateRef.current.signals = activeSignals;

      // Draw the sensor (arc destination) on top of the arcs.
      drawVantage(phase);

      stateRef.current.animationId = requestAnimationFrame(animate);
    };

    // Start animation
    stateRef.current.animationId = requestAnimationFrame(animate);

    // Load initial indicators and connect WebSocket
    fetchAllIndicators();
    connectWebSocket();

    // Cleanup
    return () => {
      // Block any in-flight or scheduled reconnect from resurrecting the socket
      stateRef.current.wsMounted = false;
      cancelAnimationFrame(stateRef.current.animationId);
      if (stateRef.current.wsReconnectTimeout) {
        clearTimeout(stateRef.current.wsReconnectTimeout);
        stateRef.current.wsReconnectTimeout = null;
      }
      if (stateRef.current.ws) {
        // Detach handlers first so close() can't schedule a zombie reconnect
        const sock = stateRef.current.ws;
        sock.onopen = null;
        sock.onmessage = null;
        sock.onerror = null;
        sock.onclose = null;
        try { sock.close(); } catch { /* ignore */ }
        stateRef.current.ws = null;
      }
      if (stateRef.current.liveTimeout) {
        clearTimeout(stateRef.current.liveTimeout);
      }
      window.removeEventListener("resize", resizeCanvas);
      map.remove();
    };
  }, [fetchAllIndicators, connectWebSocket]);

  return (
    <div className="absolute inset-0">
      <style jsx global>{`
        .leaflet-container {
          background: #0a0a0a !important;
        }
        .leaflet-control-zoom {
          border: none !important;
        }
        .leaflet-control-zoom a {
          background: rgba(31, 41, 55, 0.9) !important;
          color: #9ca3af !important;
          border: 1px solid #374151 !important;
        }
        .leaflet-control-zoom a:hover {
          background: rgba(55, 65, 81, 0.9) !important;
          color: #fff !important;
        }
      `}</style>
      <div ref={containerRef} className="absolute inset-0" style={{ zIndex: 1 }} />
      <canvas
        ref={canvasRef}
        className="absolute inset-0 pointer-events-none"
        style={{ zIndex: 1000 }}
      />

      {/* Loading overlay */}
      {isLoading && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-[1001] bg-gray-900/90 px-4 py-2 rounded-lg border border-gray-700">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-gray-300">
              Loading threat data...
            </span>
          </div>
        </div>
      )}

      {/* Error overlay */}
      {error && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-[1001] bg-red-900/90 px-4 py-2 rounded-lg border border-red-700">
          <span className="text-sm text-red-300">API Error: {error}</span>
        </div>
      )}

      {/* Connection status indicator */}
      {!isLoading && !error && (
        <div className={`absolute top-4 left-1/2 -translate-x-1/2 z-[1001] px-3 py-1.5 rounded-lg border ${
          connectionStatus === "connected" 
            ? "bg-green-900/80 border-green-700"
            : connectionStatus === "replay"
            ? "bg-amber-900/80 border-amber-700"
            : "bg-gray-900/80 border-gray-700"
        }`}>
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${
              connectionStatus === "connected"
                ? "bg-green-500 animate-pulse"
                : connectionStatus === "replay"
                ? "bg-amber-500 animate-pulse"
                : "bg-gray-500"
            }`} />
            <span className={`text-xs ${
              connectionStatus === "connected"
                ? "text-green-300"
                : connectionStatus === "replay"
                ? "text-amber-300"
                : "text-gray-400"
            }`}>
              {connectionStatus === "connected" && "LIVE - Waiting for threats..."}
              {connectionStatus === "replay" && `Replaying ${totalIndicators.toLocaleString()} IOCs from last 24 hours`}
              {connectionStatus === "connecting" && "CONNECTING..."}
              {connectionStatus === "disconnected" && "DISCONNECTED"}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
