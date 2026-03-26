"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { COUNTRY_COORDS, AFRICAN_TARGETS, ATTACKER_CODES } from "./countries";

// Re-export for use in other components
export { AFRICAN_COUNTRY_LIST } from "./countries";

const THREAT_TYPES = [
  { type: "malware", color: "#ef4444" },
  { type: "c2", color: "#f97316" },
  { type: "phishing", color: "#a855f7" },
  { type: "ddos", color: "#3b82f6" },
  { type: "bruteforce", color: "#eab308" },
];

interface Attack {
  id: number;
  sourceCoord: { lat: number; lon: number };
  targetCoord: { lat: number; lon: number };
  sourceName: string;
  targetName: string;
  color: string;
  progress: number;
  type: string;
}

interface LiveThreatMapProps {
  onAttack?: (attack: { source: { name: string }; target: { name: string }; threatType: string; color: string; timestamp: Date }) => void;
  onStatsUpdate?: (stats: { total: number; byType: Record<string, number>; bySource: Record<string, number>; byTarget: Record<string, number> }) => void;
  selectedCountries?: string[]; // Filter by country codes (e.g., ["KE", "NG"]). Empty or undefined = all countries
}

export default function LiveThreatMap({ onAttack, onStatsUpdate, selectedCountries }: LiveThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef({
    map: null as L.Map | null,
    attacks: [] as Attack[],
    attackId: 0,
    stats: { total: 0, byType: {} as Record<string, number>, bySource: {} as Record<string, number>, byTarget: {} as Record<string, number> },
    animationId: 0,
    intervalId: null as ReturnType<typeof setInterval> | null,
    onAttack,
    onStatsUpdate,
    selectedCountries: selectedCountries && selectedCountries.length > 0 ? selectedCountries : AFRICAN_TARGETS,
  });

  // Keep callbacks and selected countries fresh
  useEffect(() => {
    stateRef.current.onAttack = onAttack;
    stateRef.current.onStatsUpdate = onStatsUpdate;
    stateRef.current.selectedCountries = selectedCountries && selectedCountries.length > 0 ? selectedCountries : AFRICAN_TARGETS;
  }, [onAttack, onStatsUpdate, selectedCountries]);

  useEffect(() => {
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

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      subdomains: "abcd",
      maxZoom: 19,
    }).addTo(map);

    L.control.zoom({ position: "bottomright" }).addTo(map);

    // Resize canvas
    const resizeCanvas = () => {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight;
    };
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);
    map.on("move zoom", resizeCanvas);

    // Create new attack
    const createAttack = (): Attack => {
      const attackerCode = ATTACKER_CODES[Math.floor(Math.random() * ATTACKER_CODES.length)];
      // Use filtered countries from stateRef
      const targets = stateRef.current.selectedCountries;
      const targetCode = targets[Math.floor(Math.random() * targets.length)];
      const threat = THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)];
      const source = COUNTRY_COORDS[attackerCode];
      const target = COUNTRY_COORDS[targetCode];

      stateRef.current.attackId++;
      
      return {
        id: stateRef.current.attackId,
        sourceCoord: { lat: source.lat, lon: source.lon },
        targetCoord: { lat: target.lat, lon: target.lon },
        sourceName: source.name,
        targetName: target.name,
        color: threat.color,
        progress: 0,
        type: threat.type,
      };
    };

    // Add attack and notify
    const addAttack = () => {
      const attack = createAttack();
      stateRef.current.attacks.push(attack);
      
      // Update stats
      const stats = stateRef.current.stats;
      stats.total++;
      stats.byType[attack.type] = (stats.byType[attack.type] || 0) + 1;
      stats.bySource[attack.sourceName] = (stats.bySource[attack.sourceName] || 0) + 1;
      stats.byTarget[attack.targetName] = (stats.byTarget[attack.targetName] || 0) + 1;

      // Callbacks
      if (stateRef.current.onAttack) {
        stateRef.current.onAttack({
          source: { name: attack.sourceName },
          target: { name: attack.targetName },
          threatType: attack.type,
          color: attack.color,
          timestamp: new Date(),
        });
      }
      if (stateRef.current.onStatsUpdate) {
        stateRef.current.onStatsUpdate({ ...stats });
      }
    };

    // Draw attack arc
    const drawAttack = (attack: Attack) => {
      const srcPt = map.latLngToContainerPoint([attack.sourceCoord.lat, attack.sourceCoord.lon]);
      const tgtPt = map.latLngToContainerPoint([attack.targetCoord.lat, attack.targetCoord.lon]);

      const midX = (srcPt.x + tgtPt.x) / 2;
      const midY = (srcPt.y + tgtPt.y) / 2;
      const dist = Math.sqrt(Math.pow(tgtPt.x - srcPt.x, 2) + Math.pow(tgtPt.y - srcPt.y, 2));
      const arcHeight = Math.min(dist * 0.3, 120);
      const ctrlPt = { x: midX, y: midY - arcHeight };

      const t = Math.min(attack.progress, 1);
      const curX = (1 - t) * (1 - t) * srcPt.x + 2 * (1 - t) * t * ctrlPt.x + t * t * tgtPt.x;
      const curY = (1 - t) * (1 - t) * srcPt.y + 2 * (1 - t) * t * ctrlPt.y + t * t * tgtPt.y;

      // Trail
      ctx.beginPath();
      ctx.moveTo(srcPt.x, srcPt.y);
      ctx.quadraticCurveTo(ctrlPt.x, ctrlPt.y, curX, curY);
      const grad = ctx.createLinearGradient(srcPt.x, srcPt.y, curX, curY);
      grad.addColorStop(0, attack.color + "00");
      grad.addColorStop(0.6, attack.color + "88");
      grad.addColorStop(1, attack.color);
      ctx.strokeStyle = grad;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Projectile
      ctx.beginPath();
      ctx.arc(curX, curY, 5, 0, Math.PI * 2);
      ctx.fillStyle = attack.color;
      ctx.fill();

      // Glow
      ctx.beginPath();
      ctx.arc(curX, curY, 10, 0, Math.PI * 2);
      const glow = ctx.createRadialGradient(curX, curY, 0, curX, curY, 10);
      glow.addColorStop(0, attack.color + "aa");
      glow.addColorStop(1, attack.color + "00");
      ctx.fillStyle = glow;
      ctx.fill();

      // Impact
      if (attack.progress > 0.9 && attack.progress < 1.2) {
        const impactProgress = (attack.progress - 0.9) / 0.3;
        const impactSize = impactProgress * 35;
        ctx.beginPath();
        ctx.arc(tgtPt.x, tgtPt.y, impactSize, 0, Math.PI * 2);
        const impactGrad = ctx.createRadialGradient(tgtPt.x, tgtPt.y, 0, tgtPt.x, tgtPt.y, impactSize);
        impactGrad.addColorStop(0, attack.color + "88");
        impactGrad.addColorStop(1, attack.color + "00");
        ctx.fillStyle = impactGrad;
        ctx.fill();
      }
    };

    // Draw target markers (only for selected countries)
    const drawTargets = (phase: number) => {
      stateRef.current.selectedCountries.forEach((code) => {
        const coord = COUNTRY_COORDS[code];
        if (!coord) return;
        const pt = map.latLngToContainerPoint([coord.lat, coord.lon]);
        const size = 6 + Math.sin(phase) * 2;

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, size + 6, 0, Math.PI * 2);
        const ring = ctx.createRadialGradient(pt.x, pt.y, size, pt.x, pt.y, size + 6);
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

    // Animation loop
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      const phase = (Date.now() / 400) % (Math.PI * 2);
      drawTargets(phase);

      // Update attacks
      const activeAttacks: Attack[] = [];
      for (const attack of stateRef.current.attacks) {
        attack.progress += 0.008;
        if (attack.progress < 1.3) {
          drawAttack(attack);
          activeAttacks.push(attack);
        }
      }
      stateRef.current.attacks = activeAttacks;

      stateRef.current.animationId = requestAnimationFrame(animate);
    };

    // Start animation
    stateRef.current.animationId = requestAnimationFrame(animate);

    // Initial attacks
    for (let i = 0; i < 6; i++) {
      setTimeout(addAttack, i * 150);
    }

    // Continuous attack generation using setInterval (more reliable)
    stateRef.current.intervalId = setInterval(() => {
      addAttack();
      // Random burst
      if (Math.random() < 0.3) {
        setTimeout(addAttack, 80);
      }
      if (Math.random() < 0.15) {
        setTimeout(addAttack, 160);
      }
    }, 500);

    // Cleanup
    return () => {
      cancelAnimationFrame(stateRef.current.animationId);
      if (stateRef.current.intervalId) {
        clearInterval(stateRef.current.intervalId);
      }
      window.removeEventListener("resize", resizeCanvas);
      map.remove();
    };
  }, []);

  return (
    <div className="absolute inset-0">
      <style jsx global>{`
        .leaflet-container { background: #0a0a0a !important; }
        .leaflet-control-zoom { border: none !important; }
        .leaflet-control-zoom a { background: rgba(31,41,55,0.9) !important; color: #9ca3af !important; border: 1px solid #374151 !important; }
        .leaflet-control-zoom a:hover { background: rgba(55,65,81,0.9) !important; color: #fff !important; }
      `}</style>
      <div ref={containerRef} className="absolute inset-0" style={{ zIndex: 1 }} />
      <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none" style={{ zIndex: 1000 }} />
    </div>
  );
}
