import { SVGProps } from "react";

/**
 * Distinct, single-source-of-truth icons for the six platform modules.
 * Monoline, currentColor, 32-grid — so they inherit the gold/cyan tone
 * of whatever tile they sit in. Each has its own silhouette (no two alike).
 */
type IconProps = SVGProps<SVGSVGElement> & { className?: string };
const svg = (className = "w-7 h-7") => ({
  viewBox: "0 0 32 32",
  fill: "none" as const,
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  className,
});

/** Threat Intelligence — a target lock with a detected blip. */
export function ThreatIntelIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <circle cx="16" cy="16" r="11" />
      <circle cx="16" cy="16" r="5.5" />
      <path d="M16 2v5M16 25v5M2 16h5M25 16h5" />
      <circle cx="16" cy="16" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="22.4" cy="9.6" r="2.1" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** Dark Web Monitoring — an iceberg through the waterline (surface vs deep). */
export function DarkWebIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <path d="M16 5 L21 13 L23.5 23 L8.5 23 L11 13 Z" />
      <path d="M3 13 H29" strokeDasharray="3 3" opacity="0.7" />
      <path d="M16 5 L16 13M11 13 H21" opacity="0.55" />
    </svg>
  );
}

/** Brand Protection — a shield with a verification check. */
export function BrandIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <path d="M16 4 L26 8 V15 C26 21 21.2 25.6 16 28 C10.8 25.6 6 21 6 15 V8 Z" />
      <path d="M11.5 16 L14.5 19 L20.5 12" />
    </svg>
  );
}

/** Attack Surface — a connected asset graph with one exposed node. */
export function AttackSurfaceIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <path d="M16 16 L8 8M16 16 L24 9M16 16 L23 24M16 16 L9 23" opacity="0.7" />
      <circle cx="16" cy="16" r="2.8" />
      <circle cx="8" cy="8" r="2.2" />
      <circle cx="9" cy="23" r="2.2" />
      <circle cx="23" cy="24" r="2.2" />
      <circle cx="24" cy="9" r="2.6" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** Threat Reports — a document with a mini bar chart. */
export function ReportsIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <rect x="6.5" y="4" width="19" height="24" rx="2.5" />
      <path d="M10.5 10 H21.5M10.5 14 H18" opacity="0.75" />
      <path d="M11 24 V20M16 24 V16.5M21 24 V18.5" />
    </svg>
  );
}

/** API & Integrations — code brackets with a slash. */
export function ApiIcon({ className, ...p }: IconProps) {
  return (
    <svg {...svg(className)} {...p}>
      <path d="M11 9 L5 16 L11 23" />
      <path d="M21 9 L27 16 L21 23" />
      <path d="M18.5 7.5 L13.5 24.5" opacity="0.85" />
    </svg>
  );
}

/** id → icon, so every surface (hero, features, header) stays in sync. */
export const MODULE_ICONS: Record<string, (p: IconProps) => JSX.Element> = {
  "threat-intelligence": ThreatIntelIcon,
  "dark-web": DarkWebIcon,
  "brand-protection": BrandIcon,
  "attack-surface": AttackSurfaceIcon,
  "threat-reports": ReportsIcon,
  "ai-reports": ReportsIcon,
  "api-access": ApiIcon,
};
