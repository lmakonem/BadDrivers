import { CSSProperties } from "react";

/**
 * JichoMark — the JichoSec brand mark.
 * "Jicho" = eye (Swahili): an eye whose iris is a computer circuit board —
 * PCB traces + vias radiating from a gold pupil, a cyan DNS-resolution ring,
 * and a scanning sweep. The watchful eye over African cyberspace.
 *
 * Pure SVG, ~2KB, themes on any background, animates. Set animated={false}
 * for a static mark (favicons, print).
 */
export function JichoMark({
  size = 40,
  animated = true,
  className = "",
  style,
}: {
  size?: number;
  animated?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  const a = animated ? "" : " jm-static";
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      role="img"
      aria-label="JichoSec"
      className={`jicho-mark${a} ${className}`}
      style={{ overflow: "visible", ...style }}
    >
      <defs>
        <radialGradient id="jmPupil" cx="50%" cy="45%" r="60%">
          <stop offset="0%" stopColor="#ffd879" />
          <stop offset="55%" stopColor="#f5b62c" />
          <stop offset="100%" stopColor="#c98f10" />
        </radialGradient>
        <linearGradient id="jmSweep" x1="0" y1="0" x2="1" y2="0.4">
          <stop offset="0%" stopColor="#38e1d0" stopOpacity="0" />
          <stop offset="100%" stopColor="#38e1d0" stopOpacity="0.6" />
        </linearGradient>
      </defs>

      {/* eye lens */}
      <path
        d="M4 32 C 16 13, 48 13, 60 32 C 48 51, 16 51, 4 32 Z"
        stroke="#f5b62c"
        strokeWidth="2.6"
        strokeLinejoin="round"
      />

      {/* iris circuit rings (broken = PCB traces) */}
      <circle cx="32" cy="32" r="16" stroke="#38e1d0" strokeWidth="1.1" strokeDasharray="9 7" opacity="0.4" />
      <circle cx="32" cy="32" r="11" stroke="#38e1d0" strokeWidth="1.1" strokeDasharray="5 5" opacity="0.6" />

      {/* radial PCB traces + vias */}
      <g stroke="#38e1d0" strokeWidth="1.2" strokeLinecap="round" opacity="0.85">
        <path d="M32 26 L32 19 L35 16" /><path d="M37 30 L45 30 L48 26" />
        <path d="M35 37 L40 43 L40 46" /><path d="M29 37 L24 43 L24 46" />
        <path d="M27 30 L19 30 L16 26" /><path d="M32 26 L32 19 L29 16" />
      </g>
      <g fill="#f5b62c">
        <circle cx="35" cy="16" r="1.4" /><circle cx="48" cy="26" r="1.4" />
        <circle cx="40" cy="46" r="1.4" /><circle cx="24" cy="46" r="1.4" />
        <circle cx="16" cy="26" r="1.4" /><circle cx="29" cy="16" r="1.4" />
      </g>

      {/* scanning sweep */}
      <g className="jm-sweep">
        <path d="M32 32 L32 16 A 16 16 0 0 1 45.9 24 Z" fill="url(#jmSweep)" />
      </g>

      {/* pupil */}
      <circle className="jm-pulse" cx="32" cy="32" r="16" stroke="#f5b62c" strokeWidth="1" opacity="0.28" />
      <circle cx="32" cy="32" r="5.6" fill="url(#jmPupil)" />
      <circle cx="32" cy="32" r="2" fill="#080b14" />
    </svg>
  );
}

/**
 * JichoLogo — mark + wordmark lockup.
 * variant "full" = mark + "jichoSec"; "mark" = mark only.
 */
export function JichoLogo({
  size = 34,
  variant = "full",
  animated = true,
  className = "",
  wordClassName = "",
}: {
  size?: number;
  variant?: "full" | "mark";
  animated?: boolean;
  className?: string;
  wordClassName?: string;
}) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <JichoMark size={size} animated={animated} />
      {variant === "full" && (
        <span
          className={`font-display font-bold tracking-tight leading-none ${wordClassName}`}
          style={{ fontSize: size * 0.62 }}
        >
          jicho<span className="text-primary">Sec</span>
        </span>
      )}
    </span>
  );
}
