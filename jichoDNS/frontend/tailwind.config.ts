import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // ── opsecfusion brand: signal-green on near-black navy, cyan accent ──
        // `primary` is the single green accent — every existing bg-primary/
        // text-primary across the app re-themes to green automatically.
        primary: "#4ADE80",
        "primary-hover": "#36C46B",
        "primary-light": "#86EFAC",
        "primary-deep": "#22C55E",

        // cyan — SPARING: gradients / diagrams only, never the main accent
        secondary: "#38BDF8",
        "secondary-hover": "#0EA5E9",
        cyan: "#38BDF8",

        // near-black navy ink surfaces (token names kept; values re-tuned)
        "body-dark": "#0A0E17",
        "card-dark": "#111927",
        "card-light": "#0D131F",
        "card-hover": "#152032",

        // legacy token names remapped to the navy palette so old usages retheme
        "port-gore": {
          50: "#eef4ff", 100: "#dbe6ff", 200: "#b9ccff", 300: "#8aa8f5",
          400: "#5c7fe0", 500: "#3d5bc0", 600: "#2c4396", 700: "#1E2A3D",
          800: "#111927", 900: "#0D131F", 950: "#0A0E17",
        },
        ebony: { 900: "#0D131F", 950: "#0A0E17" },

        background: "var(--background)",
        foreground: "var(--foreground)",
      },
      fontFamily: {
        display: ["var(--font-display)", "var(--font-inter)", "system-ui", "sans-serif"],
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      animation: {
        float: "float 6s ease-in-out infinite",
        "pulse-slow": "pulse 3s ease-in-out infinite",
        radar: "radar 3s linear infinite",
        sweep: "jicho-sweep 4.2s cubic-bezier(0.5,0.15,0.35,1) infinite",
        "circuit-flow": "circuit-flow 3s linear infinite",
        "fade-up": "fade-up 0.6s ease-out both",
      },
      keyframes: {
        float: { "0%, 100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-10px)" } },
        radar: { "0%": { transform: "scale(0.5)", opacity: "1" }, "100%": { transform: "scale(2)", opacity: "0" } },
        "jicho-sweep": { to: { transform: "rotate(360deg)" } },
        "circuit-flow": { to: { "stroke-dashoffset": "-24" } },
        "fade-up": { from: { opacity: "0", transform: "translateY(14px)" }, to: { opacity: "1", transform: "translateY(0)" } },
      },
      boxShadow: {
        "glow-primary": "0 0 40px -10px rgba(74, 222, 128, 0.5)",
        "glow-sm": "0 0 20px -5px rgba(74, 222, 128, 0.32)",
        "glow-cyan": "0 0 30px -8px rgba(56, 189, 248, 0.4)",
      },
      backgroundImage: {
        "circuit-grid":
          "linear-gradient(rgba(74,222,128,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(74,222,128,0.05) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};
export default config;
