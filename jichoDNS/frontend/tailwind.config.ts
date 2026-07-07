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
        // ── JichoSec brand: signal-gold on navy ink, network-cyan accent ──
        // `primary` is the gold beacon — every existing bg-primary/text-primary
        // across the app re-themes to gold automatically.
        primary: "#f5b62c",
        "primary-hover": "#e0a41f",
        "primary-light": "#ffcf5e",
        "primary-deep": "#c98f10",

        // network cyan — data / DNS / links
        secondary: "#38e1d0",
        "secondary-hover": "#22c9b9",
        cyan: "#38e1d0",

        // navy ink surfaces (token names kept; values re-tuned)
        "body-dark": "#080b14",
        "card-dark": "#111827",
        "card-light": "#161f33",
        "card-hover": "#18213a",

        // legacy token names remapped to the navy palette so old usages retheme
        "port-gore": {
          50: "#eef4ff", 100: "#dbe6ff", 200: "#b9ccff", 300: "#8aa8f5",
          400: "#5c7fe0", 500: "#3d5bc0", 600: "#2c4396", 700: "#233570",
          800: "#161f33", 900: "#0c1120", 950: "#080b14",
        },
        ebony: { 900: "#0c1120", 950: "#080b14" },

        background: "var(--background)",
        foreground: "var(--foreground)",
      },
      fontFamily: {
        display: ["var(--font-sora)", "var(--font-inter)", "system-ui", "sans-serif"],
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
        "glow-primary": "0 0 40px -10px rgba(245, 182, 44, 0.5)",
        "glow-sm": "0 0 20px -5px rgba(245, 182, 44, 0.32)",
        "glow-cyan": "0 0 30px -8px rgba(56, 225, 208, 0.4)",
      },
      backgroundImage: {
        "circuit-grid":
          "linear-gradient(rgba(56,225,208,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(56,225,208,0.05) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};
export default config;
