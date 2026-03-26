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
        // SOCRadar-inspired color scheme
        primary: "#fe4562",
        "primary-hover": "#e63e57",
        "primary-light": "#ff6b84",
        
        // Dark backgrounds (SOCRadar uses dark purple-tinted blacks)
        "body-dark": "#0d0e1a",
        "card-dark": "#191A34",
        "card-light": "#2B2C44",
        "card-hover": "#252640",
        
        // Port Gore (SOCRadar's dark blue-purple)
        "port-gore": {
          50: "#f5f5ff",
          100: "#ebebff",
          200: "#d6d6ff",
          300: "#b3b3ff",
          400: "#8585ff",
          500: "#5c5cff",
          600: "#4040ff",
          700: "#2929e6",
          800: "#2121b3",
          900: "#1a1a80",
          950: "#191A34",
        },
        
        // Ebony (darker variant)
        ebony: {
          900: "#1a1b2e",
          950: "#0d0e1a",
        },
        
        background: "var(--background)",
        foreground: "var(--foreground)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "monospace"],
      },
      animation: {
        "float": "float 6s ease-in-out infinite",
        "pulse-slow": "pulse 3s ease-in-out infinite",
        "radar": "radar 3s linear infinite",
      },
      keyframes: {
        float: {
          "0%, 100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
        radar: {
          "0%": { transform: "scale(0.5)", opacity: "1" },
          "100%": { transform: "scale(2)", opacity: "0" },
        },
      },
      boxShadow: {
        "glow-primary": "0 0 40px -10px rgba(254, 69, 98, 0.5)",
        "glow-sm": "0 0 20px -5px rgba(254, 69, 98, 0.3)",
      },
    },
  },
  plugins: [],
};
export default config;
