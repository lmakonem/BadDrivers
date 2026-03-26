import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(num: number): string {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + "M";
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + "K";
  }
  return num.toString();
}

export function getThreatColor(score: number): string {
  if (score >= 0.8) return "#ef4444"; // Critical - red
  if (score >= 0.6) return "#f97316"; // High - orange
  if (score >= 0.4) return "#eab308"; // Medium - yellow
  if (score >= 0.2) return "#22c55e"; // Low - green
  return "#6b7280"; // None - gray
}

export function getThreatLabel(score: number): string {
  if (score >= 0.8) return "Critical";
  if (score >= 0.6) return "High";
  if (score >= 0.4) return "Medium";
  if (score >= 0.2) return "Low";
  return "None";
}
