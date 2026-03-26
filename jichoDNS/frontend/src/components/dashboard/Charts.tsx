"use client";

// Unused imports removed to fix linting

// =============================================================================
// Chart Types
// =============================================================================

interface DataPoint {
  label: string;
  value: number;
  color?: string;
}

interface TimeSeriesPoint {
  date: string;
  value: number;
}

interface ChartProps {
  data: DataPoint[];
  height?: number;
  showLabels?: boolean;
  showLegend?: boolean;
  animate?: boolean;
}

interface TimeSeriesProps {
  data: TimeSeriesPoint[];
  height?: number;
  color?: string;
  fillColor?: string;
  showGrid?: boolean;
}

interface GaugeProps {
  value: number;
  max?: number;
  label?: string;
  size?: number;
  thickness?: number;
  colors?: { low: string; medium: string; high: string; critical: string };
}

// =============================================================================
// Default Colors
// =============================================================================

const DEFAULT_COLORS = [
  "#fe4562", // Primary red
  "#f97316", // Orange
  "#eab308", // Yellow
  "#22c55e", // Green
  "#3b82f6", // Blue
  "#8b5cf6", // Purple
  "#ec4899", // Pink
  "#14b8a6", // Teal
];

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

// =============================================================================
// Donut Chart Component
// =============================================================================

export function DonutChart({
  data,
  height = 200,
  showLabels = true,
  showLegend = true,
}: ChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const size = height;
  const strokeWidth = 30;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  let currentOffset = 0;

  return (
    <div className="flex items-center gap-6">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          {data.map((item, index) => {
            const percentage = item.value / total;
            const strokeDasharray = `${percentage * circumference} ${circumference}`;
            const strokeDashoffset = -currentOffset;
            currentOffset += percentage * circumference;

            return (
              <circle
                key={item.label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length]}
                strokeWidth={strokeWidth}
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                className="transition-all duration-500"
              />
            );
          })}
        </svg>
        {showLabels && (
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-bold text-white">{total.toLocaleString()}</span>
            <span className="text-sm text-gray-400">Total</span>
          </div>
        )}
      </div>

      {showLegend && (
        <div className="space-y-2">
          {data.map((item, index) => (
            <div key={item.label} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length] }}
              />
              <span className="text-sm text-gray-400">{item.label}</span>
              <span className="text-sm font-medium text-white ml-auto">
                {item.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// =============================================================================
// Bar Chart Component
// =============================================================================

export function BarChart({
  data,
  height = 200,
  showLabels = true,
}: ChartProps) {
  const maxValue = Math.max(...data.map((d) => d.value));

  return (
    <div className="space-y-3" style={{ height }}>
      {data.map((item, index) => {
        const percentage = (item.value / maxValue) * 100;
        return (
          <div key={item.label}>
            <div className="flex items-center justify-between text-sm mb-1">
              <span className="text-gray-400">{item.label}</span>
              {showLabels && (
                <span className="text-white font-medium">{item.value.toLocaleString()}</span>
              )}
            </div>
            <div className="h-2 bg-white/10 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${percentage}%`,
                  backgroundColor: item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length],
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// =============================================================================
// Horizontal Bar Chart Component
// =============================================================================

export function HorizontalBarChart({
  data,
  height = 300,
  showLabels = true,
}: ChartProps) {
  const maxValue = Math.max(...data.map((d) => d.value));
  // barHeight calculation available for future use
  const _barHeight = Math.min(40, (height - 20) / data.length);
  void _barHeight; // Explicitly mark as intentionally unused

  return (
    <div className="space-y-2" style={{ minHeight: height }}>
      {data.slice(0, 10).map((item, index) => {
        const percentage = (item.value / maxValue) * 100;
        return (
          <div key={item.label} className="flex items-center gap-3">
            <div className="w-20 text-xs text-gray-400 truncate" title={item.label}>
              {item.label}
            </div>
            <div className="flex-1 h-6 bg-white/5 rounded overflow-hidden">
              <div
                className="h-full rounded flex items-center justify-end px-2 transition-all duration-500"
                style={{
                  width: `${percentage}%`,
                  backgroundColor: item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length],
                }}
              >
                {showLabels && percentage > 15 && (
                  <span className="text-xs text-white font-medium">
                    {item.value.toLocaleString()}
                  </span>
                )}
              </div>
            </div>
            {showLabels && percentage <= 15 && (
              <span className="text-xs text-gray-400 w-12 text-right">
                {item.value.toLocaleString()}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// =============================================================================
// Line/Area Chart Component
// =============================================================================

export function AreaChart({
  data,
  height = 200,
  color = "#fe4562",
  fillColor,
  showGrid = true,
}: TimeSeriesProps) {
  if (data.length === 0) return null;

  const maxValue = Math.max(...data.map((d) => d.value));
  const minValue = Math.min(...data.map((d) => d.value));
  const range = maxValue - minValue || 1;
  
  const width = 400;
  const padding = 40;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding;

  const points = data.map((d, i) => ({
    x: padding + (i / (data.length - 1)) * chartWidth,
    y: chartHeight - ((d.value - minValue) / range) * (chartHeight - 20) + 10,
  }));

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const areaPath = `${linePath} L ${points[points.length - 1].x} ${chartHeight} L ${points[0].x} ${chartHeight} Z`;

  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet">
      {/* Grid lines */}
      {showGrid && (
        <g className="text-gray-700">
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => (
            <line
              key={ratio}
              x1={padding}
              y1={10 + (chartHeight - 20) * (1 - ratio)}
              x2={width - padding}
              y2={10 + (chartHeight - 20) * (1 - ratio)}
              stroke="currentColor"
              strokeOpacity={0.2}
              strokeDasharray="4,4"
            />
          ))}
        </g>
      )}

      {/* Area fill */}
      <path
        d={areaPath}
        fill={fillColor || `${color}20`}
        className="transition-all duration-500"
      />

      {/* Line */}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={2}
        className="transition-all duration-500"
      />

      {/* Data points */}
      {points.map((p, i) => (
        <circle
          key={i}
          cx={p.x}
          cy={p.y}
          r={3}
          fill={color}
          className="opacity-0 hover:opacity-100 transition-opacity"
        />
      ))}

      {/* X-axis labels */}
      {data.length <= 7 && data.map((d, i) => (
        <text
          key={i}
          x={points[i].x}
          y={height - 5}
          textAnchor="middle"
          className="fill-gray-500 text-xs"
        >
          {d.date}
        </text>
      ))}
    </svg>
  );
}

// =============================================================================
// Gauge Chart Component
// =============================================================================

export function GaugeChart({
  value,
  max = 100,
  label: _label = "Risk Score",
  size = 160,
  thickness = 12,
  colors = { low: "#22c55e", medium: "#eab308", high: "#f97316", critical: "#ef4444" },
}: GaugeProps) {
  void _label; // Label prop available for customization
  const radius = (size - thickness) / 2;
  const circumference = Math.PI * radius; // Half circle
  const percentage = Math.min(value / max, 1);
  const strokeDashoffset = circumference * (1 - percentage);

  const getColor = () => {
    if (percentage <= 0.25) return colors.low;
    if (percentage <= 0.5) return colors.medium;
    if (percentage <= 0.75) return colors.high;
    return colors.critical;
  };

  const getLabel = () => {
    if (percentage <= 0.25) return "Low";
    if (percentage <= 0.5) return "Medium";
    if (percentage <= 0.75) return "High";
    return "Critical";
  };

  return (
    <div className="relative" style={{ width: size, height: size / 2 + 30 }}>
      <svg width={size} height={size / 2 + 10} className="overflow-visible">
        {/* Background arc */}
        <path
          d={`M ${thickness / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - thickness / 2} ${size / 2}`}
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth={thickness}
          strokeLinecap="round"
        />
        {/* Value arc */}
        <path
          d={`M ${thickness / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - thickness / 2} ${size / 2}`}
          fill="none"
          stroke={getColor()}
          strokeWidth={thickness}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-x-0 bottom-0 text-center">
        <span className="text-3xl font-bold text-white">{value}</span>
        <span className="text-sm text-gray-400">/{max}</span>
        <p className="text-sm font-medium" style={{ color: getColor() }}>
          {getLabel()} Risk
        </p>
      </div>
    </div>
  );
}

// =============================================================================
// Severity Badge Component
// =============================================================================

export function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS] || SEVERITY_COLORS.info;
  
  return (
    <span
      className="px-2 py-0.5 rounded-full text-xs font-medium border"
      style={{
        backgroundColor: `${color}20`,
        borderColor: `${color}50`,
        color: color,
      }}
    >
      {severity.toUpperCase()}
    </span>
  );
}

// =============================================================================
// Stats Card Component
// =============================================================================

interface StatsCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  icon?: React.ReactNode;
  color?: string;
}

export function StatsCard({
  title,
  value,
  change,
  changeLabel = "vs last week",
  icon,
  color = "#3b82f6",
}: StatsCardProps) {
  const isPositive = change && change > 0;
  const isNegative = change && change < 0;

  return (
    <div className="bg-card-dark border border-white/10 rounded-2xl p-6 hover:border-white/20 transition-colors">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-2">
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
        </div>
        {icon && (
          <div
            className="p-3 rounded-xl"
            style={{ backgroundColor: `${color}15` }}
          >
            <div style={{ color }}>{icon}</div>
          </div>
        )}
      </div>
      {change !== undefined && (
        <div className="flex items-center gap-2 mt-4">
          <span
            className={`flex items-center text-sm ${
              isPositive ? "text-green-400" : isNegative ? "text-red-400" : "text-gray-400"
            }`}
          >
            {isPositive ? (
              <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
              </svg>
            ) : isNegative ? (
              <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 17h8m0 0V9m0 8l-8-8-4 4-6-6" />
              </svg>
            ) : null}
            {Math.abs(change)}%
          </span>
          <span className="text-gray-500 text-sm">{changeLabel}</span>
        </div>
      )}
    </div>
  );
}

// =============================================================================
// Data Table Component
// =============================================================================

interface Column {
  key: string;
  label: string;
  render?: (value: unknown, row: Record<string, unknown>) => React.ReactNode;
}

interface DataTableProps {
  columns: Column[];
  data: Record<string, unknown>[];
  onRowClick?: (row: Record<string, unknown>) => void;
  maxRows?: number;
}

export function DataTable({ columns, data, onRowClick, maxRows = 10 }: DataTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-white/10">
            {columns.map((col) => (
              <th
                key={col.key}
                className="text-left text-xs font-medium text-gray-400 uppercase tracking-wider py-3 px-4"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {data.slice(0, maxRows).map((row, i) => (
            <tr
              key={i}
              className={`hover:bg-white/5 transition-colors ${onRowClick ? "cursor-pointer" : ""}`}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((col) => (
                <td key={col.key} className="py-3 px-4 text-sm text-gray-300">
                  {col.render ? col.render(row[col.key], row) : String(row[col.key] ?? "-")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {data.length === 0 && (
        <div className="text-center py-8 text-gray-500">No data available</div>
      )}
    </div>
  );
}

// =============================================================================
// World Map Component (Simple SVG)
// =============================================================================

interface CountryData {
  code: string;
  value: number;
}

export function WorldMapMini({ data }: { data: CountryData[] }) {
  // Simplified Africa-focused map visualization
  const africanCountries = [
    { code: "ZA", x: 55, y: 85, name: "South Africa" },
    { code: "KE", x: 65, y: 55, name: "Kenya" },
    { code: "NG", x: 35, y: 50, name: "Nigeria" },
    { code: "EG", x: 55, y: 25, name: "Egypt" },
    { code: "ET", x: 65, y: 45, name: "Ethiopia" },
    { code: "GH", x: 30, y: 50, name: "Ghana" },
    { code: "TZ", x: 65, y: 60, name: "Tanzania" },
    { code: "UG", x: 60, y: 52, name: "Uganda" },
    { code: "MA", x: 25, y: 20, name: "Morocco" },
    { code: "DZ", x: 35, y: 22, name: "Algeria" },
  ];

  const maxValue = Math.max(...data.map((d) => d.value), 1);

  const getCountryData = (code: string) => data.find((d) => d.code === code);

  return (
    <div className="relative w-full h-48 bg-gradient-to-br from-card-dark to-card-light rounded-lg overflow-hidden">
      <svg viewBox="0 0 100 100" className="w-full h-full">
        {/* Africa outline (simplified) */}
        <path
          d="M25,15 Q35,10 50,15 Q70,20 75,40 Q80,60 70,80 Q55,95 40,90 Q25,85 20,70 Q15,50 20,30 Q22,20 25,15"
          fill="rgba(255,255,255,0.05)"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="0.5"
        />

        {/* Country dots */}
        {africanCountries.map((country) => {
          const countryData = getCountryData(country.code);
          const value = countryData?.value || 0;
          const intensity = value / maxValue;
          const radius = 2 + intensity * 4;

          return (
            <g key={country.code}>
              {/* Glow effect */}
              {value > 0 && (
                <circle
                  cx={country.x}
                  cy={country.y}
                  r={radius * 2}
                  fill={`rgba(254, 69, 98, ${intensity * 0.3})`}
                  className="animate-pulse"
                />
              )}
              {/* Main dot */}
              <circle
                cx={country.x}
                cy={country.y}
                r={radius}
                fill={value > 0 ? `rgba(254, 69, 98, ${0.5 + intensity * 0.5})` : "rgba(255,255,255,0.2)"}
                className="transition-all duration-300"
              />
              {/* Label on hover would go here */}
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-2 left-2 text-xs text-gray-400">
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-primary/50" />
          <span>Threat Activity</span>
        </div>
      </div>
    </div>
  );
}
