import { getAccessToken, refreshAccessToken, clearTokens } from "./auth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";

export interface Indicator {
  id: string;
  indicator: string;
  indicator_type: string;
  threat_type: string;
  confidence: number;
  risk_score: number;
  source: string;
  first_seen: string;
  last_seen: string;
  country_code?: string;
  asn?: number;
  tags: string[];
}

export interface IndicatorListResponse {
  items: Indicator[];
  total: number;
  page: number;
  page_size: number;
}

export interface RegionScore {
  region_type: string;
  region_id: string;
  region_name: string;
  c2_risk: number;
  exfil_risk: number;
  phishing_risk: number;
  overall_risk: number;
  indicator_count: number;
  latitude?: number;
  longitude?: number;
  timestamp: string;
}

export interface RegionListResponse {
  items: RegionScore[];
  timestamp: string;
}

export interface DomainAnalysis {
  domain: string;
  entropy: number;
  length: number;
  label_count: number;
  digit_ratio: number;
  consonant_ratio: number;
  vowel_ratio: number;
  has_digits: boolean;
  tld: string;
  is_dga_like: boolean;
  dga_score: number;
  impossible_ngrams: string[];
  classification: string;
  confidence: number;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  service: string;
}

export interface IndicatorStats {
  total: number;
  by_threat_type: Record<string, number>;
  by_indicator_type: Record<string, number>;
  by_source: Record<string, number>;
  by_country: Record<string, number>;
}

/**
 * Authenticated fetch wrapper.
 *
 * - Attaches the JWT access token from localStorage.
 * - On 401, attempts a single token refresh and retries.
 * - On second 401, clears tokens and redirects to /login.
 */
async function fetchAPI<T>(
  endpoint: string,
  options?: RequestInit,
  _retried = false,
): Promise<T> {
  const token = getAccessToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && !_retried) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      return fetchAPI<T>(endpoint, options, true);
    }
    // Refresh failed — force login
    clearTokens();
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
    throw new Error("Session expired. Please log in again.");
  }

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `API Error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

export { API_BASE_URL };

export const api = {
  // Health (public)
  getHealth: () => fetchAPI<HealthResponse>("/health"),

  // Indicators
  getIndicators: (params?: {
    page?: number;
    page_size?: number;
    threat_type?: string;
    indicator_type?: string;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.set("page", params.page.toString());
    if (params?.page_size) searchParams.set("page_size", params.page_size.toString());
    if (params?.threat_type) searchParams.set("threat_type", params.threat_type);
    if (params?.indicator_type) searchParams.set("indicator_type", params.indicator_type);

    const query = searchParams.toString();
    return fetchAPI<IndicatorListResponse>(`/api/v1/indicators${query ? `?${query}` : ""}`);
  },

  getStats: () => fetchAPI<IndicatorStats>("/api/v1/indicators/stats"),

  // Regions
  getCountryScores: (minRisk = 0) =>
    fetchAPI<RegionListResponse>(`/api/v1/regions/countries?min_risk=${minRisk}`),

  getAsnScores: (country?: string, minRisk = 0) => {
    const params = new URLSearchParams({ min_risk: minRisk.toString() });
    if (country) params.set("country", country);
    return fetchAPI<RegionListResponse>(`/api/v1/regions/asns?${params}`);
  },

  getMapData: () =>
    fetchAPI<GeoJSON.FeatureCollection>("/api/v1/regions/map"),

  // Analysis
  analyzeDomain: (domain: string) =>
    fetchAPI<DomainAnalysis>("/api/v1/analysis/domain", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
};
