/**
 * Authenticated fetch wrapper for portal pages.
 *
 * Automatically attaches the JWT Bearer token from localStorage.
 * All portal pages should use this instead of raw fetch().
 */

import { getAccessToken, refreshAccessToken, clearTokens } from "./auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

export async function apiFetch(
  path: string,
  options?: RequestInit,
): Promise<Response> {
  const token = getAccessToken();
  const headers = new Headers(options?.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  // AbortController with 10s timeout prevents browser hangs
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeout);
    if (err instanceof DOMException && err.name === "AbortError") {
      return new Response(JSON.stringify({ error: "Request timeout" }), {
        status: 408,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw err;
  }
  clearTimeout(timeout);

  // Auto-refresh on 401
  if (res.status === 401 && token) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      headers.set("Authorization", `Bearer ${newToken}`);
      return fetch(`${API_BASE}${path}`, { ...options, headers });
    }
    clearTokens();
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  }

  return res;
}

/**
 * Fetch JSON with auth. Returns parsed JSON or null on error.
 */
export async function apiFetchJSON<T = unknown>(
  path: string,
  options?: RequestInit,
): Promise<T | null> {
  try {
    const res = await apiFetch(path, options);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}
