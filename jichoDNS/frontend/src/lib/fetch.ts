/**
 * Authenticated fetch wrapper for portal pages.
 *
 * Automatically attaches the JWT Bearer token from localStorage.
 * All portal pages should use this instead of raw fetch().
 *
 * Timeouts:
 *   - GET/DELETE: 15 seconds
 *   - POST/PUT/PATCH: 60 seconds (report generation can take a while)
 */

import { getAccessToken, refreshAccessToken, clearTokens } from "./auth";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

/** Determine timeout based on HTTP method. */
function _timeout(method?: string): number {
  const m = (method || "GET").toUpperCase();
  return m === "GET" || m === "DELETE" || m === "HEAD" ? 15_000 : 60_000;
}

export async function apiFetch(
  path: string,
  options?: RequestInit,
): Promise<Response> {
  const token = getAccessToken();
  const headers = new Headers(options?.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const controller = new AbortController();
  const ms = _timeout(options?.method);
  const timeout = setTimeout(() => controller.abort(), ms);

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
      // Retry with a fresh timeout
      const retryController = new AbortController();
      const retryTimeout = setTimeout(() => retryController.abort(), ms);
      try {
        const retryRes = await fetch(`${API_BASE}${path}`, {
          ...options,
          headers,
          signal: retryController.signal,
        });
        clearTimeout(retryTimeout);
        return retryRes;
      } catch {
        clearTimeout(retryTimeout);
        // fall through to return original 401
      }
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
