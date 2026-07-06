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
 * Thrown by apiFetchJSONOrThrow on any non-2xx response, network failure,
 * or JSON parse failure. Lets call sites distinguish "empty result" from
 * "request failed" and render real error states.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(message: string, status: number, body: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/**
 * Fetch JSON with auth. Resolves with parsed JSON of type T, or THROWS an
 * ApiError on non-ok / network / parse failure. Prefer this in new code so
 * pages can show real error states.
 */
export async function apiFetchJSONOrThrow<T = unknown>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  let res: Response;
  try {
    res = await apiFetch(path, options);
  } catch (err) {
    throw new ApiError(
      err instanceof Error ? err.message : "Network request failed",
      0,
    );
  }
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error body */
    }
    const detail =
      (body && typeof body === "object" && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : null) || `Request failed (${res.status})`;
    throw new ApiError(detail, res.status, body);
  }
  try {
    return (await res.json()) as T;
  } catch {
    throw new ApiError("Malformed JSON response", res.status);
  }
}

/**
 * Back-compat wrapper: parsed JSON or null on error.
 * @deprecated Prefer apiFetchJSONOrThrow so callers can render error states.
 * Retained so existing null-tolerant call sites (asm, brand, settings) keep
 * working unchanged.
 */
export async function apiFetchJSON<T = unknown>(
  path: string,
  options?: RequestInit,
): Promise<T | null> {
  try {
    return await apiFetchJSONOrThrow<T>(path, options);
  } catch {
    return null;
  }
}
