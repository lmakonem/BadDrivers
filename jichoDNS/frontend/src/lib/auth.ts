/**
 * Authentication utilities for client-side token management.
 *
 * Tokens are stored in localStorage. On login the access + refresh tokens
 * are persisted; the API client reads the access token from here and
 * automatically refreshes when it expires.
 */

const ACCESS_TOKEN_KEY = "jichodns_access_token";
const REFRESH_TOKEN_KEY = "jichodns_refresh_token";
const USER_KEY = "jichodns_user";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";

// ── Token helpers ────────────────────────────────────────────────────────────

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(access: string, refresh: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, access);
  localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  // Also set a cookie so Next.js middleware can read it. httpOnly is left off
  // deliberately — the edge middleware currently reads this cookie from JS to
  // gate routes. `Secure` restricts it to HTTPS so the token never rides an
  // http connection. TODO: the eventual fix is a full httpOnly migration where
  // the backend sets the auth cookie via Set-Cookie (httpOnly + Secure) and the
  // middleware relies on that instead of a JS-readable value.
  document.cookie = `${ACCESS_TOKEN_KEY}=${access}; path=/; max-age=${60 * 60 * 24 * 7}; SameSite=Lax; Secure`;
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  document.cookie = `${ACCESS_TOKEN_KEY}=; path=/; max-age=0`;
}

// ── User cache (avoids round-trip on every page) ─────────────────────────────

export interface AuthUser {
  id: number;
  email: string;
  name: string | null;
  organization: string | null;
  is_active: boolean;
  is_verified: boolean;
  is_admin: boolean;
  tier: string;
  created_at: string;
}

export function getCachedUser(): AuthUser | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

export function setCachedUser(user: AuthUser): void {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

// ── Auth API calls ───────────────────────────────────────────────────────────

/**
 * Canonical email form, mirroring the backend: trimmed + lowercased. Mobile
 * keyboards auto-capitalize; without this a user could sign up as
 * "Name@x.com" and then fail to log in as "name@x.com".
 */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Cap auth requests so a hung fetch surfaces an error instead of freezing the form. */
const AUTH_TIMEOUT_MS = 20_000;

/**
 * Extract a human-readable message from a FastAPI error body. `detail` is a
 * string for HTTPException but an ARRAY of objects for 422 validation errors —
 * naively passing it to Error() renders "[object Object]".
 */
function apiErrorMessage(data: unknown, fallback: string): string {
  const detail = (data as { detail?: unknown })?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (d as { msg?: string })?.msg)
      .filter((m): m is string => typeof m === "string");
    if (msgs.length) return msgs.join(" — ");
  }
  return fallback;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export async function login(
  email: string,
  password: string
): Promise<AuthUser> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: normalizeEmail(email), password }),
    signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(apiErrorMessage(data, "Invalid email or password."));
  }

  const tokens: LoginResponse = await res.json();
  setTokens(tokens.access_token, tokens.refresh_token);

  // Fetch user profile
  const user = await fetchMe(tokens.access_token);
  setCachedUser(user);
  return user;
}

export async function register(body: {
  email: string;
  password: string;
  name?: string;
  organization?: string;
}): Promise<AuthUser> {
  const email = normalizeEmail(body.email);
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...body, email }),
    signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(apiErrorMessage(data, "Registration failed."));
  }

  // The register endpoint returns a generic { message } (HTTP 202) to avoid
  // account enumeration — NOT a user object. Complete sign-in and return the
  // AuthUser that login() resolves (login() also caches it).
  const user = await login(email, body.password);
  return user;
}

/** POST /verify-email with the token from the emailed link. */
export async function verifyEmail(token: string): Promise<string> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/verify-email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
    signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(
      apiErrorMessage(data, "Verification failed. The link may have expired.")
    );
  }
  return (
    (data as { message?: string }).message ||
    "Email verified. Your account is fully active."
  );
}

/** Request a fresh verification email. Resolves to the generic server message. */
export async function resendVerification(email: string): Promise<string> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/resend-verification`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: normalizeEmail(email) }),
    signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(apiErrorMessage(data, "Could not send verification email."));
  }
  return (
    (data as { message?: string }).message ||
    "If an unverified account exists for that address, a new verification email has been sent."
  );
}

// Single-flight guard: the dashboard fires several authed requests at once, so
// a burst of 401s would otherwise each spawn a competing refresh (and one
// failing sibling could wipe tokens another just stored). All concurrent
// callers share one in-flight refresh.
let _refreshInFlight: Promise<string | null> | null = null;

async function _doRefresh(): Promise<string | null> {
  const refresh = getRefreshToken();
  if (!refresh) return null;

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
      signal: AbortSignal.timeout(AUTH_TIMEOUT_MS),
    });

    if (res.status === 401 || res.status === 403) {
      // Definitively rejected — the refresh token is bad/expired. Clear it.
      clearTokens();
      return null;
    }
    if (!res.ok) {
      // Transient (5xx, 408, gateway hiccup) — keep the session; the caller
      // can retry. Clearing here would log users out on a flaky tunnel.
      return null;
    }

    const tokens: LoginResponse = await res.json();
    setTokens(tokens.access_token, tokens.refresh_token);
    return tokens.access_token;
  } catch {
    // Network error / timeout — transient, do NOT clear the session.
    return null;
  }
}

export async function refreshAccessToken(): Promise<string | null> {
  if (_refreshInFlight) return _refreshInFlight;
  _refreshInFlight = _doRefresh().finally(() => {
    _refreshInFlight = null;
  });
  return _refreshInFlight;
}

async function fetchMe(accessToken: string): Promise<AuthUser> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error("Failed to fetch user profile");
  return res.json();
}

/**
 * Result of validating the current session against the server.
 * - `ok`: the token is valid; `user` is the fresh server profile (cache updated).
 * - `unauthorized`: a definitive 401 — the token is bad/expired and callers
 *   should clear the session.
 * - `error`: a transient failure (network error / 5xx) — callers should keep
 *   the session and fall back to the cached user.
 */
export type MeResult =
  | { status: "ok"; user: AuthUser }
  | { status: "unauthorized" }
  | { status: "error" };

/**
 * Validate an access token against GET /api/v1/auth/me and refresh the user
 * cache on success. Unlike `fetchMe`, this never throws — it maps the outcome
 * to a discriminated result so callers can tell a definitive 401 apart from a
 * transient network/server error.
 */
export async function checkMe(accessToken: string): Promise<MeResult> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (res.status === 401) return { status: "unauthorized" };
    if (!res.ok) return { status: "error" };
    const user = (await res.json()) as AuthUser;
    setCachedUser(user);
    return { status: "ok", user };
  } catch {
    // fetch() rejects only on network-level failure — treat as transient.
    return { status: "error" };
  }
}

export function logout(): void {
  clearTokens();
  window.location.href = "/login";
}
