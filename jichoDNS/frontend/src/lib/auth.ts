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
  // Also set a cookie so Next.js middleware can read it (httpOnly=false is
  // intentional — middleware runs on the edge and needs to read the cookie).
  document.cookie = `${ACCESS_TOKEN_KEY}=${access}; path=/; max-age=${60 * 60 * 24 * 7}; SameSite=Lax`;
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
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Invalid email or password.");
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
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Registration failed.");
  }

  const user: AuthUser = await res.json();

  // Auto-login after registration
  await login(body.email, body.password);
  return user;
}

export async function refreshAccessToken(): Promise<string | null> {
  const refresh = getRefreshToken();
  if (!refresh) return null;

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });

    if (!res.ok) {
      clearTokens();
      return null;
    }

    const tokens: LoginResponse = await res.json();
    setTokens(tokens.access_token, tokens.refresh_token);
    return tokens.access_token;
  } catch {
    clearTokens();
    return null;
  }
}

async function fetchMe(accessToken: string): Promise<AuthUser> {
  const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error("Failed to fetch user profile");
  return res.json();
}

export function logout(): void {
  clearTokens();
  window.location.href = "/login";
}
