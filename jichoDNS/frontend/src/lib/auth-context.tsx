"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  AuthUser,
  getAccessToken,
  getCachedUser,
  login as authLogin,
  register as authRegister,
  clearTokens,
  checkMe,
  refreshAccessToken,
} from "./auth";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (body: {
    email: string;
    password: string;
    name?: string;
    organization?: string;
  }) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // On mount, validate any stored token against the server before painting the
  // portal — this avoids the "logged-in-but-stale / first-call-401" symptom
  // where the UI trusts a cached user that the server has since rejected.
  // `loading` stays true until validation resolves so nothing renders a stale
  // user in the meantime.
  useEffect(() => {
    let cancelled = false;

    async function hydrate() {
      const token = getAccessToken();
      if (!token) {
        if (!cancelled) {
          setUser(null);
          setLoading(false);
        }
        return;
      }

      // Kept only as a fallback for transient failures — never painted while
      // `loading` is still true.
      const cached = getCachedUser();

      // Validate the token. On a definitive 401, try one refresh + retry.
      let result = await checkMe(token);
      if (result.status === "unauthorized") {
        const refreshed = await refreshAccessToken();
        if (refreshed) {
          result = await checkMe(refreshed);
        }
      }

      if (cancelled) return;

      if (result.status === "ok") {
        // checkMe already refreshed the cached user.
        setUser(result.user);
      } else if (result.status === "error") {
        // Transient network/server error — tolerate it and fall back to cache
        // rather than logging the user out.
        setUser(cached);
      } else {
        // Definitive 401 even after a refresh attempt — clear the session.
        clearTokens();
        setUser(null);
      }
      setLoading(false);
    }

    hydrate();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const u = await authLogin(email, password);
    setUser(u);
  }, []);

  const register = useCallback(
    async (body: {
      email: string;
      password: string;
      name?: string;
      organization?: string;
    }) => {
      const u = await authRegister(body);
      setUser(u);
    },
    []
  );

  const logout = useCallback(() => {
    clearTokens();
    setUser(null);
    window.location.href = "/login";
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
