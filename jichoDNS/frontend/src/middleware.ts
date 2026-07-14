import { NextRequest, NextResponse } from "next/server";

/**
 * Next.js middleware — runs on every matched request before rendering.
 *
 * Protected routes redirect to /login if the auth cookie is missing.
 * The cookie is set by the client-side auth lib after a successful login.
 */

const PUBLIC_PATHS = new Set([
  "/",
  "/login",
  "/signup",
  "/pricing",
  "/about",
  "/contact",
  "/forgot-password",
  "/verify-email",
  "/terms",
  "/privacy",
  "/api-docs",
]);

function isPublic(pathname: string): boolean {
  if (PUBLIC_PATHS.has(pathname)) return true;
  // Static assets and API routes are always public
  if (pathname.startsWith("/_next")) return true;
  if (pathname.startsWith("/api")) return true;
  if (pathname.startsWith("/images")) return true;
  if (pathname.match(/\.\w+$/)) return true; // files with extensions (favicon, etc.)
  return false;
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  // Check for auth cookie (set by client-side auth lib)
  const token = request.cookies.get("jichodns_access_token")?.value;

  if (!token) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Token exists — let the request through.
  // Actual token validation happens on the API side; if the token is
  // expired the API returns 401 and the client-side auth lib handles refresh.
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all paths except static files and Next.js internals.
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
