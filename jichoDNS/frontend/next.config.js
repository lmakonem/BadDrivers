/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  async headers() {
    // Security headers for the browser-facing portal. A full script-src CSP is
    // deferred: Next.js injects inline hydration scripts, so a strict CSP needs
    // per-request nonce wiring (middleware) — tracked as follow-up. Until then
    // `frame-ancestors 'none'` gives robust clickjacking protection and the
    // rest are safe, non-breaking hardening.
    const securityHeaders = [
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' },
      {
        key: 'Strict-Transport-Security',
        value: 'max-age=31536000; includeSubDomains',
      },
      { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
    ];
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
