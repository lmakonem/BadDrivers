"use client";

import { useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { JichoLogo, JichoMark } from "@/components/brand/JichoMark";

/* Decorative circuit-board brand panel — the animated eye over a PCB grid + gold glow. */
function BrandPanel({
  eyebrow,
  headline,
  tagline,
}: {
  eyebrow: string;
  headline: string;
  tagline: string;
}) {
  return (
    <div className="relative hidden lg:flex lg:w-1/2 flex-col justify-between overflow-hidden bg-body-dark p-12">
      {/* PCB grid + ambient glows */}
      <div className="circuit-grid absolute inset-0 opacity-70" />
      <div className="glow-gold absolute inset-0" />
      <div className="glow-cyan absolute inset-0" />
      {/* faint circuit traces along the lower edge */}
      <svg
        className="pointer-events-none absolute inset-x-0 bottom-0 h-44 w-full opacity-25"
        viewBox="0 0 480 176"
        fill="none"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <g stroke="#38BDF8" strokeWidth="1.2" strokeLinecap="round">
          <path className="circuit-trace" d="M0 132 H96 L128 100 H236" />
          <path className="circuit-trace" d="M40 176 V148 L76 112 H168 L192 88 H320" />
          <path className="circuit-trace" d="M300 176 V144 L340 104 H480" />
        </g>
        <g fill="#4ADE80">
          <circle cx="236" cy="100" r="1.6" />
          <circle cx="320" cy="88" r="1.6" />
          <circle cx="168" cy="112" r="1.6" />
        </g>
      </svg>

      <Link href="/" className="relative z-10">
        <JichoLogo size={46} />
      </Link>

      <div className="relative z-10 flex flex-col items-center text-center">
        <JichoMark size={210} />
        <span className="mt-9 text-xs font-semibold uppercase tracking-[0.28em] text-primary/80">
          {eyebrow}
        </span>
        <h1 className="font-display mt-3 text-4xl font-bold text-white">{headline}</h1>
        <p className="mt-4 max-w-sm text-white/55">{tagline}</p>
      </div>

      <p className="relative z-10 text-sm text-white/40">
        jicho — the watchful eye over Africa&apos;s cyberspace.
      </p>
    </div>
  );
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();

  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      await login(formData.email, formData.password);
      // Sanitize the post-login redirect to a same-site path only: require a
      // single leading slash NOT followed by another slash or backslash. This
      // rejects protocol-relative ("//evil.tld", "/\evil.tld") and absolute
      // ("https://evil.tld") URLs, preventing an open redirect via ?next=.
      const rawNext = searchParams.get("next");
      const next = rawNext && /^\/(?![/\\])/.test(rawNext) ? rawNext : "/portal";
      router.push(next);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Login failed. Please try again.";
      setError(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-body-dark flex">
      {/* Left Side - Branding */}
      <BrandPanel
        eyebrow="Threat intelligence"
        headline="Welcome back"
        tagline="Sign in to your dashboard — continuous watch over your attack surface, brand, and the dark web."
      />

      {/* Right Side - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile Logo */}
          <div className="lg:hidden mb-8">
            <Link href="/">
              <JichoLogo size={40} />
            </Link>
          </div>

          <h2 className="font-display text-3xl font-bold text-white mb-2">Sign in</h2>
          <p className="text-white/50 mb-8">
            Enter your credentials to access your dashboard
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-white/70 mb-2">Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="you@company.com"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-white/70">Password</label>
                <Link href="/forgot-password" className="text-sm text-primary hover:underline">
                  Forgot?
                </Link>
              </div>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                minLength={8}
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="Enter your password"
              />
            </div>

            {error && (
              <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="btn-primary w-full py-3.5 text-base disabled:opacity-50"
            >
              {isSubmitting ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <p className="mt-8 text-center text-white/50">
            Don&apos;t have an account?{" "}
            <Link href="/signup" className="text-primary hover:underline font-medium">
              Sign up free
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-body-dark flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}
