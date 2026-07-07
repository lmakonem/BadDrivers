"use client";

import { useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { JichoLogo, JichoMark } from "@/components/brand/JichoMark";

/* Decorative circuit-board brand panel — the animated eye over a PCB grid + gold glow. */
function BrandPanel() {
  const perks = [
    "Access to 37,000+ threat indicators",
    "Real-time threat map visualization",
    "API access for SIEM integration",
  ];
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
        <JichoMark size={200} />
        <span className="mt-9 text-xs font-semibold uppercase tracking-[0.28em] text-primary/80">
          Get started
        </span>
        <h1 className="font-display mt-3 text-4xl font-bold text-white">
          Protect your organization
        </h1>
        <p className="mt-4 max-w-sm text-white/55">
          Join security teams across Africa using JichoSec for real-time threat intelligence.
        </p>

        <ul className="mt-8 space-y-3 text-left">
          {perks.map((perk) => (
            <li key={perk} className="flex items-center gap-3 text-sm text-white/75">
              <span className="flex h-6 w-6 items-center justify-center rounded-md bg-primary/15 text-primary">
                <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M20 6L9 17l-5-5" />
                </svg>
              </span>
              {perk}
            </li>
          ))}
        </ul>
      </div>

      <p className="relative z-10 text-sm text-white/40">
        jicho — the watchful eye over Africa&apos;s cyberspace.
      </p>
    </div>
  );
}

function SignupForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { register } = useAuth();
  const plan = searchParams.get("plan") || "free";

  const [formData, setFormData] = useState({
    first_name: "",
    last_name: "",
    email: "",
    company: "",
    password: "",
    confirm_password: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (formData.password !== formData.confirm_password) {
      setError("Passwords do not match");
      return;
    }

    if (formData.password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setIsSubmitting(true);

    try {
      await register({
        email: formData.email,
        password: formData.password,
        name: `${formData.first_name} ${formData.last_name}`.trim(),
        organization: formData.company || undefined,
      });
      // Registration auto-logs in, redirect to portal
      router.push("/portal");
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Registration failed.";
      setError(message);
      setIsSubmitting(false);
    }
  };

  const planNames: Record<string, string> = {
    free: "Community (Free)",
    pro: "Professional ($299/mo)",
    enterprise: "Enterprise",
  };

  return (
    <div className="min-h-screen bg-body-dark flex">
      {/* Left Side - Branding */}
      <BrandPanel />

      {/* Right Side - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile Logo */}
          <div className="lg:hidden mb-8">
            <Link href="/">
              <JichoLogo size={40} />
            </Link>
          </div>

          <h2 className="font-display text-3xl font-bold text-white mb-2">Create your account</h2>
          <p className="text-white/50 mb-8">
            Selected plan: <span className="text-primary font-medium">{planNames[plan]}</span>
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-white/70 mb-2">First Name</label>
                <input
                  type="text"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                  placeholder="John"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-white/70 mb-2">Last Name</label>
                <input
                  type="text"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleChange}
                  required
                  className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                  placeholder="Doe"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-white/70 mb-2">Work Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="john@company.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-white/70 mb-2">Company</label>
              <input
                type="text"
                name="company"
                value={formData.company}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="Company name"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-white/70 mb-2">Password</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="Min 8 characters"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-white/70 mb-2">Confirm Password</label>
              <input
                type="password"
                name="confirm_password"
                value={formData.confirm_password}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                placeholder="Confirm your password"
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
              {isSubmitting ? "Creating account..." : "Create Account"}
            </button>

            <p className="text-xs text-white/40 text-center">
              By creating an account, you agree to our{" "}
              <Link href="/terms" className="text-primary hover:underline">Terms</Link>
              {" "}and{" "}
              <Link href="/privacy" className="text-primary hover:underline">Privacy Policy</Link>.
            </p>
          </form>

          <p className="mt-8 text-center text-white/50">
            Already have an account?{" "}
            <Link href="/login" className="text-primary hover:underline font-medium">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function SignupPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-body-dark flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-white/50">Loading...</p>
        </div>
      </div>
    }>
      <SignupForm />
    </Suspense>
  );
}
