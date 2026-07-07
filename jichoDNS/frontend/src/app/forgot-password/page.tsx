"use client";

import { useState } from "react";
import Link from "next/link";
import { JichoLogo, JichoMark } from "@/components/brand/JichoMark";

/* Decorative circuit-board brand panel — the animated eye over a PCB grid + gold glow. */
function BrandPanel() {
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
          Account recovery
        </span>
        <h1 className="font-display mt-3 text-4xl font-bold text-white">
          Regain access
        </h1>
        <p className="mt-4 max-w-sm text-white/55">
          We&apos;ll help you get back into your threat intelligence dashboard.
        </p>
      </div>

      <p className="relative z-10 text-sm text-white/40">
        jicho — the watchful eye over Africa&apos;s cyberspace.
      </p>
    </div>
  );
}

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // There is no automated password-reset flow yet, so we don't send an email.
    // Show an honest confirmation that routes the user to support instead.
    setSubmitted(true);
  };

  return (
    <div className="min-h-screen bg-body-dark flex">
      {/* Left Side - Branding */}
      <BrandPanel />

      {/* Right Side - Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile Logo */}
          <div className="lg:hidden mb-8 flex justify-center">
            <Link href="/">
              <JichoLogo size={40} />
            </Link>
          </div>

          {submitted ? (
            <div className="text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-primary/15 flex items-center justify-center mb-6">
                <svg className="w-8 h-8 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                </svg>
              </div>
              <h2 className="font-display text-2xl font-bold text-white mb-2">Contact support to reset</h2>
              <p className="text-white/50 mb-6">
                Self-service password reset isn&apos;t available yet. To reset the
                password for <strong className="text-white">{email}</strong>, email
                our team and we&apos;ll verify you and restore access.
              </p>
              <p className="text-white/40 text-sm mb-6">
                Reach us at <a href="mailto:support@defendanddetect.com" className="text-primary hover:underline">support@defendanddetect.com</a>.
              </p>
              <Link href="/login" className="btn-primary">
                Back to Login
              </Link>
            </div>
          ) : (
            <>
              <h2 className="font-display text-3xl font-bold text-white mb-2">Reset Password</h2>
              <p className="text-white/50 mb-8">
                Self-service reset isn&apos;t available yet. Enter your email and
                we&apos;ll show you how to get back into your account.
              </p>

              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label className="block text-sm font-medium text-white/70 mb-2">Email Address</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/60 transition-colors"
                    placeholder="you@company.com"
                  />
                </div>

                <button
                  type="submit"
                  className="btn-primary w-full py-3.5 text-base"
                >
                  Continue
                </button>
              </form>

              <p className="mt-8 text-center text-white/50">
                Remember your password?{" "}
                <Link href="/login" className="text-primary hover:underline font-medium">
                  Sign in
                </Link>
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
