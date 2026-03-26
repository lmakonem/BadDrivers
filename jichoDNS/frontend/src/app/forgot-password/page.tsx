"use client";

import { useState } from "react";
import Link from "next/link";
import Image from "next/image";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Email verification is not configured yet — show a helpful message
    setSubmitted(true);
  };

  return (
    <div className="min-h-screen bg-ebony-950 flex items-center justify-center p-8">
      <div className="w-full max-w-md">
        <Link href="/" className="flex items-center gap-3 mb-8 justify-center">
          <Image src="/jichosec.png" alt="JichoSec" width={40} height={40} className="rounded-lg" />
          <div className="flex items-baseline">
            <span className="text-xl font-bold text-white">Jicho</span>
            <span className="text-xl font-bold text-primary">Sec</span>
          </div>
        </Link>

        {submitted ? (
          <div className="text-center">
            <div className="w-16 h-16 mx-auto rounded-full bg-primary/20 flex items-center justify-center mb-6">
              <svg className="w-8 h-8 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-white mb-2">Check Your Email</h2>
            <p className="text-white/50 mb-6">
              If an account exists for <strong className="text-white">{email}</strong>, we&apos;ll
              send password reset instructions shortly.
            </p>
            <p className="text-white/40 text-sm mb-6">
              Email delivery is being set up. If you don&apos;t receive an email,
              please contact <a href="mailto:support@defendanddetect.com" className="text-primary hover:underline">support@defendanddetect.com</a> for
              assistance.
            </p>
            <Link
              href="/login"
              className="inline-block px-8 py-3 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-colors"
            >
              Back to Login
            </Link>
          </div>
        ) : (
          <>
            <h2 className="text-3xl font-bold text-white mb-2 text-center">Reset Password</h2>
            <p className="text-white/50 mb-8 text-center">
              Enter your email address and we&apos;ll send you instructions to reset your password.
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-white/70 mb-2">Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="w-full px-4 py-3 rounded-xl bg-card-dark border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-primary/50 transition-colors"
                  placeholder="you@company.com"
                />
              </div>

              <button
                type="submit"
                className="w-full py-4 bg-primary hover:bg-primary-hover text-white font-semibold rounded-xl transition-all duration-300 shadow-lg shadow-primary/25"
              >
                Send Reset Link
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
  );
}
