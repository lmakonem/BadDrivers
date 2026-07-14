"use client";

import { useEffect, useRef, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { verifyEmail } from "@/lib/auth";
import { JichoLogo } from "@/components/brand/JichoMark";

type State =
  | { status: "verifying" }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

function VerifyEmailInner() {
  const searchParams = useSearchParams();
  const token = searchParams.get("token") || "";
  const [state, setState] = useState<State>({ status: "verifying" });
  // React 18 StrictMode double-runs effects in dev; the call is idempotent on
  // the server but there's no reason to fire it twice.
  const fired = useRef(false);

  useEffect(() => {
    if (fired.current) return;
    fired.current = true;

    if (!token) {
      setState({
        status: "error",
        message:
          "No verification token found. Use the link from your verification email.",
      });
      return;
    }

    verifyEmail(token)
      .then((message) => setState({ status: "success", message }))
      .catch((err: unknown) =>
        setState({
          status: "error",
          message:
            err instanceof Error
              ? err.message
              : "Verification failed. The link may have expired.",
        })
      );
  }, [token]);

  return (
    <div className="min-h-screen bg-body-dark flex items-center justify-center p-8">
      <div className="w-full max-w-md text-center">
        <div className="mb-10 flex justify-center">
          <Link href="/">
            <JichoLogo size={44} />
          </Link>
        </div>

        {state.status === "verifying" && (
          <>
            <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-6" />
            <h1 className="font-display text-2xl font-bold text-white mb-2">
              Verifying your email…
            </h1>
            <p className="text-white/50">This only takes a moment.</p>
          </>
        )}

        {state.status === "success" && (
          <>
            <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-400">
              <svg
                className="h-8 w-8"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M20 6L9 17l-5-5" />
              </svg>
            </div>
            <h1 className="font-display text-2xl font-bold text-white mb-2">
              Email verified
            </h1>
            <p className="text-white/50 mb-8">{state.message}</p>
            <Link href="/portal" className="btn-primary inline-block px-8 py-3">
              Go to your portal
            </Link>
            <p className="mt-6 text-sm text-white/40">
              Not signed in?{" "}
              <Link href="/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </p>
          </>
        )}

        {state.status === "error" && (
          <>
            <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/15 text-red-400">
              <svg
                className="h-8 w-8"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </div>
            <h1 className="font-display text-2xl font-bold text-white mb-2">
              Verification failed
            </h1>
            <p className="text-white/50 mb-8">{state.message}</p>
            <Link href="/portal" className="btn-primary inline-block px-8 py-3">
              Go to your portal
            </Link>
            <p className="mt-6 text-sm text-white/40">
              You can request a fresh verification email from your portal, or{" "}
              <Link href="/contact" className="text-primary hover:underline">
                contact support
              </Link>
              .
            </p>
          </>
        )}
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-body-dark flex items-center justify-center">
          <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <VerifyEmailInner />
    </Suspense>
  );
}
