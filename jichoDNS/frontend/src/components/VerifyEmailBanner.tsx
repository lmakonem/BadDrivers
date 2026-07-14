"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { resendVerification } from "@/lib/auth";

/**
 * Shown to signed-in users whose email is not yet verified. Renders nothing
 * for verified users, so it can sit unconditionally at the top of the portal.
 */
export default function VerifyEmailBanner() {
  const { user } = useAuth();
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">(
    "idle"
  );
  const [message, setMessage] = useState("");

  if (!user || user.is_verified) return null;

  const resend = async () => {
    setState("sending");
    try {
      const msg = await resendVerification(user.email);
      setMessage(msg);
      setState("sent");
    } catch (err: unknown) {
      setMessage(
        err instanceof Error ? err.message : "Could not send verification email."
      );
      setState("error");
    }
  };

  return (
    <div className="relative rounded-[14px] border border-amber-400/25 bg-amber-400/10 px-5 py-4">
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex items-center gap-3 flex-1">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-400/15 text-amber-300">
            <svg
              className="h-5 w-5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
              <path d="M22 6l-10 7L2 6" />
            </svg>
          </span>
          <div>
            <p className="text-sm font-medium text-amber-200">
              Verify your email address
            </p>
            <p className="text-sm text-amber-200/60">
              {state === "sent" || state === "error"
                ? message
                : `We sent a verification link to ${user.email}. Check your inbox.`}
            </p>
          </div>
        </div>
        {state !== "sent" && (
          <button
            onClick={resend}
            disabled={state === "sending"}
            className="shrink-0 rounded-lg border border-amber-400/40 px-4 py-2 text-sm font-medium text-amber-200 hover:bg-amber-400/15 disabled:opacity-50 transition-colors"
          >
            {state === "sending" ? "Sending…" : "Resend email"}
          </button>
        )}
      </div>
    </div>
  );
}
