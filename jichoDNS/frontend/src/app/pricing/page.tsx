"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { getAccessToken } from "@/lib/auth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";

const plans = [
  {
    id: "free",
    name: "Community",
    price: "Free",
    period: "",
    priceId: null,
    description:
      "For security researchers and small teams getting started with threat intelligence.",
    features: [
      "Access to threat map",
      "1,000 API queries/month",
      "Basic IOC feeds",
      "Community support",
      "7-day data retention",
    ],
    cta: "Current Plan",
    popular: false,
  },
  {
    id: "professional",
    name: "Professional",
    price: "$299",
    period: "/month",
    priceId: "price_professional",
    description:
      "For growing security teams needing comprehensive threat intelligence.",
    features: [
      "Everything in Community",
      "50,000 API queries/month",
      "All threat feeds (15+)",
      "Dark web monitoring",
      "Brand protection alerts",
      "Threat reports",
      "30-day data retention",
      "Email support",
      "Webhook integrations",
    ],
    cta: "Upgrade to Pro",
    popular: true,
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Custom",
    period: "",
    priceId: null,
    description:
      "For large organizations requiring dedicated infrastructure and support.",
    features: [
      "Everything in Professional",
      "Unlimited API queries",
      "Custom threat feeds",
      "Attack surface management",
      "Dedicated account manager",
      "90-day data retention",
      "24/7 priority support",
      "Custom integrations",
      "On-premise deployment",
      "SLA guarantee",
    ],
    cta: "Contact Sales",
    popular: false,
  },
];

export default function PricingPage() {
  const { user } = useAuth();
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState("");

  const handleUpgrade = async (planId: string, priceId: string | null) => {
    if (!priceId) {
      // Enterprise — redirect to contact
      window.location.href = "/contact";
      return;
    }

    if (!user) {
      window.location.href = `/signup?plan=${planId}`;
      return;
    }

    setLoading(planId);
    setError("");

    try {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE_URL}/api/v1/billing/checkout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ plan: planId }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to create checkout session");
      }

      const { url } = await res.json();
      window.location.href = url;
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Something went wrong. Try again."
      );
    } finally {
      setLoading(null);
    }
  };

  const currentTier = user?.tier || "free";

  return (
    <div className="min-h-screen bg-ebony-950">
      {/* Header */}
      <header className="border-b border-white/10 bg-card-dark/50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center">
              <span className="text-white font-bold text-sm">JS</span>
            </div>
            <span className="text-lg font-semibold text-white">JichoSec</span>
          </Link>
          <div className="flex items-center gap-4">
            {user ? (
              <Link
                href="/portal"
                className="px-4 py-2 text-sm text-white bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
              >
                Back to Portal
              </Link>
            ) : (
              <Link
                href="/login"
                className="px-4 py-2 text-sm text-white bg-primary hover:bg-primary-hover rounded-lg transition-colors"
              >
                Sign In
              </Link>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-16">
        {/* Title */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h1 className="text-4xl lg:text-5xl font-bold text-white mb-6">
            Simple, Transparent <span className="text-primary">Pricing</span>
          </h1>
          <p className="text-xl text-white/50">
            Choose the plan that fits your security needs. Upgrade or downgrade
            anytime.
          </p>
        </div>

        {error && (
          <div className="max-w-md mx-auto mb-8 p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-center">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {/* Cards */}
        <div className="grid lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {plans.map((plan) => {
            const isCurrent = currentTier === plan.id;
            const isDowngrade =
              (TIER_RANK[currentTier] || 0) > (TIER_RANK[plan.id] || 0);

            return (
              <div
                key={plan.id}
                className={`relative p-8 rounded-2xl border transition-all duration-300 ${
                  plan.popular
                    ? "bg-gradient-to-b from-primary/10 to-card-dark border-primary/30 scale-105 shadow-2xl shadow-primary/20"
                    : "bg-ebony-950 border-white/10 hover:border-white/20"
                }`}
              >
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1.5 bg-primary rounded-full">
                    <span className="text-sm font-semibold text-white">
                      Most Popular
                    </span>
                  </div>
                )}

                {isCurrent && (
                  <div className="absolute -top-4 right-4 px-3 py-1 bg-green-500/20 border border-green-500/30 rounded-full">
                    <span className="text-xs font-semibold text-green-400">
                      Current Plan
                    </span>
                  </div>
                )}

                <div className="mb-8">
                  <h3 className="text-xl font-semibold text-white mb-2">
                    {plan.name}
                  </h3>
                  <div className="flex items-baseline gap-1 mb-4">
                    <span
                      className={`text-4xl font-bold ${
                        plan.popular ? "text-primary" : "text-white"
                      }`}
                    >
                      {plan.price}
                    </span>
                    {plan.period && (
                      <span className="text-white/50">{plan.period}</span>
                    )}
                  </div>
                  <p className="text-white/50 text-sm">{plan.description}</p>
                </div>

                <ul className="space-y-4 mb-8">
                  {plan.features.map((feature, idx) => (
                    <li key={idx} className="flex items-start gap-3">
                      <svg
                        className="w-5 h-5 text-primary shrink-0 mt-0.5"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                      >
                        <path
                          fillRule="evenodd"
                          d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                          clipRule="evenodd"
                        />
                      </svg>
                      <span className="text-sm text-white/70">{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => handleUpgrade(plan.id, plan.priceId)}
                  disabled={isCurrent || isDowngrade || loading === plan.id}
                  className={`block w-full py-3.5 rounded-full text-center font-semibold transition-all ${
                    isCurrent
                      ? "bg-green-500/10 text-green-400 border border-green-500/20 cursor-default"
                      : isDowngrade
                        ? "bg-white/5 text-gray-500 border border-white/5 cursor-not-allowed"
                        : plan.popular
                          ? "bg-primary hover:bg-primary-hover text-white shadow-lg shadow-primary/25"
                          : "bg-white/5 hover:bg-white/10 text-white border border-white/10"
                  }`}
                >
                  {loading === plan.id
                    ? "Redirecting..."
                    : isCurrent
                      ? "Current Plan"
                      : isDowngrade
                        ? "Downgrade"
                        : plan.id === "enterprise"
                          ? "Contact Sales"
                          : plan.cta}
                </button>
              </div>
            );
          })}
        </div>

        <div className="mt-16 text-center">
          <p className="text-white/40 mb-4">
            Need a custom solution for your organization?
          </p>
          <Link
            href="/contact"
            className="text-primary hover:text-primary-light font-medium transition-colors"
          >
            Contact our sales team
          </Link>
        </div>
      </main>
    </div>
  );
}

const TIER_RANK: Record<string, number> = {
  free: 0,
  professional: 1,
  enterprise: 2,
};
