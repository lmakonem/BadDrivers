"use client";

import Link from "next/link";

const plans = [
  {
    name: "Community",
    price: "Free",
    period: "",
    description: "For security researchers and small teams getting started with threat intelligence.",
    features: [
      "Access to threat map",
      "1,000 API queries/month",
      "Basic IOC feeds",
      "Community support",
      "7-day data retention",
    ],
    cta: "Get Started",
    ctaLink: "/signup",
    popular: false,
  },
  {
    name: "Professional",
    price: "$299",
    period: "/month",
    description: "For growing security teams needing comprehensive threat intelligence.",
    features: [
      "Everything in Community",
      "50,000 API queries/month",
      "All 9 threat feeds",
      "Dark web monitoring",
      "Brand protection alerts",
      "30-day data retention",
      "Email support",
      "Webhook integrations",
    ],
    cta: "Get Started",
    ctaLink: "/signup?plan=pro",
    popular: true,
  },
  {
    name: "Enterprise",
    price: "Custom",
    period: "",
    description: "For large organizations requiring dedicated infrastructure and support.",
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
    ctaLink: "/contact",
    popular: false,
  },
];

export function Pricing() {
  return (
    <section id="pricing" className="bg-ebony-900/45 py-16 lg:py-24">
      <div className="max-w-[1200px] mx-auto px-6 lg:px-8">

        {/* section head — small green label + big left-aligned white title */}
        <div className="max-w-[760px] mb-12 lg:mb-16">
          <p className="font-display text-[13px] font-medium uppercase tracking-[0.16em] text-primary mb-4">
            Pricing
          </p>
          <h2 className="font-display text-[clamp(1.9rem,3.5vw,2.75rem)] font-bold leading-[1.12] tracking-[-0.02em] text-white">
            Simple, transparent pricing.
          </h2>
          <p className="mt-5 text-lg leading-relaxed text-[#94A3B8]">
            Choose the plan that fits your security needs. All plans include access to our
            real-time threat intelligence platform.
          </p>
        </div>

        {/* pricing cards */}
        <div className="grid lg:grid-cols-3 gap-6">
          {plans.map((plan) => (
            <div
              key={plan.name}
              className={`relative flex flex-col p-8 rounded-[14px] bg-card-dark border transition-colors duration-200 ${
                plan.popular
                  ? "border-primary"
                  : "border-[#1E2A3D] hover:border-primary/50"
              }`}
            >
              {/* recommended badge */}
              {plan.popular && (
                <div className="absolute -top-3 left-8 px-3 py-1 rounded-full bg-primary">
                  <span className="font-display text-xs font-semibold text-body-dark">Most Popular</span>
                </div>
              )}

              {/* plan header */}
              <div className="mb-8">
                <h3 className="font-display text-xl font-medium text-white mb-3">{plan.name}</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className={`font-display text-4xl font-bold ${plan.popular ? "text-primary" : "text-white"}`}>
                    {plan.price}
                  </span>
                  {plan.period && <span className="text-[#94A3B8]">{plan.period}</span>}
                </div>
                <p className="text-sm text-[#94A3B8]">{plan.description}</p>
              </div>

              {/* features */}
              <ul className="space-y-3.5 mb-8 flex-1">
                {plan.features.map((feature, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <svg className="w-4 h-4 shrink-0 mt-0.5 text-primary" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/>
                    </svg>
                    <span className="text-sm text-[#94A3B8]">{feature}</span>
                  </li>
                ))}
              </ul>

              {/* CTA button */}
              <Link
                href={plan.ctaLink}
                className={`w-full ${plan.popular ? "btn-primary" : "btn-secondary"}`}
              >
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>

        {/* enterprise CTA */}
        <div className="mt-14">
          <p className="text-[#94A3B8] mb-3">
            Need a custom solution for your organization?
          </p>
          <Link
            href="/contact"
            className="font-display font-medium text-primary hover:text-primary-hover transition-colors"
          >
            Contact our sales team →
          </Link>
        </div>
      </div>
    </section>
  );
}
