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
      "All threat feeds (15+)",
      "Dark web monitoring",
      "Brand protection alerts",
      "30-day data retention",
      "Email support",
      "Webhook integrations",
    ],
    cta: "Start Free Trial",
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
    <section id="pricing" className="relative py-24 bg-card-dark">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-primary/5 rounded-full blur-[150px]" />
      </div>

      <div className="relative z-10 max-w-[1680px] mx-auto px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <span className="text-sm font-medium text-primary">Pricing</span>
          </div>
          <h2 className="text-4xl lg:text-5xl font-bold text-white mb-6">
            Simple, Transparent
            <span className="text-primary"> Pricing</span>
          </h2>
          <p className="text-xl text-white/50">
            Choose the plan that fits your security needs. All plans include access to our 
            real-time threat intelligence platform.
          </p>
        </div>

        {/* Pricing Cards */}
        <div className="grid lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {plans.map((plan) => (
            <div
              key={plan.name}
              className={`relative p-8 rounded-2xl border transition-all duration-300 ${
                plan.popular
                  ? "bg-gradient-to-b from-primary/10 to-card-dark border-primary/30 scale-105 shadow-2xl shadow-primary/20"
                  : "bg-ebony-950 border-white/10 hover:border-white/20"
              }`}
            >
              {/* Popular Badge */}
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1.5 bg-primary rounded-full">
                  <span className="text-sm font-semibold text-white">Most Popular</span>
                </div>
              )}

              {/* Plan Header */}
              <div className="mb-8">
                <h3 className="text-xl font-semibold text-white mb-2">{plan.name}</h3>
                <div className="flex items-baseline gap-1 mb-4">
                  <span className={`text-4xl font-bold ${plan.popular ? "text-primary" : "text-white"}`}>
                    {plan.price}
                  </span>
                  {plan.period && <span className="text-white/50">{plan.period}</span>}
                </div>
                <p className="text-white/50 text-sm">{plan.description}</p>
              </div>

              {/* Features */}
              <ul className="space-y-4 mb-8">
                {plan.features.map((feature, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <svg className="w-5 h-5 text-primary shrink-0 mt-0.5" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd"/>
                    </svg>
                    <span className="text-sm text-white/70">{feature}</span>
                  </li>
                ))}
              </ul>

              {/* CTA Button */}
              <Link
                href={plan.ctaLink}
                className={`block w-full py-3.5 rounded-full text-center font-semibold transition-all ${
                  plan.popular
                    ? "bg-primary hover:bg-primary-hover text-white shadow-lg shadow-primary/25"
                    : "bg-white/5 hover:bg-white/10 text-white border border-white/10"
                }`}
              >
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>

        {/* Enterprise CTA */}
        <div className="mt-16 text-center">
          <p className="text-white/40 mb-4">
            Need a custom solution for your organization?
          </p>
          <Link
            href="/contact"
            className="text-primary hover:text-primary-light font-medium transition-colors"
          >
            Contact our sales team →
          </Link>
        </div>
      </div>
    </section>
  );
}
