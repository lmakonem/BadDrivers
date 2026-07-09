"use client";

import { useState } from "react";

const companySizes = [
  { value: "1-50", label: "1-50 employees" },
  { value: "51-200", label: "51-200 employees" },
  { value: "201-500", label: "201-500 employees" },
  { value: "501-1000", label: "501-1000 employees" },
  { value: "1000+", label: "1000+ employees" },
];

export function DemoSection() {
  const [formData, setFormData] = useState({
    first_name: "",
    last_name: "",
    email: "",
    company: "",
    job_title: "",
    phone: "",
    company_size: "",
    message: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [error, setError] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError("");

    try {
      const response = await fetch(`/api/v1/forms/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error("Failed to submit. Please try again.");
      }

      setIsSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section id="demo" className="py-16 lg:py-24">
      <div className="max-w-[1200px] mx-auto px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left Content */}
          <div>
            <p className="font-display text-[13px] font-medium uppercase tracking-[0.16em] text-primary mb-4">
              Live Demo
            </p>

            <h2 className="font-display text-[clamp(1.9rem,3.5vw,2.75rem)] font-bold leading-[1.12] tracking-[-0.02em] text-white">
              See JichoSec in action.
            </h2>

            <p className="mt-5 text-lg leading-relaxed text-[#94A3B8] mb-10">
              Get a personalized walkthrough of our platform and discover how JichoSec can
              help protect your organization from emerging threats across Africa and beyond.
            </p>

            <div className="space-y-6">
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-[10px] border border-[#1E2A3D] bg-card-dark flex items-center justify-center shrink-0 text-primary">
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  </svg>
                </div>
                <div>
                  <h3 className="font-display font-medium text-white mb-1">Threat Intelligence Overview</h3>
                  <p className="text-[#94A3B8] text-sm">See how we aggregate data from 9 live threat feeds with Africa-specific coverage</p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-[10px] border border-[#1E2A3D] bg-card-dark flex items-center justify-center shrink-0 text-primary">
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                  </svg>
                </div>
                <div>
                  <h3 className="font-display font-medium text-white mb-1">Live Threat Map Demo</h3>
                  <p className="text-[#94A3B8] text-sm">Watch real-time attacks and understand threat patterns in your region</p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="w-10 h-10 rounded-[10px] border border-[#1E2A3D] bg-card-dark flex items-center justify-center shrink-0 text-primary">
                  <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
                  </svg>
                </div>
                <div>
                  <h3 className="font-display font-medium text-white mb-1">API & Integration Setup</h3>
                  <p className="text-[#94A3B8] text-sm">Learn how to integrate with your existing SIEM, SOAR, and security tools</p>
                </div>
              </div>
            </div>
          </div>

          {/* Right - Form */}
          <div>
            <div className="p-8 lg:p-10 rounded-[14px] bg-card-dark border border-[#1E2A3D]">
              {isSubmitted ? (
                <div className="text-center py-12">
                  <div className="w-16 h-16 rounded-full border border-primary/30 bg-primary/10 flex items-center justify-center mx-auto mb-6 text-primary">
                    <svg className="w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 6L9 17l-5-5"/>
                    </svg>
                  </div>
                  <h3 className="font-display text-2xl font-bold text-white mb-2">Demo Request Received!</h3>
                  <p className="text-[#94A3B8]">
                    Our team will contact you within 24 hours to schedule your personalized demo.
                  </p>
                </div>
              ) : (
                <>
                  <h3 className="font-display text-2xl font-bold text-white mb-2">Request a Demo</h3>
                  <p className="text-[#94A3B8] mb-8">Fill out the form and we&apos;ll be in touch shortly.</p>

                  <form onSubmit={handleSubmit} className="space-y-5">
                    <div className="grid sm:grid-cols-2 gap-5">
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">First Name *</label>
                        <input
                          type="text"
                          name="first_name"
                          value={formData.first_name}
                          onChange={handleChange}
                          required
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                          placeholder="John"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">Last Name *</label>
                        <input
                          type="text"
                          name="last_name"
                          value={formData.last_name}
                          onChange={handleChange}
                          required
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                          placeholder="Doe"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-white/70 mb-2">Work Email *</label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                        placeholder="john@company.com"
                      />
                    </div>

                    <div className="grid sm:grid-cols-2 gap-5">
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">Company *</label>
                        <input
                          type="text"
                          name="company"
                          value={formData.company}
                          onChange={handleChange}
                          required
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                          placeholder="Company name"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">Job Title</label>
                        <input
                          type="text"
                          name="job_title"
                          value={formData.job_title}
                          onChange={handleChange}
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                          placeholder="Security Analyst"
                        />
                      </div>
                    </div>

                    <div className="grid sm:grid-cols-2 gap-5">
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">Phone</label>
                        <input
                          type="tel"
                          name="phone"
                          value={formData.phone}
                          onChange={handleChange}
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors"
                          placeholder="+254 700 000 000"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-white/70 mb-2">Company Size</label>
                        <select
                          name="company_size"
                          value={formData.company_size}
                          onChange={handleChange}
                          className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white focus:outline-none focus:border-primary transition-colors"
                        >
                          <option value="" className="bg-card-dark">Select size</option>
                          {companySizes.map((size) => (
                            <option key={size.value} value={size.value} className="bg-card-dark">
                              {size.label}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-white/70 mb-2">Message</label>
                      <textarea
                        name="message"
                        value={formData.message}
                        onChange={handleChange}
                        rows={3}
                        className="w-full px-4 py-3 rounded-[10px] bg-card-light border border-[#1E2A3D] text-white placeholder-white/30 focus:outline-none focus:border-primary transition-colors resize-none"
                        placeholder="Tell us about your security needs..."
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
                      className="btn-primary w-full py-4 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isSubmitting ? (
                        <span className="flex items-center justify-center gap-2">
                          <svg className="w-5 h-5 animate-spin" viewBox="0 0 24 24" fill="none">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                          </svg>
                          Submitting...
                        </span>
                      ) : (
                        "Request Demo"
                      )}
                    </button>

                    <p className="text-xs text-white/40 text-center">
                      By submitting, you agree to our{" "}
                      <a href="/privacy" className="text-primary hover:underline">Privacy Policy</a>
                      {" "}and{" "}
                      <a href="/terms" className="text-primary hover:underline">Terms of Service</a>.
                    </p>
                  </form>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
