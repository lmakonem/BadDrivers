"use client";

import { useState } from "react";
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import { JichoMark } from "@/components/brand/JichoMark";

const offices = [
  {
    city: "Nairobi",
    country: "Kenya",
    type: "Global Headquarters",
    address: "Westlands Business Park, Tower B, 14th Floor",
    addressLine2: "Waiyaki Way, Westlands",
    addressLine3: "Nairobi, Kenya",
    phone: "+254 20 123 4567",
    email: "nairobi@jichosec.com",
  },
  {
    city: "Lagos",
    country: "Nigeria",
    type: "West Africa Hub",
    address: "Landmark Towers, 5th Floor",
    addressLine2: "Plot 5B Water Corporation Road",
    addressLine3: "Victoria Island, Lagos, Nigeria",
    phone: "+234 1 234 5678",
    email: "lagos@jichosec.com",
  },
  {
    city: "Johannesburg",
    country: "South Africa",
    type: "Southern Africa Hub",
    address: "The Campus, Building 2",
    addressLine2: "57 Sloane Street, Bryanston",
    addressLine3: "Johannesburg, South Africa",
    phone: "+27 11 234 5678",
    email: "johannesburg@jichosec.com",
  },
];

const subjects = [
  "General Inquiry",
  "Sales & Pricing",
  "Technical Support",
  "Partnership Opportunities",
  "Press & Media",
  "Careers",
  "Security Vulnerability Report",
];

export default function ContactPage() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    company: "",
    subject: "",
    message: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitStatus("idle");
    setErrorMessage("");

    try {
      const response = await fetch("/api/v1/forms/contact", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        setSubmitStatus("success");
        setFormData({
          name: "",
          email: "",
          company: "",
          subject: "",
          message: "",
        });
      } else {
        const data = await response.json();
        setErrorMessage(data.message || "Failed to submit form. Please try again.");
        setSubmitStatus("error");
      }
    } catch {
      setErrorMessage("Network error. Please check your connection and try again.");
      setSubmitStatus("error");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  return (
    <main className="min-h-screen bg-body-dark">
      <Header />

      {/* Hero Section */}
      <section className="relative pt-40 pb-20 overflow-hidden">
        <div className="absolute inset-0 circuit-grid opacity-60" />
        <div className="absolute inset-0 glow-gold" />
        <div className="absolute inset-0 glow-cyan" />

        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <span className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm font-medium mb-6">
              <JichoMark size={18} />
              Contact Us
            </span>
            <h1 className="font-display text-4xl md:text-6xl font-bold text-white mb-6">
              Get in <span className="gradient-text">Touch</span>
            </h1>
            <p className="text-xl text-white/60 max-w-2xl mx-auto">
              Have questions about our platform? Want to schedule a demo? 
              Our team is here to help you secure your organization.
            </p>
          </div>
        </div>
      </section>

      {/* Contact Form & Info Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-16">
            {/* Contact Form */}
            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 lg:p-12">
              <h2 className="font-display text-2xl font-bold text-white mb-2">Send us a message</h2>
              <p className="text-white/60 mb-8">
                Fill out the form below and we&apos;ll get back to you within 24 hours.
              </p>

              {submitStatus === "success" && (
                <div className="mb-6 p-4 rounded-xl bg-green-500/10 border border-green-500/30">
                  <p className="text-green-400 font-medium">
                    Thank you for your message! We&apos;ll be in touch soon.
                  </p>
                </div>
              )}

              {submitStatus === "error" && (
                <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30">
                  <p className="text-red-400 font-medium">{errorMessage}</p>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <label htmlFor="name" className="block text-sm font-medium text-white mb-2">
                      Full Name *
                    </label>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      value={formData.name}
                      onChange={handleChange}
                      required
                      className="w-full px-4 py-3 rounded-xl bg-card-light border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-secondary transition-colors"
                      placeholder="John Doe"
                    />
                  </div>
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-white mb-2">
                      Work Email *
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      required
                      className="w-full px-4 py-3 rounded-xl bg-card-light border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-secondary transition-colors"
                      placeholder="john@company.com"
                    />
                  </div>
                </div>

                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <label htmlFor="company" className="block text-sm font-medium text-white mb-2">
                      Company
                    </label>
                    <input
                      type="text"
                      id="company"
                      name="company"
                      value={formData.company}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl bg-card-light border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-secondary transition-colors"
                      placeholder="Your Company"
                    />
                  </div>
                  <div>
                    <label htmlFor="subject" className="block text-sm font-medium text-white mb-2">
                      Subject *
                    </label>
                    <select
                      id="subject"
                      name="subject"
                      value={formData.subject}
                      onChange={handleChange}
                      required
                      className="w-full px-4 py-3 rounded-xl bg-card-light border border-white/10 text-white focus:outline-none focus:border-secondary transition-colors"
                    >
                      <option value="">Select a subject</option>
                      {subjects.map((subject) => (
                        <option key={subject} value={subject}>
                          {subject}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label htmlFor="message" className="block text-sm font-medium text-white mb-2">
                    Message *
                  </label>
                  <textarea
                    id="message"
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    required
                    rows={6}
                    className="w-full px-4 py-3 rounded-xl bg-card-light border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-secondary transition-colors resize-none"
                    placeholder="Tell us how we can help..."
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isSubmitting ? "Sending..." : "Send Message"}
                </button>
              </form>
            </div>

            {/* Contact Information */}
            <div className="space-y-8">
              {/* Quick Contact */}
              <div className="bg-card-dark rounded-2xl border border-white/10 p-8">
                <h3 className="font-display text-xl font-semibold text-white mb-6">Quick Contact</h3>
                <div className="space-y-6">
                  <div className="flex items-start gap-4">
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                      <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                      </svg>
                    </div>
                    <div>
                      <p className="text-white font-medium">Sales Inquiries</p>
                      <a href="mailto:sales@jichosec.com" className="text-secondary hover:text-secondary-hover transition-colors">
                        sales@jichosec.com
                      </a>
                    </div>
                  </div>

                  <div className="flex items-start gap-4">
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                      <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M18.36 6.64a9 9 0 11-12.73 0"/>
                        <circle cx="12" cy="12" r="2"/>
                      </svg>
                    </div>
                    <div>
                      <p className="text-white font-medium">Technical Support</p>
                      <a href="mailto:support@jichosec.com" className="text-secondary hover:text-secondary-hover transition-colors">
                        support@jichosec.com
                      </a>
                    </div>
                  </div>

                  <div className="flex items-start gap-4">
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                      <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72 12.84 12.84 0 00.7 2.81 2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45 12.84 12.84 0 002.81.7A2 2 0 0122 16.92z"/>
                      </svg>
                    </div>
                    <div>
                      <p className="text-white font-medium">General Inquiries</p>
                      <a href="tel:+254201234567" className="text-secondary hover:text-secondary-hover transition-colors">
                        +254 20 123 4567
                      </a>
                    </div>
                  </div>

                  <div className="flex items-start gap-4">
                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0">
                      <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                      </svg>
                    </div>
                    <div>
                      <p className="text-white font-medium">Security Issues</p>
                      <a href="mailto:security@jichosec.com" className="text-secondary hover:text-secondary-hover transition-colors">
                        security@jichosec.com
                      </a>
                    </div>
                  </div>
                </div>
              </div>

              {/* Response Time */}
              <div className="bg-gradient-to-br from-primary/10 to-secondary/10 rounded-2xl border border-white/10 p-8">
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-primary/20 flex items-center justify-center">
                    <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <path d="M12 6v6l4 2"/>
                    </svg>
                  </div>
                  <div>
                    <p className="text-white font-semibold">Response Time</p>
                    <p className="text-white/60">Within 24 hours</p>
                  </div>
                </div>
                <p className="text-white/50 text-sm">
                  Our team typically responds to inquiries within 24 hours during business days. 
                  For urgent security matters, please email security@jichosec.com with &quot;URGENT&quot; in the subject line.
                </p>
              </div>

              {/* Map Placeholder */}
              <div className="bg-card-dark rounded-2xl border border-white/10 p-8">
                <h3 className="font-display text-xl font-semibold text-white mb-4">Our Locations</h3>
                <div className="relative aspect-video bg-card-light rounded-xl border border-white/10 flex items-center justify-center overflow-hidden">
                  <div className="absolute inset-0 circuit-grid opacity-70" />
                  <div className="absolute inset-0 glow-cyan" />
                  <div className="relative z-10 text-center">
                    <JichoMark size={44} className="mx-auto mb-3" />
                    <p className="text-white/50">Interactive Map</p>
                    <p className="text-white/30 text-sm">Nairobi &middot; Lagos &middot; Johannesburg</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Office Locations */}
      <section className="py-20 bg-card-dark/40">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold text-white mb-4">
              Visit Our Offices
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              We&apos;d love to meet you in person. Visit any of our offices across Africa.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {offices.map((office) => (
              <div
                key={office.city}
                className="bg-card-dark rounded-2xl border border-white/10 p-8 hover:border-primary/30 transition-colors"
              >
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                    <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"/>
                      <circle cx="12" cy="10" r="3"/>
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-display text-xl font-semibold text-white">{office.city}</h3>
                    <p className="text-primary text-sm">{office.type}</p>
                  </div>
                </div>
                <div className="space-y-3 text-white/60">
                  <p>{office.address}</p>
                  <p>{office.addressLine2}</p>
                  <p>{office.addressLine3}</p>
                  <div className="pt-4 space-y-2 border-t border-white/10">
                    <p className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72 12.84 12.84 0 00.7 2.81 2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45 12.84 12.84 0 002.81.7A2 2 0 0122 16.92z"/>
                      </svg>
                      <span className="text-white/80">{office.phone}</span>
                    </p>
                    <p className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                      </svg>
                      <a href={`mailto:${office.email}`} className="text-secondary hover:text-secondary-hover transition-colors">
                        {office.email}
                      </a>
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
