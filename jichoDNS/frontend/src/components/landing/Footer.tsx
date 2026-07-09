"use client";

import Link from "next/link";
import { JichoLogo } from "@/components/brand/JichoMark";

const footerLinks = {
  Products: [
    { name: "Threat Intelligence", href: "#threat-intelligence" },
    { name: "Dark Web Monitoring", href: "#dark-web" },
    { name: "Brand Protection", href: "#brand-protection" },
    { name: "Attack Surface Management", href: "#attack-surface" },
    { name: "API Access", href: "/docs/api" },
  ],
  Resources: [
    { name: "Documentation", href: "/docs" },
    { name: "API Reference", href: "/docs/api" },
    { name: "Blog", href: "/blog" },
    { name: "Threat Reports", href: "/reports" },
    { name: "Status Page", href: "/status" },
  ],
  Company: [
    { name: "About Us", href: "/about" },
    { name: "Careers", href: "/careers" },
    { name: "Contact", href: "/contact" },
    { name: "Partners", href: "/partners" },
    { name: "Press", href: "/press" },
  ],
  Legal: [
    { name: "Privacy Policy", href: "/privacy" },
    { name: "Terms of Service", href: "/terms" },
    { name: "Security", href: "/security" },
    { name: "GDPR", href: "/gdpr" },
  ],
};

const socialLinks = [
  {
    name: "Twitter",
    href: "https://twitter.com/jichosec",
    icon: (
      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
        <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
      </svg>
    ),
  },
  {
    name: "LinkedIn",
    href: "https://linkedin.com/company/jichosec",
    icon: (
      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
        <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
      </svg>
    ),
  },
  {
    name: "GitHub",
    href: "https://github.com/jichosec",
    icon: (
      <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
        <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
      </svg>
    ),
  },
];

export function Footer() {
  return (
    <footer className="bg-card-light border-t border-[#1E2A3D]">
      {/* CTA Section */}
      <div className="max-w-[1200px] mx-auto px-6 lg:px-8 pt-20 pb-16">
        <div className="p-10 lg:p-12 rounded-[14px] bg-gradient-to-b from-card-dark to-card-light border border-primary">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
            <div>
              <h3 className="font-display text-[clamp(1.6rem,3vw,2.25rem)] font-bold tracking-[-0.02em] text-white mb-4">
                Ready to secure your organization?
              </h3>
              <p className="text-lg text-[#94A3B8] max-w-2xl">
                Cyber threat intelligence built for organizations across Africa —
                real-time visibility and actionable alerts. Get started today.
              </p>
            </div>
            <div className="flex flex-wrap gap-4">
              <Link href="/signup" className="btn-primary whitespace-nowrap">
                Get Started Free
              </Link>
              <Link href="#demo" className="btn-secondary whitespace-nowrap">
                Request Demo
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Main Footer */}
      <div className="max-w-[1200px] mx-auto px-6 lg:px-8 py-16 border-t border-[#1E2A3D]">
        <div className="grid lg:grid-cols-6 gap-12">
          {/* Brand Column */}
          <div className="lg:col-span-2">
            <Link href="/" className="inline-flex items-center mb-6" aria-label="JichoSec home">
              <JichoLogo size={52} wordClassName="text-white" />
            </Link>
            <p className="text-[#94A3B8] mb-6 max-w-sm">
              Cyber threat intelligence for organizations across Africa. Real-time
              threat visibility and actionable security intelligence — the watchful
              eye over African cyberspace.
            </p>
            <div className="flex gap-4">
              {socialLinks.map((social) => (
                <a
                  key={social.name}
                  href={social.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 rounded-[10px] bg-card-dark flex items-center justify-center text-[#94A3B8] hover:text-primary border border-[#1E2A3D] hover:border-primary transition-colors"
                  aria-label={social.name}
                >
                  {social.icon}
                </a>
              ))}
            </div>
          </div>

          {/* Link Columns */}
          {Object.entries(footerLinks).map(([category, links]) => (
            <div key={category}>
              <h4 className="font-display text-[13px] font-medium text-white uppercase tracking-[0.14em] mb-4">
                {category}
              </h4>
              <ul className="space-y-3">
                {links.map((link) => (
                  <li key={link.name}>
                    <Link
                      href={link.href}
                      className="text-[#94A3B8] hover:text-primary transition-colors text-sm"
                    >
                      {link.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Bar */}
      <div className="border-t border-[#1E2A3D]">
        <div className="max-w-[1200px] mx-auto px-6 lg:px-8 py-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm text-[#94A3B8]">
            © {new Date().getFullYear()} JichoSec. All rights reserved.
          </p>
          <div className="flex items-center gap-6">
            <Link href="/privacy" className="text-sm text-[#94A3B8] hover:text-primary transition-colors">
              Privacy
            </Link>
            <Link href="/terms" className="text-sm text-[#94A3B8] hover:text-primary transition-colors">
              Terms
            </Link>
            <Link href="/security" className="text-sm text-[#94A3B8] hover:text-primary transition-colors">
              Security
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
