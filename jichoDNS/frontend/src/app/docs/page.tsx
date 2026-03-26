"use client";

import Link from "next/link";
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import { 
  Book, 
  Code, 
  Zap, 
  Shield, 
  Globe, 
  Terminal,
  FileCode,
  Plug,
  ArrowRight,
  Clock,
  CheckCircle,
  Key
} from "lucide-react";

const quickLinks = [
  {
    title: "API Reference",
    description: "Complete API documentation with endpoints, authentication, and code examples.",
    href: "/docs/api",
    icon: Code,
    color: "from-blue-500/20 to-blue-600/5"
  },
  {
    title: "Integration Guides",
    description: "Step-by-step guides for SIEM, SOAR, and security tool integrations.",
    href: "/docs/integration",
    icon: Plug,
    color: "from-purple-500/20 to-purple-600/5"
  },
  {
    title: "Python SDK",
    description: "Official Python SDK for seamless integration with your security stack.",
    href: "/docs/integration#python-sdk",
    icon: FileCode,
    color: "from-green-500/20 to-green-600/5"
  },
  {
    title: "Webhook Events",
    description: "Real-time threat notifications via webhooks to your systems.",
    href: "/docs/integration#webhooks",
    icon: Zap,
    color: "from-yellow-500/20 to-yellow-600/5"
  }
];

const gettingStartedSteps = [
  {
    step: 1,
    title: "Create an Account",
    description: "Sign up for a free JichoSec account to get started. You'll receive 100 API calls per day on the free tier.",
    code: null
  },
  {
    step: 2,
    title: "Generate API Key",
    description: "Navigate to Settings > API Keys and generate your first API key. Keep this secure - it provides access to your account.",
    code: null
  },
  {
    step: 3,
    title: "Make Your First Request",
    description: "Test your API key with a simple health check request:",
    code: `curl -X GET "https://api.jichosec.io/v1/health" \\
  -H "Authorization: Bearer YOUR_API_KEY"`
  },
  {
    step: 4,
    title: "Query Threat Intelligence",
    description: "Start querying our threat intelligence database for IOCs:",
    code: `curl -X GET "https://api.jichosec.io/v1/indicators?type=domain&limit=10" \\
  -H "Authorization: Bearer YOUR_API_KEY"`
  }
];

const platformFeatures = [
  {
    icon: Shield,
    title: "Threat Intelligence Feeds",
    description: "Access aggregated threat data from 15+ premium and open-source feeds, including Abuse.ch, PhishTank, and AlienVault OTX. Our feeds are updated every 15 minutes with new IOCs."
  },
  {
    icon: Globe,
    title: "Africa-Focused Coverage",
    description: "Purpose-built for African organizations with specialized coverage of regional threats, including mobile money fraud, telecom-specific attacks, and African brand typosquatting."
  },
  {
    icon: Terminal,
    title: "DNS Analysis Engine",
    description: "Advanced DNS threat detection using ML-powered analysis. Detect DGA domains, DNS tunneling, and exfiltration attempts with our proprietary scoring algorithms."
  },
  {
    icon: Clock,
    title: "Real-Time Monitoring",
    description: "RIPE Atlas integration provides real-time DNS measurements from African vantage points, giving you visibility into regional DNS infrastructure and threats."
  }
];

export default function DocsPage() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />
      
      {/* Hero Section */}
      <section className="pt-40 pb-20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 via-transparent to-transparent" />
        <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-primary/10 rounded-full blur-[120px]" />
        
        <div className="max-w-[1680px] mx-auto px-8 relative z-10">
          <div className="flex items-center gap-2 text-white/60 mb-6">
            <Link href="/" className="hover:text-white transition-colors">Home</Link>
            <span>/</span>
            <span className="text-white">Documentation</span>
          </div>
          
          <div className="max-w-3xl">
            <h1 className="text-4xl lg:text-5xl font-bold text-white mb-6">
              JichoSec Documentation
            </h1>
            <p className="text-xl text-white/60 mb-8">
              Everything you need to integrate Africa&apos;s leading cyber threat intelligence 
              platform into your security operations. From quick starts to advanced configurations.
            </p>
            
            <div className="flex flex-wrap gap-4">
              <Link 
                href="/docs/api"
                className="inline-flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary-hover text-white font-medium rounded-full transition-all"
              >
                <Code className="w-5 h-5" />
                API Reference
              </Link>
              <Link 
                href="/docs/integration"
                className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 hover:bg-white/20 text-white font-medium rounded-full border border-white/10 transition-all"
              >
                <Plug className="w-5 h-5" />
                Integration Guides
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Links */}
      <section className="py-16">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {quickLinks.map((link) => (
              <Link 
                key={link.title}
                href={link.href}
                className="group p-6 rounded-2xl bg-card-dark border border-white/10 hover:border-primary/30 transition-all duration-300"
              >
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${link.color} flex items-center justify-center mb-4`}>
                  <link.icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-primary transition-colors">
                  {link.title}
                </h3>
                <p className="text-white/50 text-sm">
                  {link.description}
                </p>
                <div className="flex items-center gap-2 mt-4 text-primary text-sm font-medium">
                  Learn more
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Getting Started */}
      <section className="py-20 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Zap className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-3xl font-bold text-white">Getting Started</h2>
          </div>
          <p className="text-white/60 mb-12 max-w-2xl">
            Get up and running with JichoSec in minutes. Follow these steps to make your first API call.
          </p>
          
          <div className="space-y-8">
            {gettingStartedSteps.map((item) => (
              <div key={item.step} className="flex gap-6">
                <div className="flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold">
                    {item.step}
                  </div>
                  {item.step < gettingStartedSteps.length && (
                    <div className="w-0.5 h-full bg-white/10 ml-5 mt-2" />
                  )}
                </div>
                <div className="flex-1 pb-8">
                  <h3 className="text-xl font-semibold text-white mb-2">{item.title}</h3>
                  <p className="text-white/60 mb-4">{item.description}</p>
                  {item.code && (
                    <div className="bg-card-light rounded-xl p-4 font-mono text-sm overflow-x-auto">
                      <pre className="text-white/80">{item.code}</pre>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Platform Overview */}
      <section className="py-20 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Book className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-3xl font-bold text-white">Platform Overview</h2>
          </div>
          <p className="text-white/60 mb-12 max-w-2xl">
            JichoSec provides comprehensive cyber threat intelligence with a focus on African organizations 
            and regional threat actors.
          </p>
          
          <div className="grid md:grid-cols-2 gap-8">
            {platformFeatures.map((feature) => (
              <div 
                key={feature.title}
                className="p-6 rounded-2xl bg-card-dark border border-white/10"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-4">
                  <feature.icon className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">{feature.title}</h3>
                <p className="text-white/60">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* API Overview */}
      <section className="py-20 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-12">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                  <Key className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-3xl font-bold text-white">Authentication</h2>
              </div>
              <p className="text-white/60 mb-6">
                JichoSec uses API keys for authentication. Include your API key in the 
                Authorization header of all requests.
              </p>
              
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">Bearer Token Authentication</p>
                    <p className="text-white/50 text-sm">Pass your API key as a Bearer token in the Authorization header.</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">OAuth 2.0 Support</p>
                    <p className="text-white/50 text-sm">Enterprise plans support OAuth 2.0 for enhanced security.</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
                  <div>
                    <p className="text-white font-medium">IP Whitelisting</p>
                    <p className="text-white/50 text-sm">Restrict API access to specific IP addresses (Pro & Enterprise).</p>
                  </div>
                </div>
              </div>
              
              <Link 
                href="/docs/api#authentication"
                className="inline-flex items-center gap-2 mt-6 text-primary hover:text-primary-light transition-colors"
              >
                View authentication docs
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
            
            <div>
              <div className="bg-card-light rounded-2xl p-6 border border-white/10">
                <p className="text-white/60 text-sm mb-4">Example Request</p>
                <pre className="text-sm overflow-x-auto">
                  <code className="text-white/80">
{`curl -X GET "https://api.jichosec.io/v1/indicators" \\
  -H "Authorization: Bearer js_live_abc123..." \\
  -H "Content-Type: application/json"`}
                  </code>
                </pre>
                
                <p className="text-white/60 text-sm mb-4 mt-6">Example Response</p>
                <pre className="text-sm overflow-x-auto">
                  <code className="text-white/80">
{`{
  "data": [
    {
      "id": "ioc_8x7f9k2m",
      "type": "domain",
      "value": "malicious-site.example.com",
      "threat_type": "phishing",
      "risk_score": 87,
      "first_seen": "2024-01-15T08:30:00Z",
      "tags": ["financial", "africa"]
    }
  ],
  "meta": {
    "total": 1542,
    "page": 1,
    "per_page": 20
  }
}`}
                  </code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Rate Limits Preview */}
      <section className="py-20 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-white mb-4">Rate Limits by Plan</h2>
            <p className="text-white/60 max-w-2xl mx-auto">
              Choose the plan that fits your organization&apos;s needs. Upgrade anytime as your requirements grow.
            </p>
          </div>
          
          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl bg-card-dark border border-white/10 text-center">
              <h3 className="text-lg font-semibold text-white mb-2">Free</h3>
              <p className="text-4xl font-bold text-white mb-1">100</p>
              <p className="text-white/50 text-sm">requests / day</p>
              <div className="mt-4 pt-4 border-t border-white/10">
                <p className="text-white/60 text-sm">Perfect for testing and small projects</p>
              </div>
            </div>
            
            <div className="p-6 rounded-2xl bg-gradient-to-br from-primary/20 to-card-dark border border-primary/30 text-center relative">
              <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-primary rounded-full text-xs font-medium text-white">
                Most Popular
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Pro</h3>
              <p className="text-4xl font-bold text-white mb-1">10,000</p>
              <p className="text-white/50 text-sm">requests / day</p>
              <div className="mt-4 pt-4 border-t border-white/10">
                <p className="text-white/60 text-sm">For security teams and SOC operations</p>
              </div>
            </div>
            
            <div className="p-6 rounded-2xl bg-card-dark border border-white/10 text-center">
              <h3 className="text-lg font-semibold text-white mb-2">Enterprise</h3>
              <p className="text-4xl font-bold text-white mb-1">Unlimited</p>
              <p className="text-white/50 text-sm">requests / day</p>
              <div className="mt-4 pt-4 border-t border-white/10">
                <p className="text-white/60 text-sm">For large organizations and MSSPs</p>
              </div>
            </div>
          </div>
          
          <div className="text-center mt-8">
            <Link 
              href="/docs/api#rate-limits"
              className="inline-flex items-center gap-2 text-primary hover:text-primary-light transition-colors"
            >
              View detailed rate limit information
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* Support Section */}
      <section className="py-20 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="p-8 rounded-3xl bg-card-dark border border-white/10">
            <div className="grid md:grid-cols-2 gap-8 items-center">
              <div>
                <h2 className="text-2xl font-bold text-white mb-4">Need Help?</h2>
                <p className="text-white/60 mb-6">
                  Our security engineering team is here to help you get the most out of JichoSec. 
                  From implementation support to custom integrations, we&apos;ve got you covered.
                </p>
                <div className="flex flex-wrap gap-4">
                  <Link 
                    href="mailto:support@jichosec.io"
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-full transition-all"
                  >
                    Contact Support
                  </Link>
                  <Link 
                    href="https://github.com/jichosec"
                    target="_blank"
                    className="inline-flex items-center gap-2 px-5 py-2.5 bg-white/10 hover:bg-white/20 text-white font-medium rounded-full border border-white/10 transition-all"
                  >
                    GitHub
                  </Link>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-card-light border border-white/10">
                  <p className="text-2xl font-bold text-white">24/7</p>
                  <p className="text-white/50 text-sm">Enterprise Support</p>
                </div>
                <div className="p-4 rounded-xl bg-card-light border border-white/10">
                  <p className="text-2xl font-bold text-white">&lt;4hr</p>
                  <p className="text-white/50 text-sm">Response Time</p>
                </div>
                <div className="p-4 rounded-xl bg-card-light border border-white/10">
                  <p className="text-2xl font-bold text-white">99.9%</p>
                  <p className="text-white/50 text-sm">API Uptime SLA</p>
                </div>
                <div className="p-4 rounded-xl bg-card-light border border-white/10">
                  <p className="text-2xl font-bold text-white">SOC 2</p>
                  <p className="text-white/50 text-sm">Type II Certified</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
