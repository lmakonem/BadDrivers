"use client";

import { useState } from "react";
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import Link from "next/link";

const benefits = [
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/>
      </svg>
    ),
    title: "Competitive Salary",
    description: "Market-leading compensation packages benchmarked against global tech companies",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
        <line x1="16" y1="2" x2="16" y2="6"/>
        <line x1="8" y1="2" x2="8" y2="6"/>
        <line x1="3" y1="10" x2="21" y2="10"/>
      </svg>
    ),
    title: "Flexible PTO",
    description: "Generous paid time off plus local holidays. We trust you to manage your time.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
        <polyline points="9,22 9,12 15,12 15,22"/>
      </svg>
    ),
    title: "Remote-First",
    description: "Work from anywhere in Africa. Collaborate on your schedule, wherever you are.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
        <polyline points="22,4 12,14.01 9,11.01"/>
      </svg>
    ),
    title: "Health Insurance",
    description: "Comprehensive medical, dental, and vision coverage for you and your family.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M4 19.5A2.5 2.5 0 016.5 17H20"/>
        <path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>
      </svg>
    ),
    title: "Learning Budget",
    description: "$2,000/year for conferences, courses, certifications, and books.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="12" y1="1" x2="12" y2="23"/>
        <path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/>
      </svg>
    ),
    title: "Equity Options",
    description: "Share in our success with employee stock options for all full-time employees.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
        <line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
    ),
    title: "Equipment Budget",
    description: "Latest MacBook Pro, monitor, and $1,000 for home office setup.",
  },
  {
    icon: (
      <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 00-3-3.87"/>
        <path d="M16 3.13a4 4 0 010 7.75"/>
      </svg>
    ),
    title: "Team Offsites",
    description: "Annual company retreats at beautiful African destinations.",
  },
];

const openPositions = [
  {
    title: "Senior Security Researcher",
    department: "Threat Intelligence",
    location: "Nairobi, Lagos, or Remote",
    type: "Full-time",
    description: "Lead threat research initiatives focused on African threat actors, mobile money fraud, and regional APT groups. You'll analyze malware, track campaigns, and produce actionable intelligence for our customers.",
    requirements: [
      "5+ years in threat intelligence or security research",
      "Experience with malware analysis and reverse engineering",
      "Knowledge of African threat landscape preferred",
      "Strong technical writing skills",
      "Proficiency with OSINT tools and techniques",
    ],
  },
  {
    title: "Full Stack Engineer",
    department: "Engineering",
    location: "Remote (Africa)",
    type: "Full-time",
    description: "Build and scale our threat intelligence platform used by security teams across Africa. Work with Next.js, FastAPI, PostgreSQL, and ClickHouse to deliver real-time threat visibility.",
    requirements: [
      "4+ years of full-stack development experience",
      "Proficiency with React/Next.js and Python",
      "Experience with high-throughput data systems",
      "Familiarity with cybersecurity concepts",
      "Strong problem-solving skills",
    ],
  },
  {
    title: "Sales Manager - Africa",
    department: "Sales",
    location: "Lagos or Johannesburg",
    type: "Full-time",
    description: "Drive revenue growth across the African continent. Build relationships with enterprise customers, financial institutions, and government agencies looking to enhance their security posture.",
    requirements: [
      "5+ years of B2B sales experience in technology",
      "Track record of exceeding sales targets",
      "Network within African enterprise/finance sectors",
      "Understanding of cybersecurity market",
      "Willingness to travel across Africa",
    ],
  },
  {
    title: "Machine Learning Engineer",
    department: "Engineering",
    location: "Nairobi or Remote",
    type: "Full-time",
    description: "Develop and deploy ML models for threat detection, domain classification, and anomaly detection. Work with Vertex AI and large-scale DNS datasets to improve our detection capabilities.",
    requirements: [
      "3+ years of ML engineering experience",
      "Experience with production ML systems",
      "Proficiency with Python, TensorFlow/PyTorch",
      "Background in NLP or anomaly detection",
      "Experience with GCP/Vertex AI a plus",
    ],
  },
  {
    title: "Customer Success Manager",
    department: "Customer Success",
    location: "Nairobi, Lagos, or Johannesburg",
    type: "Full-time",
    description: "Ensure our customers achieve their security goals with JichoSec. Onboard new customers, provide training, and serve as their advocate within the company.",
    requirements: [
      "3+ years in customer success or account management",
      "Background in cybersecurity or SaaS",
      "Excellent communication skills",
      "Technical aptitude to understand security products",
      "Experience working with enterprise customers",
    ],
  },
];

const values = [
  {
    title: "Mission-Driven",
    description: "We're building technology that protects millions of Africans from cyber threats. Every line of code matters.",
  },
  {
    title: "Transparency",
    description: "Open communication, honest feedback, and shared context. Everyone has visibility into company decisions.",
  },
  {
    title: "Ownership",
    description: "Take initiative, make decisions, and own the outcomes. We trust you to do what's right.",
  },
  {
    title: "Continuous Learning",
    description: "The security landscape evolves daily. We invest in our team's growth and encourage experimentation.",
  },
];

export default function CareersPage() {
  const [selectedPosition, setSelectedPosition] = useState<typeof openPositions[0] | null>(null);
  const [applicationData, setApplicationData] = useState({
    name: "",
    email: "",
    linkedin: "",
    portfolio: "",
    message: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<"idle" | "success" | "error">("idle");

  const handleApply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPosition) return;

    setIsSubmitting(true);
    setSubmitStatus("idle");

    try {
      const response = await fetch("/api/v1/forms/careers", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...applicationData,
          position: selectedPosition.title,
          department: selectedPosition.department,
        }),
      });

      if (response.ok) {
        setSubmitStatus("success");
        setApplicationData({
          name: "",
          email: "",
          linkedin: "",
          portfolio: "",
          message: "",
        });
      } else {
        setSubmitStatus("error");
      }
    } catch {
      setSubmitStatus("error");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setApplicationData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />

      {/* Hero Section */}
      <section className="relative pt-40 pb-20 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/10 rounded-full blur-[150px]" />
        <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] bg-purple-600/10 rounded-full blur-[100px]" />

        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <span className="inline-block px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
              Join Our Team
            </span>
            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
              Build the Future of{" "}
              <span className="bg-gradient-to-r from-primary to-purple-500 bg-clip-text text-transparent">
                African Cybersecurity
              </span>
            </h1>
            <p className="text-xl text-white/60 max-w-2xl mx-auto mb-8">
              Join a team of passionate security professionals working to protect 
              Africa&apos;s digital transformation. Remote-first, mission-driven, and growing fast.
            </p>
            <Link
              href="#positions"
              className="inline-block px-8 py-4 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-all shadow-lg shadow-primary/25"
            >
              View Open Positions
            </Link>
          </div>
        </div>
      </section>

      {/* Culture Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
                Our Culture
              </h2>
              <div className="space-y-4 text-white/60 text-lg">
                <p>
                  At JichoSec, we believe the best security comes from diverse teams with 
                  different perspectives. We&apos;re building a company where talented people 
                  from across Africa can do their best work, regardless of where they live.
                </p>
                <p>
                  We move fast, take ownership, and celebrate wins together. We&apos;re a small,
                  focused team building for the long term — and growing deliberately.
                </p>
                <p>
                  If you&apos;re passionate about cybersecurity and want to make a real impact on 
                  Africa&apos;s digital future, we&apos;d love to meet you.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {values.map((value) => (
                <div
                  key={value.title}
                  className="bg-card-dark rounded-2xl border border-white/10 p-6"
                >
                  <h3 className="text-lg font-semibold text-white mb-2">{value.title}</h3>
                  <p className="text-white/50 text-sm">{value.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Benefits Section */}
      <section className="py-20 bg-card-dark/50">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Benefits & Perks
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              We take care of our team so they can focus on protecting Africa
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {benefits.map((benefit) => (
              <div
                key={benefit.title}
                className="bg-card-dark rounded-2xl border border-white/10 p-6 hover:border-primary/30 transition-colors"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary mb-4">
                  {benefit.icon}
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">{benefit.title}</h3>
                <p className="text-white/50 text-sm">{benefit.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Open Positions Section */}
      <section id="positions" className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Open Positions
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              These roles are illustrative of the team we&apos;re building. We&apos;re not
              actively recruiting for every position at all times — send an application and
              we&apos;ll reach out when there&apos;s a match.
            </p>
          </div>

          <div className="space-y-4">
            {openPositions.map((position) => (
              <div
                key={position.title}
                className="bg-card-dark rounded-2xl border border-white/10 overflow-hidden"
              >
                <button
                  onClick={() =>
                    setSelectedPosition(
                      selectedPosition?.title === position.title ? null : position
                    )
                  }
                  className="w-full p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 text-left hover:bg-card-light/50 transition-colors"
                >
                  <div>
                    <h3 className="text-xl font-semibold text-white mb-1">
                      {position.title}
                    </h3>
                    <div className="flex flex-wrap gap-3 text-sm">
                      <span className="text-primary">{position.department}</span>
                      <span className="text-white/40">|</span>
                      <span className="text-white/60">{position.location}</span>
                      <span className="text-white/40">|</span>
                      <span className="text-white/60">{position.type}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-primary">
                    <span className="text-sm font-medium">
                      {selectedPosition?.title === position.title ? "Close" : "View Details"}
                    </span>
                    <svg
                      className={`w-5 h-5 transition-transform ${
                        selectedPosition?.title === position.title ? "rotate-180" : ""
                      }`}
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M6 9l6 6 6-6" />
                    </svg>
                  </div>
                </button>

                {selectedPosition?.title === position.title && (
                  <div className="p-6 pt-0 border-t border-white/10">
                    <div className="grid lg:grid-cols-2 gap-8 mt-6">
                      <div>
                        <h4 className="text-lg font-semibold text-white mb-3">About the Role</h4>
                        <p className="text-white/60 mb-6">{position.description}</p>

                        <h4 className="text-lg font-semibold text-white mb-3">Requirements</h4>
                        <ul className="space-y-2">
                          {position.requirements.map((req, index) => (
                            <li key={index} className="flex items-start gap-3 text-white/60">
                              <svg
                                className="w-5 h-5 text-primary shrink-0 mt-0.5"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="2"
                              >
                                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                                <polyline points="22,4 12,14.01 9,11.01" />
                              </svg>
                              {req}
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className="bg-card-light rounded-xl p-6">
                        <h4 className="text-lg font-semibold text-white mb-4">
                          Apply for this Position
                        </h4>

                        {submitStatus === "success" && (
                          <div className="mb-4 p-4 rounded-xl bg-green-500/10 border border-green-500/30">
                            <p className="text-green-400 font-medium">
                              Application submitted! We&apos;ll be in touch soon.
                            </p>
                          </div>
                        )}

                        {submitStatus === "error" && (
                          <div className="mb-4 p-4 rounded-xl bg-red-500/10 border border-red-500/30">
                            <p className="text-red-400 font-medium">
                              Something went wrong. Please try again.
                            </p>
                          </div>
                        )}

                        <form onSubmit={handleApply} className="space-y-4">
                          <div>
                            <label className="block text-sm font-medium text-white mb-1">
                              Full Name *
                            </label>
                            <input
                              type="text"
                              name="name"
                              value={applicationData.name}
                              onChange={handleChange}
                              required
                              className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors"
                              placeholder="Your name"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-white mb-1">
                              Email *
                            </label>
                            <input
                              type="email"
                              name="email"
                              value={applicationData.email}
                              onChange={handleChange}
                              required
                              className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors"
                              placeholder="you@email.com"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-white mb-1">
                              LinkedIn Profile
                            </label>
                            <input
                              type="url"
                              name="linkedin"
                              value={applicationData.linkedin}
                              onChange={handleChange}
                              className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors"
                              placeholder="linkedin.com/in/yourprofile"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-white mb-1">
                              Portfolio / GitHub
                            </label>
                            <input
                              type="url"
                              name="portfolio"
                              value={applicationData.portfolio}
                              onChange={handleChange}
                              className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors"
                              placeholder="github.com/username"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-white mb-1">
                              Why JichoSec? *
                            </label>
                            <textarea
                              name="message"
                              value={applicationData.message}
                              onChange={handleChange}
                              required
                              rows={3}
                              className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors resize-none"
                              placeholder="Tell us why you're interested..."
                            />
                          </div>
                          <button
                            type="submit"
                            disabled={isSubmitting}
                            className="w-full px-6 py-3 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {isSubmitting ? "Submitting..." : "Submit Application"}
                          </button>
                        </form>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Don't see a fit */}
          <div className="mt-12 text-center">
            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 max-w-2xl mx-auto">
              <h3 className="text-xl font-semibold text-white mb-3">
                Don&apos;t see a role that fits?
              </h3>
              <p className="text-white/60 mb-6">
                We&apos;re always looking for talented people. Send us your resume and 
                we&apos;ll reach out when we have a position that matches your skills.
              </p>
              <a
                href="mailto:careers@jichosec.com"
                className="inline-block px-6 py-3 bg-white/10 hover:bg-white/20 text-white font-medium rounded-full border border-white/10 transition-colors"
              >
                Send General Application
              </a>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
