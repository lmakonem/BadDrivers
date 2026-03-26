"use client";

import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import Link from "next/link";

const teamMembers = [
  {
    name: "Dr. Amani Okonkwo",
    role: "Founder & CEO",
    bio: "Former cybersecurity lead at Safaricom. PhD in Computer Science from University of Nairobi. 15+ years in threat intelligence.",
    image: "/team/amani.jpg",
  },
  {
    name: "Fatima Hassan",
    role: "Chief Technology Officer",
    bio: "Ex-Google Security Engineer. Built ML systems processing billions of DNS queries. Stanford MS in AI.",
    image: "/team/fatima.jpg",
  },
  {
    name: "Kwame Asante",
    role: "VP of Engineering",
    bio: "Former Principal Engineer at Cloudflare. Expert in distributed systems and real-time threat detection.",
    image: "/team/kwame.jpg",
  },
  {
    name: "Lindiwe Ndlovu",
    role: "Head of Threat Research",
    bio: "Previously led threat intelligence at CyberCX. Specialized in African cybercrime ecosystems and mobile money fraud.",
    image: "/team/lindiwe.jpg",
  },
  {
    name: "Oluwaseun Adeyemi",
    role: "Director of Sales, Africa",
    bio: "10+ years building enterprise security sales across West Africa. Former Regional Director at Palo Alto Networks.",
    image: "/team/oluwaseun.jpg",
  },
  {
    name: "Thandiwe Moyo",
    role: "Head of Customer Success",
    bio: "Former SOC Manager at Standard Bank. Expert in SIEM integration and security operations optimization.",
    image: "/team/thandiwe.jpg",
  },
];

const offices = [
  {
    city: "Nairobi",
    country: "Kenya",
    type: "Global Headquarters",
    address: "Westlands Business Park, Tower B, 14th Floor",
    addressLine2: "Waiyaki Way, Westlands",
    addressLine3: "Nairobi, Kenya",
    phone: "+254 20 123 4567",
  },
  {
    city: "Lagos",
    country: "Nigeria",
    type: "West Africa Hub",
    address: "Landmark Towers, 5th Floor",
    addressLine2: "Plot 5B Water Corporation Road",
    addressLine3: "Victoria Island, Lagos, Nigeria",
    phone: "+234 1 234 5678",
  },
  {
    city: "Johannesburg",
    country: "South Africa",
    type: "Southern Africa Hub",
    address: "The Campus, Building 2",
    addressLine2: "57 Sloane Street, Bryanston",
    addressLine3: "Johannesburg, South Africa",
    phone: "+27 11 234 5678",
  },
];

const partners = [
  { name: "AWS", logo: "/partners/aws.svg" },
  { name: "Google Cloud", logo: "/partners/gcp.svg" },
  { name: "Microsoft", logo: "/partners/microsoft.svg" },
  { name: "RIPE NCC", logo: "/partners/ripe.svg" },
  { name: "AfriNIC", logo: "/partners/afrinic.svg" },
  { name: "Safaricom", logo: "/partners/safaricom.svg" },
];

const milestones = [
  { year: "2022", event: "Founded in Nairobi, Kenya" },
  { year: "2022", event: "Seed funding from African VC consortium" },
  { year: "2023", event: "Launched threat intelligence platform" },
  { year: "2023", event: "Expanded to Lagos and Johannesburg" },
  { year: "2024", event: "Series A funding ($12M)" },
  { year: "2024", event: "100+ enterprise customers" },
  { year: "2025", event: "Processing 1B+ DNS queries daily" },
  { year: "2026", event: "Expanded ML capabilities with Vertex AI" },
];

export default function AboutPage() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />
      
      {/* Hero Section */}
      <section className="relative pt-40 pb-20 overflow-hidden">
        {/* Background Elements */}
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/10 rounded-full blur-[150px]" />
        <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] bg-purple-600/10 rounded-full blur-[100px]" />
        
        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <span className="inline-block px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
              About JichoSec
            </span>
            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
              Securing Africa&apos;s{" "}
              <span className="bg-gradient-to-r from-primary to-purple-500 bg-clip-text text-transparent">
                Digital Future
              </span>
            </h1>
            <p className="text-xl text-white/60 max-w-3xl mx-auto">
              We are Africa&apos;s leading cyber threat intelligence company, dedicated to protecting 
              organizations across the continent with world-class security solutions built for 
              African challenges.
            </p>
          </div>
        </div>
      </section>

      {/* Our Story Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
                Our Story
              </h2>
              <div className="space-y-4 text-white/60 text-lg">
                <p>
                  JichoSec was founded in 2022 in Nairobi, Kenya, born from a simple observation: 
                  Africa&apos;s rapidly growing digital economy needed cybersecurity solutions designed 
                  specifically for its unique challenges.
                </p>
                <p>
                  Our founders, a team of seasoned security professionals from companies like 
                  Safaricom, Google, and Cloudflare, recognized that global threat intelligence 
                  platforms often overlooked the specific threat landscape facing African organizations 
                  mobile money fraud, regional phishing campaigns, and infrastructure targeting.
                </p>
                <p>
                  &quot;Jicho&quot; means &quot;eye&quot; in Swahili, reflecting our mission to provide unparalleled 
                  visibility into cyber threats across the continent. Today, we protect over 100 
                  enterprises across 20 African countries, processing billions of DNS queries daily 
                  to detect and neutralize threats before they cause harm.
                </p>
                <p>
                  From our headquarters in Nairobi, with regional hubs in Lagos and Johannesburg, 
                  we&apos;re building the future of African cybersecurity one threat at a time.
                </p>
              </div>
            </div>
            
            {/* Timeline */}
            <div className="bg-card-dark rounded-2xl border border-white/10 p-8">
              <h3 className="text-xl font-semibold text-white mb-8">Our Journey</h3>
              <div className="space-y-6">
                {milestones.map((milestone, index) => (
                  <div key={index} className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className="w-3 h-3 rounded-full bg-primary" />
                      {index < milestones.length - 1 && (
                        <div className="w-0.5 h-full bg-white/10 mt-2" />
                      )}
                    </div>
                    <div className="pb-6">
                      <span className="text-primary font-semibold">{milestone.year}</span>
                      <p className="text-white/70 mt-1">{milestone.event}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Mission & Values Section */}
      <section className="py-20 bg-card-dark/50">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Our Mission & Values
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              What drives us every day to build the best threat intelligence platform for Africa
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 text-center">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-6">
                <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white mb-3">Security First</h3>
              <p className="text-white/50">
                We believe every African organization deserves world-class protection against cyber threats.
              </p>
            </div>

            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 text-center">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-6">
                <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2L2 7l10 5 10-5-10-5z"/>
                  <path d="M2 17l10 5 10-5"/>
                  <path d="M2 12l10 5 10-5"/>
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white mb-3">African Expertise</h3>
              <p className="text-white/50">
                Built by Africans, for Africa. We understand the unique challenges of our digital landscape.
              </p>
            </div>

            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 text-center">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-6">
                <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/>
                  <path d="M12 6v6l4 2"/>
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white mb-3">Real-Time Response</h3>
              <p className="text-white/50">
                Threats don&apos;t wait. Neither do we. Our platform delivers instant visibility and alerts.
              </p>
            </div>

            <div className="bg-card-dark rounded-2xl border border-white/10 p-8 text-center">
              <div className="w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-6">
                <svg className="w-8 h-8 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                  <circle cx="9" cy="7" r="4"/>
                  <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                  <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white mb-3">Customer Success</h3>
              <p className="text-white/50">
                Your security is our success. We partner with you to achieve your security goals.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Leadership Team
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              Industry veterans with decades of combined experience in cybersecurity, 
              cloud infrastructure, and African technology markets
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {teamMembers.map((member) => (
              <div
                key={member.name}
                className="bg-card-dark rounded-2xl border border-white/10 p-8 hover:border-primary/30 transition-colors"
              >
                <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-primary/20 to-purple-600/20 flex items-center justify-center mb-6 mx-auto">
                  <span className="text-3xl font-bold text-white">
                    {member.name.split(" ").map(n => n[0]).join("")}
                  </span>
                </div>
                <div className="text-center">
                  <h3 className="text-xl font-semibold text-white mb-1">{member.name}</h3>
                  <p className="text-primary font-medium mb-4">{member.role}</p>
                  <p className="text-white/50 text-sm">{member.bio}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Offices Section */}
      <section className="py-20 bg-card-dark/50">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Our Offices
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              Strategically located across Africa&apos;s major tech hubs to serve our customers
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {offices.map((office) => (
              <div
                key={office.city}
                className="bg-card-dark rounded-2xl border border-white/10 p-8"
              >
                <div className="flex items-center gap-3 mb-6">
                  <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                    <svg className="w-6 h-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/>
                      <circle cx="12" cy="10" r="3"/>
                    </svg>
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold text-white">{office.city}</h3>
                    <p className="text-primary text-sm">{office.type}</p>
                  </div>
                </div>
                <div className="space-y-3 text-white/60">
                  <p>{office.address}</p>
                  <p>{office.addressLine2}</p>
                  <p>{office.addressLine3}</p>
                  <p className="text-white/80 font-medium">{office.phone}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Partners Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Backed by Industry Leaders
            </h2>
            <p className="text-white/60 text-lg max-w-2xl mx-auto">
              We partner with world-class technology companies and regional leaders 
              to deliver the best threat intelligence
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8">
            {partners.map((partner) => (
              <div
                key={partner.name}
                className="h-24 bg-card-dark rounded-2xl border border-white/10 flex items-center justify-center p-6 hover:border-primary/30 transition-colors"
              >
                <span className="text-white/40 font-semibold text-lg">{partner.name}</span>
              </div>
            ))}
          </div>

          <div className="mt-16 text-center">
            <p className="text-white/40 text-sm mb-4">Investors</p>
            <div className="flex flex-wrap justify-center gap-8">
              <span className="text-white/60">TLcom Capital</span>
              <span className="text-white/30">|</span>
              <span className="text-white/60">Partech Africa</span>
              <span className="text-white/30">|</span>
              <span className="text-white/60">Novastar Ventures</span>
              <span className="text-white/30">|</span>
              <span className="text-white/60">Future Africa</span>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="relative p-12 rounded-3xl bg-gradient-to-r from-primary/20 via-card-dark to-purple-600/20 border border-white/10 overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-primary/20 rounded-full blur-[100px]" />
            <div className="absolute bottom-0 left-0 w-64 h-64 bg-purple-600/20 rounded-full blur-[80px]" />
            
            <div className="relative z-10 text-center">
              <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
                Join Our Mission
              </h2>
              <p className="text-xl text-white/60 max-w-2xl mx-auto mb-8">
                Whether you&apos;re looking to protect your organization or build your career in 
                cybersecurity, we&apos;d love to hear from you.
              </p>
              <div className="flex flex-wrap justify-center gap-4">
                <Link
                  href="/contact"
                  className="px-8 py-4 bg-primary hover:bg-primary-hover text-white font-semibold rounded-full transition-all shadow-lg shadow-primary/25"
                >
                  Contact Us
                </Link>
                <Link
                  href="/careers"
                  className="px-8 py-4 bg-white/10 hover:bg-white/20 text-white font-semibold rounded-full border border-white/10 transition-all"
                >
                  View Careers
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
