import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import Link from "next/link";

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />

      {/* Hero Section */}
      <section className="relative pt-40 pb-12 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/10 rounded-full blur-[150px]" />
        
        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Privacy Policy
            </h1>
            <p className="text-white/60">
              Last updated: March 1, 2026
            </p>
          </div>
        </div>
      </section>

      {/* Content */}
      <section className="py-12">
        <div className="max-w-4xl mx-auto px-8">
          <div className="bg-card-dark rounded-2xl border border-white/10 p-8 lg:p-12">
            <div className="prose prose-invert max-w-none">
              <div className="space-y-8 text-white/70">
                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">1. Introduction</h2>
                  <p>
                    JichoSec Limited (&quot;JichoSec&quot;, &quot;we&quot;, &quot;us&quot;, or &quot;our&quot;) is committed to protecting 
                    your privacy. This Privacy Policy explains how we collect, use, disclose, and safeguard 
                    your information when you use our threat intelligence platform and services.
                  </p>
                  <p>
                    We are headquartered in Nairobi, Kenya, with operations across Africa. We comply with 
                    applicable data protection laws including the Kenya Data Protection Act 2019, the 
                    Nigerian Data Protection Regulation (NDPR), South Africa&apos;s Protection of Personal 
                    Information Act (POPIA), and the EU General Data Protection Regulation (GDPR) where applicable.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">2. Information We Collect</h2>
                  
                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">2.1 Information You Provide</h3>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Account registration information (name, email, company, phone number)</li>
                    <li>Billing and payment information</li>
                    <li>Communications you send to us (support tickets, emails, feedback)</li>
                    <li>Survey responses and feedback</li>
                    <li>Information submitted through contact forms</li>
                  </ul>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">2.2 Information Collected Automatically</h3>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Device information (IP address, browser type, operating system)</li>
                    <li>Usage data (features accessed, queries made, time spent)</li>
                    <li>Log data and analytics</li>
                    <li>Cookies and similar tracking technologies</li>
                  </ul>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">2.3 Threat Intelligence Data</h3>
                  <p>
                    Our platform processes threat intelligence data including DNS queries, domain information, 
                    IP addresses, and indicators of compromise (IOCs). This data is processed to provide our 
                    threat detection services and is not linked to individual users unless you configure your 
                    systems to send us such data.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">3. How We Use Your Information</h2>
                  <p className="mb-4">We use the information we collect to:</p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Provide, maintain, and improve our services</li>
                    <li>Process transactions and send related information</li>
                    <li>Send technical notices, updates, security alerts, and support messages</li>
                    <li>Respond to your comments, questions, and customer service requests</li>
                    <li>Communicate about products, services, offers, and events</li>
                    <li>Monitor and analyze trends, usage, and activities</li>
                    <li>Detect, investigate, and prevent fraudulent transactions and abuse</li>
                    <li>Personalize and improve your experience</li>
                    <li>Comply with legal obligations</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">4. Legal Basis for Processing (GDPR)</h2>
                  <p className="mb-4">For users in the European Economic Area, we process personal data based on:</p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li><strong className="text-white">Contract:</strong> Processing necessary to provide our services</li>
                    <li><strong className="text-white">Legitimate Interest:</strong> Processing for fraud prevention, security, and service improvement</li>
                    <li><strong className="text-white">Consent:</strong> Processing for marketing communications (which you can withdraw at any time)</li>
                    <li><strong className="text-white">Legal Obligation:</strong> Processing required by applicable law</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">5. Information Sharing and Disclosure</h2>
                  <p className="mb-4">We may share your information in the following circumstances:</p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li><strong className="text-white">Service Providers:</strong> Third-party vendors who perform services on our behalf (hosting, analytics, payment processing)</li>
                    <li><strong className="text-white">Business Transfers:</strong> In connection with a merger, acquisition, or sale of assets</li>
                    <li><strong className="text-white">Legal Requirements:</strong> To comply with legal obligations, court orders, or government requests</li>
                    <li><strong className="text-white">Protection of Rights:</strong> To protect the rights, privacy, safety, or property of JichoSec, our users, or the public</li>
                    <li><strong className="text-white">With Consent:</strong> With your explicit consent for any other purposes</li>
                  </ul>
                  <p className="mt-4">
                    We do not sell your personal information to third parties.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">6. Data Retention</h2>
                  <p>
                    We retain your personal information for as long as necessary to provide our services, 
                    comply with legal obligations, resolve disputes, and enforce our agreements. Account 
                    information is retained for the duration of your account and for 90 days thereafter. 
                    Threat intelligence data is retained according to your subscription tier and our data 
                    retention policies.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">7. Data Security</h2>
                  <p className="mb-4">
                    We implement industry-standard security measures to protect your information, including:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Encryption in transit (TLS 1.3) and at rest (AES-256)</li>
                    <li>Regular security assessments and penetration testing</li>
                    <li>Access controls and authentication requirements</li>
                    <li>Employee security training</li>
                    <li>Incident response procedures</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">8. Your Rights</h2>
                  <p className="mb-4">
                    Depending on your location, you may have the following rights regarding your personal data:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li><strong className="text-white">Access:</strong> Request a copy of your personal data</li>
                    <li><strong className="text-white">Rectification:</strong> Request correction of inaccurate data</li>
                    <li><strong className="text-white">Erasure:</strong> Request deletion of your personal data</li>
                    <li><strong className="text-white">Restriction:</strong> Request limitation of processing</li>
                    <li><strong className="text-white">Portability:</strong> Receive your data in a machine-readable format</li>
                    <li><strong className="text-white">Objection:</strong> Object to certain processing activities</li>
                    <li><strong className="text-white">Withdraw Consent:</strong> Withdraw consent where processing is based on consent</li>
                  </ul>
                  <p className="mt-4">
                    To exercise these rights, contact us at <a href="mailto:privacy@jichosec.com" className="text-primary hover:underline">privacy@jichosec.com</a>.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">9. International Data Transfers</h2>
                  <p>
                    Your information may be transferred to and processed in countries other than your country 
                    of residence. We ensure appropriate safeguards are in place for such transfers, including 
                    Standard Contractual Clauses approved by the European Commission and compliance with 
                    applicable African data protection laws.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">10. Cookies and Tracking</h2>
                  <p className="mb-4">
                    We use cookies and similar technologies to:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Maintain your session and authentication</li>
                    <li>Remember your preferences</li>
                    <li>Analyze usage and improve our services</li>
                    <li>Provide personalized content</li>
                  </ul>
                  <p className="mt-4">
                    You can control cookies through your browser settings. Note that disabling certain cookies 
                    may affect the functionality of our services.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">11. Children&apos;s Privacy</h2>
                  <p>
                    Our services are not directed to individuals under 18 years of age. We do not knowingly 
                    collect personal information from children. If we become aware that we have collected 
                    personal information from a child, we will take steps to delete such information.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">12. Changes to This Policy</h2>
                  <p>
                    We may update this Privacy Policy from time to time. We will notify you of any material 
                    changes by posting the new Privacy Policy on this page and updating the &quot;Last updated&quot; 
                    date. Your continued use of our services after such changes constitutes acceptance of 
                    the updated policy.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">13. Contact Us</h2>
                  <p className="mb-4">
                    If you have questions about this Privacy Policy or our data practices, please contact us:
                  </p>
                  <div className="bg-card-light rounded-xl p-6 space-y-2">
                    <p><strong className="text-white">JichoSec Limited</strong></p>
                    <p>Data Protection Officer</p>
                    <p>Westlands Business Park, Tower B, 14th Floor</p>
                    <p>Waiyaki Way, Westlands</p>
                    <p>Nairobi, Kenya</p>
                    <p className="pt-2">
                      Email: <a href="mailto:privacy@jichosec.com" className="text-primary hover:underline">privacy@jichosec.com</a>
                    </p>
                    <p>
                      Phone: <a href="tel:+254201234567" className="text-primary hover:underline">+254 20 123 4567</a>
                    </p>
                  </div>
                </section>

                <section className="border-t border-white/10 pt-8">
                  <p className="text-white/50 text-sm">
                    For complaints regarding our handling of personal data, you may contact the Office of 
                    the Data Protection Commissioner (Kenya), the National Information Technology Development 
                    Agency (Nigeria), or the Information Regulator (South Africa), as applicable.
                  </p>
                </section>
              </div>
            </div>
          </div>

          {/* Related Links */}
          <div className="mt-8 flex flex-wrap gap-4 justify-center">
            <Link
              href="/terms"
              className="px-6 py-3 bg-card-dark hover:bg-card-light text-white font-medium rounded-full border border-white/10 transition-colors"
            >
              Terms of Service
            </Link>
            <Link
              href="/contact"
              className="px-6 py-3 bg-card-dark hover:bg-card-light text-white font-medium rounded-full border border-white/10 transition-colors"
            >
              Contact Us
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
