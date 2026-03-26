import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import Link from "next/link";

export default function TermsPage() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />

      {/* Hero Section */}
      <section className="relative pt-40 pb-12 overflow-hidden">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] bg-primary/10 rounded-full blur-[150px]" />
        
        <div className="relative z-10 max-w-[1680px] mx-auto px-8">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Terms of Service
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
                  <h2 className="text-2xl font-bold text-white mb-4">1. Acceptance of Terms</h2>
                  <p>
                    These Terms of Service (&quot;Terms&quot;) govern your access to and use of the JichoSec 
                    threat intelligence platform and services (&quot;Services&quot;) provided by JichoSec Limited 
                    (&quot;JichoSec&quot;, &quot;we&quot;, &quot;us&quot;, or &quot;our&quot;), a company registered in Kenya.
                  </p>
                  <p>
                    By accessing or using our Services, you agree to be bound by these Terms. If you do not 
                    agree to these Terms, you may not access or use the Services. If you are using the Services 
                    on behalf of an organization, you represent and warrant that you have the authority to bind 
                    that organization to these Terms.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">2. Description of Services</h2>
                  <p className="mb-4">
                    JichoSec provides cyber threat intelligence services including, but not limited to:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Real-time threat intelligence feeds</li>
                    <li>DNS threat analysis and monitoring</li>
                    <li>Domain reputation and risk scoring</li>
                    <li>Typosquatting and brand impersonation detection</li>
                    <li>Dark web monitoring</li>
                    <li>API access for SIEM/SOAR integration</li>
                    <li>Threat reports and analysis</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">3. Account Registration</h2>
                  <p className="mb-4">
                    To access certain features of the Services, you must register for an account. When registering, you agree to:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Provide accurate, current, and complete information</li>
                    <li>Maintain and update your information as needed</li>
                    <li>Maintain the security of your account credentials</li>
                    <li>Notify us immediately of any unauthorized access</li>
                    <li>Accept responsibility for all activities under your account</li>
                  </ul>
                  <p className="mt-4">
                    We reserve the right to suspend or terminate accounts that violate these Terms or engage 
                    in fraudulent or harmful activities.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">4. Subscription Plans and Billing</h2>
                  
                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">4.1 Subscription Tiers</h3>
                  <p>
                    We offer various subscription plans (Free, Professional, Enterprise) with different features 
                    and pricing. The specific terms of your subscription are detailed in your Order Form or 
                    subscription confirmation.
                  </p>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">4.2 Billing and Payment</h3>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Paid subscriptions are billed in advance on a monthly or annual basis</li>
                    <li>Payment is due upon invoice or as specified in your Order Form</li>
                    <li>All fees are non-refundable unless otherwise specified</li>
                    <li>We may change pricing with 30 days&apos; notice</li>
                    <li>Late payments may result in service suspension</li>
                  </ul>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">4.3 Automatic Renewal</h3>
                  <p>
                    Subscriptions automatically renew at the end of each billing period unless cancelled 
                    at least 30 days before renewal. You may cancel your subscription through your account 
                    settings or by contacting support.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">5. Acceptable Use</h2>
                  <p className="mb-4">You agree not to use the Services to:</p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Violate any applicable laws or regulations</li>
                    <li>Infringe intellectual property rights of others</li>
                    <li>Transmit malware, viruses, or other malicious code</li>
                    <li>Conduct unauthorized security testing or attacks</li>
                    <li>Interfere with or disrupt the Services or servers</li>
                    <li>Attempt to gain unauthorized access to systems or data</li>
                    <li>Use the Services for competitive analysis against JichoSec</li>
                    <li>Resell or redistribute the Services without authorization</li>
                    <li>Use automated systems to access the Services beyond API limits</li>
                    <li>Facilitate illegal activities or harm others</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">6. API Terms</h2>
                  <p className="mb-4">If you access the Services via our API, you additionally agree to:</p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>Comply with all rate limits and usage quotas for your subscription tier</li>
                    <li>Keep your API keys confidential and secure</li>
                    <li>Not share API credentials with unauthorized parties</li>
                    <li>Use appropriate caching to minimize redundant requests</li>
                    <li>Attribute JichoSec in any public-facing applications using our data</li>
                    <li>Not use the API in ways that could harm or degrade the Services</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">7. Intellectual Property</h2>
                  
                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">7.1 Our Rights</h3>
                  <p>
                    The Services, including all content, features, and functionality, are owned by JichoSec 
                    and are protected by copyright, trademark, and other intellectual property laws. You may 
                    not copy, modify, distribute, sell, or lease any part of the Services without our prior 
                    written consent.
                  </p>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">7.2 License Grant</h3>
                  <p>
                    Subject to these Terms, we grant you a limited, non-exclusive, non-transferable, 
                    revocable license to access and use the Services for your internal business purposes 
                    during your subscription period.
                  </p>

                  <h3 className="text-lg font-semibold text-white mt-6 mb-3">7.3 Threat Intelligence Data</h3>
                  <p>
                    Threat intelligence data provided through the Services is licensed, not sold. You may 
                    use this data for your internal security operations. You may not redistribute, resell, 
                    or publicly disclose the raw data feeds without written permission.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">8. Confidentiality</h2>
                  <p>
                    Both parties agree to maintain the confidentiality of any confidential information 
                    disclosed during the course of the relationship. Confidential information includes, 
                    but is not limited to, technical data, business plans, customer information, and 
                    proprietary threat intelligence methodologies.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">9. Disclaimer of Warranties</h2>
                  <p className="mb-4">
                    THE SERVICES ARE PROVIDED &quot;AS IS&quot; AND &quot;AS AVAILABLE&quot; WITHOUT WARRANTIES OF ANY KIND, 
                    EITHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE</li>
                    <li>NON-INFRINGEMENT</li>
                    <li>ACCURACY, COMPLETENESS, OR RELIABILITY OF CONTENT</li>
                    <li>UNINTERRUPTED OR ERROR-FREE SERVICE</li>
                    <li>SECURITY OF DATA TRANSMITTED</li>
                  </ul>
                  <p className="mt-4">
                    Threat intelligence is provided for informational purposes. We do not guarantee that 
                    the Services will detect all threats or that relying on the Services will prevent all 
                    security incidents.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">10. Limitation of Liability</h2>
                  <p className="mb-4">
                    TO THE MAXIMUM EXTENT PERMITTED BY LAW, JICHOSEC SHALL NOT BE LIABLE FOR:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES</li>
                    <li>LOSS OF PROFITS, DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES</li>
                    <li>DAMAGES RESULTING FROM SECURITY BREACHES OR CYBER ATTACKS</li>
                    <li>DAMAGES EXCEEDING THE FEES PAID IN THE 12 MONTHS PRECEDING THE CLAIM</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">11. Indemnification</h2>
                  <p>
                    You agree to indemnify, defend, and hold harmless JichoSec and its officers, directors, 
                    employees, agents, and affiliates from any claims, damages, losses, liabilities, and 
                    expenses (including reasonable attorneys&apos; fees) arising out of or related to your use 
                    of the Services, violation of these Terms, or infringement of any third-party rights.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">12. Service Level Agreement</h2>
                  <p className="mb-4">
                    For Enterprise customers, service levels are defined in the applicable Service Level 
                    Agreement (SLA). For all other customers:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>We target 99.9% uptime for the platform</li>
                    <li>Scheduled maintenance is performed with advance notice</li>
                    <li>Support response times vary by subscription tier</li>
                    <li>No uptime guarantees are provided for free tier accounts</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">13. Termination</h2>
                  <p className="mb-4">
                    Either party may terminate the subscription:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>For convenience, with 30 days&apos; written notice</li>
                    <li>Immediately, if the other party materially breaches these Terms and fails to cure within 30 days</li>
                    <li>Immediately, if the other party becomes insolvent or bankrupt</li>
                  </ul>
                  <p className="mt-4">
                    Upon termination, your access to the Services will cease, and we may delete your data 
                    after 90 days. You remain responsible for any fees incurred before termination.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">14. Changes to Terms</h2>
                  <p>
                    We may modify these Terms at any time. We will provide notice of material changes via 
                    email or through the Services. Your continued use of the Services after such changes 
                    constitutes acceptance of the updated Terms. If you do not agree to the changes, you 
                    must stop using the Services.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">15. Governing Law and Disputes</h2>
                  <p className="mb-4">
                    These Terms are governed by the laws of Kenya. Any disputes arising from or related to 
                    these Terms or the Services shall be resolved as follows:
                  </p>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li>First, through good-faith negotiation between the parties</li>
                    <li>If unresolved within 30 days, through mediation in Nairobi, Kenya</li>
                    <li>If mediation fails, through arbitration under the Nairobi Centre for International Arbitration Rules</li>
                  </ul>
                  <p className="mt-4">
                    The parties agree to submit to the exclusive jurisdiction of the courts of Kenya for 
                    any matters not subject to arbitration.
                  </p>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">16. General Provisions</h2>
                  <ul className="list-disc list-inside space-y-2 ml-4">
                    <li><strong className="text-white">Entire Agreement:</strong> These Terms constitute the entire agreement between you and JichoSec regarding the Services.</li>
                    <li><strong className="text-white">Severability:</strong> If any provision is found unenforceable, the remaining provisions remain in effect.</li>
                    <li><strong className="text-white">Waiver:</strong> Failure to enforce any provision does not constitute a waiver of that provision.</li>
                    <li><strong className="text-white">Assignment:</strong> You may not assign these Terms without our consent. We may assign these Terms freely.</li>
                    <li><strong className="text-white">Force Majeure:</strong> Neither party is liable for delays due to events beyond reasonable control.</li>
                  </ul>
                </section>

                <section>
                  <h2 className="text-2xl font-bold text-white mb-4">17. Contact Information</h2>
                  <p className="mb-4">
                    For questions about these Terms or the Services, please contact us:
                  </p>
                  <div className="bg-card-light rounded-xl p-6 space-y-2">
                    <p><strong className="text-white">JichoSec Limited</strong></p>
                    <p>Legal Department</p>
                    <p>Westlands Business Park, Tower B, 14th Floor</p>
                    <p>Waiyaki Way, Westlands</p>
                    <p>Nairobi, Kenya</p>
                    <p className="pt-2">
                      Email: <a href="mailto:legal@jichosec.com" className="text-primary hover:underline">legal@jichosec.com</a>
                    </p>
                    <p>
                      Phone: <a href="tel:+254201234567" className="text-primary hover:underline">+254 20 123 4567</a>
                    </p>
                  </div>
                </section>
              </div>
            </div>
          </div>

          {/* Related Links */}
          <div className="mt-8 flex flex-wrap gap-4 justify-center">
            <Link
              href="/privacy"
              className="px-6 py-3 bg-card-dark hover:bg-card-light text-white font-medium rounded-full border border-white/10 transition-colors"
            >
              Privacy Policy
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
