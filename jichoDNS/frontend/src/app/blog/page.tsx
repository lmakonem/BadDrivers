import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import Link from "next/link";

const categories = [
  { name: "Threat Intelligence" },
  { name: "Mobile Money Fraud" },
  { name: "Phishing" },
  { name: "Malware Analysis" },
  { name: "Industry News" },
  { name: "Product Updates" },
  { name: "Research" },
];

const featuredPost = {
  title: "The Rise of Mobile Money Fraud in East Africa: A 2026 Analysis",
  excerpt:
    "A look at phishing campaigns targeting M-Pesa, Airtel Money, and other mobile money platforms — and how organizations can protect their customers.",
  author: "JichoSec Research",
  role: "Threat Research",
  date: "March 15, 2026",
  readTime: "12 min read",
  category: "Research",
  image: "/blog/mobile-money-fraud.jpg",
  href: "#",
};

const blogPosts = [
  {
    title: "Detecting Domain Generation Algorithms in African Botnet Infrastructure",
    excerpt:
      "How ML models identify DGA domains, and what this means for detecting C2 infrastructure targeting African organizations.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "March 10, 2026",
    readTime: "8 min read",
    category: "Threat Intelligence",
    href: "#",
  },
  {
    title: "Inside the 'Lagos Phishers': Tracking a Nigerian Cybercrime Group",
    excerpt:
      "A deep dive into the tactics, techniques, and procedures of a prolific phishing group targeting financial institutions across West Africa.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "March 5, 2026",
    readTime: "15 min read",
    category: "Research",
    href: "#",
  },
  {
    title: "How Typosquatting Campaigns Target African Banks",
    excerpt:
      "How lookalike domains impersonate major African banks — and how to protect your organization and customers.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "February 28, 2026",
    readTime: "6 min read",
    category: "Phishing",
    href: "#",
  },
  {
    title: "Integrating JichoSec with Your SIEM: A Technical Guide",
    excerpt:
      "Step-by-step instructions for integrating our threat intelligence feeds with Splunk, Microsoft Sentinel, and Elastic Security.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "February 20, 2026",
    readTime: "10 min read",
    category: "Product Updates",
    href: "#",
  },
  {
    title: "Q1 2026 African Threat Landscape Report",
    excerpt:
      "Key findings from our quarterly analysis of cyber threats across the continent, including emerging trends and regional hotspots.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "February 15, 2026",
    readTime: "20 min read",
    category: "Research",
    href: "#",
  },
  {
    title: "Understanding DNS-Based Data Exfiltration in African Enterprises",
    excerpt:
      "How attackers use DNS tunneling to steal data, and how our platform detects these stealthy exfiltration techniques in real-time.",
    author: "JichoSec Research",
    role: "Threat Research",
    date: "February 8, 2026",
    readTime: "11 min read",
    category: "Threat Intelligence",
    href: "#",
  },
];

export default function BlogPage() {
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
              JichoSec Blog
            </span>
            <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
              Threat Intelligence &{" "}
              <span className="bg-gradient-to-r from-primary to-purple-500 bg-clip-text text-transparent">
                Security Insights
              </span>
            </h1>
            <p className="text-xl text-white/60 max-w-2xl mx-auto">
              Sample articles previewing the analysis and research we&apos;ll publish.
              Our blog launches soon.
            </p>
          </div>
        </div>
      </section>

      {/* Featured Post */}
      <section className="py-12">
        <div className="max-w-[1680px] mx-auto px-8">
          <Link
            href={featuredPost.href}
            className="block bg-gradient-to-r from-card-dark to-card-light rounded-3xl border border-white/10 overflow-hidden hover:border-primary/30 transition-colors group"
          >
            <div className="grid lg:grid-cols-2 gap-8">
              <div className="aspect-video lg:aspect-auto bg-gradient-to-br from-primary/20 to-purple-600/20 flex items-center justify-center">
                <div className="text-center p-8">
                  <span className="inline-block px-3 py-1 rounded-full bg-primary/20 text-primary text-sm font-medium mb-4">
                    Featured
                  </span>
                  <div className="w-24 h-24 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto">
                    <svg className="w-12 h-12 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                  </div>
                </div>
              </div>
              <div className="p-8 lg:p-12 flex flex-col justify-center">
                <div className="flex items-center gap-3 mb-4">
                  <span className="px-3 py-1 rounded-full bg-primary/10 text-primary text-sm font-medium">
                    {featuredPost.category}
                  </span>
                  <span className="text-white/40 text-sm">{featuredPost.readTime}</span>
                </div>
                <h2 className="text-2xl lg:text-3xl font-bold text-white mb-4 group-hover:text-primary transition-colors">
                  {featuredPost.title}
                </h2>
                <p className="text-white/60 mb-6">{featuredPost.excerpt}</p>
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-br from-primary/20 to-purple-600/20 flex items-center justify-center">
                    <span className="text-white font-semibold">
                      {featuredPost.author.split(" ").map(n => n[0]).join("")}
                    </span>
                  </div>
                  <div>
                    <p className="text-white font-medium">{featuredPost.author}</p>
                    <p className="text-white/50 text-sm">
                      {featuredPost.role} · {featuredPost.date}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </Link>
        </div>
      </section>

      {/* Blog Grid with Sidebar */}
      <section className="py-12">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-4 gap-12">
            {/* Sidebar */}
            <div className="lg:col-span-1 order-2 lg:order-1">
              <div className="sticky top-32 space-y-8">
                {/* Categories */}
                <div className="bg-card-dark rounded-2xl border border-white/10 p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Categories</h3>
                  <ul className="space-y-3">
                    {categories.map((category) => (
                      <li key={category.name}>
                        <Link
                          href="#"
                          className="flex items-center justify-between text-white/60 hover:text-white transition-colors group"
                        >
                          <span className="group-hover:text-primary transition-colors">
                            {category.name}
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Newsletter */}
                <div className="bg-gradient-to-br from-primary/10 to-purple-600/10 rounded-2xl border border-white/10 p-6">
                  <h3 className="text-lg font-semibold text-white mb-2">
                    Stay Updated
                  </h3>
                  <p className="text-white/60 text-sm mb-4">
                    Get the latest threat intelligence delivered to your inbox weekly.
                  </p>
                  <form className="space-y-3">
                    <input
                      type="email"
                      placeholder="you@company.com"
                      className="w-full px-4 py-2.5 rounded-lg bg-card-dark border border-white/10 text-white placeholder-white/40 focus:outline-none focus:border-primary transition-colors text-sm"
                    />
                    <button
                      type="submit"
                      className="w-full px-4 py-2.5 bg-primary hover:bg-primary-hover text-white font-medium rounded-lg transition-colors text-sm"
                    >
                      Subscribe
                    </button>
                  </form>
                </div>

                {/* Popular Tags */}
                <div className="bg-card-dark rounded-2xl border border-white/10 p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Popular Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {["M-Pesa", "Phishing", "DGA", "APT", "Ransomware", "C2", "Nigeria", "Kenya", "Banks", "SIEM"].map((tag) => (
                      <Link
                        key={tag}
                        href="#"
                        className="px-3 py-1.5 rounded-full bg-card-light text-white/60 text-sm hover:bg-primary/10 hover:text-primary transition-colors"
                      >
                        {tag}
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Blog Posts Grid */}
            <div className="lg:col-span-3 order-1 lg:order-2">
              <div className="grid md:grid-cols-2 gap-8">
                {blogPosts.map((post) => (
                  <Link
                    key={post.title}
                    href={post.href}
                    className="bg-card-dark rounded-2xl border border-white/10 overflow-hidden hover:border-primary/30 transition-colors group"
                  >
                    {/* Thumbnail Placeholder */}
                    <div className="aspect-video bg-gradient-to-br from-card-light to-card-dark flex items-center justify-center">
                      <div className="w-16 h-16 rounded-xl bg-primary/10 flex items-center justify-center">
                        <svg className="w-8 h-8 text-primary/50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                          <circle cx="8.5" cy="8.5" r="1.5"/>
                          <polyline points="21,15 16,10 5,21"/>
                        </svg>
                      </div>
                    </div>
                    
                    <div className="p-6">
                      <div className="flex items-center gap-3 mb-3">
                        <span className="px-2.5 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-medium">
                          {post.category}
                        </span>
                        <span className="text-white/40 text-xs">{post.readTime}</span>
                      </div>
                      <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-primary transition-colors line-clamp-2">
                        {post.title}
                      </h3>
                      <p className="text-white/50 text-sm mb-4 line-clamp-2">
                        {post.excerpt}
                      </p>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary/20 to-purple-600/20 flex items-center justify-center">
                          <span className="text-white text-xs font-semibold">
                            {post.author.split(" ").map(n => n[0]).join("").slice(0, 2)}
                          </span>
                        </div>
                        <div>
                          <p className="text-white text-sm font-medium">{post.author}</p>
                          <p className="text-white/40 text-xs">{post.date}</p>
                        </div>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>

              {/* Load More */}
              <div className="mt-12 text-center">
                <button
                  disabled
                  className="px-8 py-3 bg-white/5 text-white/40 font-medium rounded-full border border-white/10 cursor-not-allowed">
                  More articles coming soon
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
