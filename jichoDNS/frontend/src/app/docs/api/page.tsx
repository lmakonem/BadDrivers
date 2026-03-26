"use client";

import { useState } from "react";
import Link from "next/link";
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import { 
  Key, 
  Lock, 
  Gauge, 
  Code, 
  Copy, 
  Check,
  ChevronRight,
  AlertTriangle,
  Globe,
  Search,
  Shield,
  Activity,
  FileJson
} from "lucide-react";

type CodeLanguage = "curl" | "python" | "javascript";

const endpoints = [
  {
    method: "GET",
    path: "/v1/indicators",
    description: "List threat indicators (IOCs)",
    category: "Indicators"
  },
  {
    method: "GET",
    path: "/v1/indicators/{id}",
    description: "Get a specific indicator by ID",
    category: "Indicators"
  },
  {
    method: "POST",
    path: "/v1/indicators/search",
    description: "Search indicators with filters",
    category: "Indicators"
  },
  {
    method: "POST",
    path: "/v1/indicators/bulk",
    description: "Bulk lookup multiple IOCs",
    category: "Indicators"
  },
  {
    method: "GET",
    path: "/v1/threats",
    description: "List active threat campaigns",
    category: "Threats"
  },
  {
    method: "GET",
    path: "/v1/threats/{id}",
    description: "Get threat campaign details",
    category: "Threats"
  },
  {
    method: "GET",
    path: "/v1/threats/{id}/indicators",
    description: "Get indicators for a threat",
    category: "Threats"
  },
  {
    method: "GET",
    path: "/v1/regions",
    description: "Get regional threat scores",
    category: "Regions"
  },
  {
    method: "GET",
    path: "/v1/regions/{country_code}",
    description: "Get threats for a specific country",
    category: "Regions"
  },
  {
    method: "GET",
    path: "/v1/regions/{country_code}/asns",
    description: "Get ASN breakdown for country",
    category: "Regions"
  },
  {
    method: "POST",
    path: "/v1/analysis/domain",
    description: "Analyze a domain for threats",
    category: "Analysis"
  },
  {
    method: "POST",
    path: "/v1/analysis/url",
    description: "Analyze a URL for threats",
    category: "Analysis"
  },
  {
    method: "POST",
    path: "/v1/analysis/ip",
    description: "Analyze an IP address",
    category: "Analysis"
  },
  {
    method: "GET",
    path: "/v1/analysis/{job_id}",
    description: "Get analysis job status/results",
    category: "Analysis"
  }
];

const codeExamples: Record<string, Record<CodeLanguage, string>> = {
  authentication: {
    curl: `curl -X GET "https://api.jichosec.io/v1/indicators" \\
  -H "Authorization: Bearer js_live_abc123xyz789" \\
  -H "Content-Type: application/json"`,
    python: `import requests

API_KEY = "js_live_abc123xyz789"
BASE_URL = "https://api.jichosec.io/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

response = requests.get(f"{BASE_URL}/indicators", headers=headers)
data = response.json()`,
    javascript: `const API_KEY = 'js_live_abc123xyz789';
const BASE_URL = 'https://api.jichosec.io/v1';

const response = await fetch(\`\${BASE_URL}/indicators\`, {
  headers: {
    'Authorization': \`Bearer \${API_KEY}\`,
    'Content-Type': 'application/json'
  }
});

const data = await response.json();`
  },
  listIndicators: {
    curl: `curl -X GET "https://api.jichosec.io/v1/indicators?type=domain&threat_type=phishing&limit=50" \\
  -H "Authorization: Bearer js_live_abc123xyz789"`,
    python: `import requests

response = requests.get(
    "https://api.jichosec.io/v1/indicators",
    headers={"Authorization": f"Bearer {API_KEY}"},
    params={
        "type": "domain",
        "threat_type": "phishing",
        "limit": 50
    }
)

indicators = response.json()["data"]
for ioc in indicators:
    print(f"{ioc['value']} - Risk: {ioc['risk_score']}")`,
    javascript: `const params = new URLSearchParams({
  type: 'domain',
  threat_type: 'phishing',
  limit: '50'
});

const response = await fetch(
  \`https://api.jichosec.io/v1/indicators?\${params}\`,
  { headers: { 'Authorization': \`Bearer \${API_KEY}\` } }
);

const { data: indicators } = await response.json();
indicators.forEach(ioc => {
  console.log(\`\${ioc.value} - Risk: \${ioc.risk_score}\`);
});`
  },
  analyzeDomain: {
    curl: `curl -X POST "https://api.jichosec.io/v1/analysis/domain" \\
  -H "Authorization: Bearer js_live_abc123xyz789" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain": "suspicious-site.example.com",
    "deep_scan": true
  }'`,
    python: `import requests

response = requests.post(
    "https://api.jichosec.io/v1/analysis/domain",
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    },
    json={
        "domain": "suspicious-site.example.com",
        "deep_scan": True
    }
)

result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Threat Type: {result['threat_type']}")
print(f"DGA Score: {result['dga_score']}")`,
    javascript: `const response = await fetch('https://api.jichosec.io/v1/analysis/domain', {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${API_KEY}\`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    domain: 'suspicious-site.example.com',
    deep_scan: true
  })
});

const result = await response.json();
console.log(\`Risk Score: \${result.risk_score}\`);
console.log(\`Threat Type: \${result.threat_type}\`);`
  },
  bulkLookup: {
    curl: `curl -X POST "https://api.jichosec.io/v1/indicators/bulk" \\
  -H "Authorization: Bearer js_live_abc123xyz789" \\
  -H "Content-Type: application/json" \\
  -d '{
    "indicators": [
      "malicious-domain1.com",
      "192.168.1.100",
      "evil-phishing-site.net"
    ]
  }'`,
    python: `import requests

indicators_to_check = [
    "malicious-domain1.com",
    "192.168.1.100",
    "evil-phishing-site.net"
]

response = requests.post(
    "https://api.jichosec.io/v1/indicators/bulk",
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    },
    json={"indicators": indicators_to_check}
)

results = response.json()["data"]
for item in results:
    if item["found"]:
        print(f"THREAT: {item['indicator']} - {item['threat_type']}")`,
    javascript: `const indicatorsToCheck = [
  'malicious-domain1.com',
  '192.168.1.100',
  'evil-phishing-site.net'
];

const response = await fetch('https://api.jichosec.io/v1/indicators/bulk', {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${API_KEY}\`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ indicators: indicatorsToCheck })
});

const { data: results } = await response.json();
results.filter(r => r.found).forEach(item => {
  console.log(\`THREAT: \${item.indicator} - \${item.threat_type}\`);
});`
  }
};

function CodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-2 rounded-lg bg-white/5 hover:bg-white/10 text-white/50 hover:text-white transition-all opacity-0 group-hover:opacity-100"
      >
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </button>
      <pre className="bg-card-light rounded-xl p-4 overflow-x-auto">
        <code className="text-sm text-white/80 font-mono">{code}</code>
      </pre>
      <div className="absolute bottom-3 right-3 text-xs text-white/30 uppercase">
        {language}
      </div>
    </div>
  );
}

function CodeTabs({ examples }: { examples: Record<CodeLanguage, string> }) {
  const [activeTab, setActiveTab] = useState<CodeLanguage>("curl");
  const tabs: CodeLanguage[] = ["curl", "python", "javascript"];

  return (
    <div>
      <div className="flex gap-2 mb-4">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === tab
                ? "bg-primary text-white"
                : "bg-white/5 text-white/60 hover:bg-white/10 hover:text-white"
            }`}
          >
            {tab === "curl" ? "cURL" : tab === "javascript" ? "JavaScript" : "Python"}
          </button>
        ))}
      </div>
      <CodeBlock code={examples[activeTab]} language={activeTab} />
    </div>
  );
}

function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: "bg-green-500/20 text-green-400 border-green-500/30",
    POST: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    PUT: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    DELETE: "bg-red-500/20 text-red-400 border-red-500/30"
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium border ${colors[method] || colors.GET}`}>
      {method}
    </span>
  );
}

export default function APIDocsPage() {
  const categories = Array.from(new Set(endpoints.map(e => e.category)));

  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />
      
      {/* Hero Section */}
      <section className="pt-40 pb-16 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-blue-500/5 via-transparent to-transparent" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[120px]" />
        
        <div className="max-w-[1680px] mx-auto px-8 relative z-10">
          <div className="flex items-center gap-2 text-white/60 mb-6">
            <Link href="/" className="hover:text-white transition-colors">Home</Link>
            <ChevronRight className="w-4 h-4" />
            <Link href="/docs" className="hover:text-white transition-colors">Docs</Link>
            <ChevronRight className="w-4 h-4" />
            <span className="text-white">API Reference</span>
          </div>
          
          <div className="max-w-3xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-xl bg-blue-500/20 flex items-center justify-center">
                <Code className="w-6 h-6 text-blue-400" />
              </div>
              <h1 className="text-4xl lg:text-5xl font-bold text-white">
                API Reference
              </h1>
            </div>
            <p className="text-xl text-white/60 mb-6">
              Complete API documentation for JichoSec. Query threat intelligence, analyze domains, 
              and integrate real-time threat data into your security operations.
            </p>
            
            <div className="flex items-center gap-6 text-sm">
              <div className="flex items-center gap-2 text-white/60">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                Base URL: <code className="text-white bg-white/10 px-2 py-0.5 rounded">https://api.jichosec.io</code>
              </div>
              <div className="text-white/60">
                Version: <code className="text-white bg-white/10 px-2 py-0.5 rounded">v1</code>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Quick Navigation */}
      <section className="py-8 border-y border-white/10 sticky top-[78px] bg-ebony-950/95 backdrop-blur-md z-40">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-6 overflow-x-auto pb-2">
            <a href="#authentication" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Authentication</a>
            <a href="#rate-limits" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Rate Limits</a>
            <a href="#endpoints" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Endpoints</a>
            <a href="#examples" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Code Examples</a>
            <a href="#responses" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Response Format</a>
            <a href="#errors" className="text-white/60 hover:text-white transition-colors whitespace-nowrap">Error Handling</a>
          </div>
        </div>
      </section>

      {/* Authentication Section */}
      <section id="authentication" className="py-16 border-b border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="grid lg:grid-cols-2 gap-12">
            <div>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
                  <Key className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-2xl font-bold text-white">Authentication</h2>
              </div>
              
              <p className="text-white/60 mb-6">
                JichoSec uses API keys to authenticate requests. You can manage your API keys from 
                your dashboard at <code className="text-white bg-white/10 px-1.5 py-0.5 rounded text-sm">Settings &gt; API Keys</code>.
              </p>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-white mb-2">Bearer Token</h3>
                  <p className="text-white/60 text-sm mb-3">
                    Include your API key in the Authorization header as a Bearer token:
                  </p>
                  <code className="block bg-card-light rounded-lg p-3 text-sm text-white/80 font-mono">
                    Authorization: Bearer js_live_your_api_key
                  </code>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-white mb-2">API Key Types</h3>
                  <div className="space-y-3">
                    <div className="flex items-start gap-3 p-3 rounded-lg bg-card-dark border border-white/10">
                      <div className="w-8 h-8 rounded bg-green-500/20 flex items-center justify-center flex-shrink-0">
                        <span className="text-green-400 text-xs font-bold">L</span>
                      </div>
                      <div>
                        <p className="text-white font-medium">Live Keys <code className="text-xs bg-white/10 px-1.5 py-0.5 rounded ml-2">js_live_*</code></p>
                        <p className="text-white/50 text-sm">Production keys with full access. Use in production environments.</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3 p-3 rounded-lg bg-card-dark border border-white/10">
                      <div className="w-8 h-8 rounded bg-yellow-500/20 flex items-center justify-center flex-shrink-0">
                        <span className="text-yellow-400 text-xs font-bold">T</span>
                      </div>
                      <div>
                        <p className="text-white font-medium">Test Keys <code className="text-xs bg-white/10 px-1.5 py-0.5 rounded ml-2">js_test_*</code></p>
                        <p className="text-white/50 text-sm">Sandbox keys for development. Returns mock data, no rate limits.</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                    <Lock className="w-4 h-4" />
                    OAuth 2.0 (Enterprise)
                  </h3>
                  <p className="text-white/60 text-sm">
                    Enterprise plans support OAuth 2.0 for enhanced security with token refresh 
                    and scoped access. Contact sales for setup assistance.
                  </p>
                </div>
              </div>
            </div>
            
            <div>
              <p className="text-white/60 text-sm mb-4">Authentication Example</p>
              <CodeTabs examples={codeExamples.authentication} />
            </div>
          </div>
        </div>
      </section>

      {/* Rate Limits Section */}
      <section id="rate-limits" className="py-16 border-b border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Gauge className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Rate Limits</h2>
          </div>

          <div className="grid lg:grid-cols-2 gap-8 mb-8">
            <div>
              <p className="text-white/60 mb-6">
                Rate limits are applied per API key. When you exceed your rate limit, 
                the API returns a <code className="text-white bg-white/10 px-1.5 py-0.5 rounded text-sm">429 Too Many Requests</code> response.
              </p>

              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Plan</th>
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Daily Limit</th>
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Rate (per min)</th>
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Burst</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4 text-white">Free</td>
                      <td className="py-3 px-4 text-white">100</td>
                      <td className="py-3 px-4 text-white/60">10</td>
                      <td className="py-3 px-4 text-white/60">5</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4 text-white">Pro</td>
                      <td className="py-3 px-4 text-white">10,000</td>
                      <td className="py-3 px-4 text-white/60">100</td>
                      <td className="py-3 px-4 text-white/60">50</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 text-white">Enterprise</td>
                      <td className="py-3 px-4 text-white">Unlimited</td>
                      <td className="py-3 px-4 text-white/60">1,000</td>
                      <td className="py-3 px-4 text-white/60">200</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Rate Limit Headers</h3>
              <p className="text-white/60 text-sm mb-4">
                Every response includes headers to track your usage:
              </p>
              <div className="bg-card-light rounded-xl p-4 font-mono text-sm space-y-2">
                <div className="flex justify-between">
                  <span className="text-white/60">X-RateLimit-Limit:</span>
                  <span className="text-white">10000</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/60">X-RateLimit-Remaining:</span>
                  <span className="text-white">9847</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/60">X-RateLimit-Reset:</span>
                  <span className="text-white">1710720000</span>
                </div>
              </div>

              <div className="mt-6 p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-yellow-200 font-medium">Best Practice</p>
                    <p className="text-white/60 text-sm mt-1">
                      Implement exponential backoff when receiving 429 responses. 
                      Check the <code className="text-white bg-white/10 px-1 rounded">Retry-After</code> header for wait time.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Endpoints Section */}
      <section id="endpoints" className="py-16 border-b border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Globe className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Endpoint Reference</h2>
          </div>

          <div className="space-y-8">
            {categories.map((category) => (
              <div key={category}>
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                  {category === "Indicators" && <Search className="w-5 h-5 text-primary" />}
                  {category === "Threats" && <Shield className="w-5 h-5 text-primary" />}
                  {category === "Regions" && <Globe className="w-5 h-5 text-primary" />}
                  {category === "Analysis" && <Activity className="w-5 h-5 text-primary" />}
                  {category}
                </h3>
                <div className="space-y-2">
                  {endpoints
                    .filter((e) => e.category === category)
                    .map((endpoint) => (
                      <div
                        key={endpoint.path}
                        className="flex items-center gap-4 p-4 rounded-xl bg-card-dark border border-white/10 hover:border-white/20 transition-colors"
                      >
                        <MethodBadge method={endpoint.method} />
                        <code className="text-white font-mono text-sm flex-1">
                          {endpoint.path}
                        </code>
                        <span className="text-white/50 text-sm hidden md:block">
                          {endpoint.description}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Code Examples Section */}
      <section id="examples" className="py-16 border-b border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Code className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Code Examples</h2>
          </div>

          <div className="space-y-12">
            {/* List Indicators Example */}
            <div>
              <h3 className="text-xl font-semibold text-white mb-2">List Threat Indicators</h3>
              <p className="text-white/60 mb-4">
                Query the indicators endpoint with filters for type, threat category, and pagination.
              </p>
              <CodeTabs examples={codeExamples.listIndicators} />
            </div>

            {/* Analyze Domain Example */}
            <div>
              <h3 className="text-xl font-semibold text-white mb-2">Analyze a Domain</h3>
              <p className="text-white/60 mb-4">
                Submit a domain for deep analysis including DGA detection, typosquatting checks, and threat scoring.
              </p>
              <CodeTabs examples={codeExamples.analyzeDomain} />
            </div>

            {/* Bulk Lookup Example */}
            <div>
              <h3 className="text-xl font-semibold text-white mb-2">Bulk IOC Lookup</h3>
              <p className="text-white/60 mb-4">
                Check multiple indicators at once. Supports up to 100 IOCs per request.
              </p>
              <CodeTabs examples={codeExamples.bulkLookup} />
            </div>
          </div>
        </div>
      </section>

      {/* Response Format Section */}
      <section id="responses" className="py-16 border-b border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <FileJson className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Response Format</h2>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            <div>
              <p className="text-white/60 mb-6">
                All API responses follow a consistent JSON format. List endpoints include pagination metadata.
              </p>

              <h3 className="text-lg font-semibold text-white mb-3">Success Response</h3>
              <pre className="bg-card-light rounded-xl p-4 overflow-x-auto text-sm">
                <code className="text-white/80">
{`{
  "success": true,
  "data": {
    "id": "ioc_8x7f9k2m",
    "type": "domain",
    "value": "malicious.example.com",
    "threat_type": "c2",
    "risk_score": 92,
    "confidence": 0.87,
    "first_seen": "2024-01-10T14:30:00Z",
    "last_seen": "2024-03-15T09:45:00Z",
    "sources": ["abuse.ch", "phishtank"],
    "tags": ["cobalt-strike", "africa"],
    "geo": {
      "country": "KE",
      "asn": 33771,
      "org": "Safaricom Limited"
    }
  }
}`}
                </code>
              </pre>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-white mb-3">List Response with Pagination</h3>
              <pre className="bg-card-light rounded-xl p-4 overflow-x-auto text-sm">
                <code className="text-white/80">
{`{
  "success": true,
  "data": [
    { "id": "ioc_1", "value": "...", ... },
    { "id": "ioc_2", "value": "...", ... }
  ],
  "meta": {
    "total": 15420,
    "page": 1,
    "per_page": 20,
    "total_pages": 771,
    "has_next": true,
    "has_prev": false
  },
  "links": {
    "self": "/v1/indicators?page=1",
    "next": "/v1/indicators?page=2",
    "last": "/v1/indicators?page=771"
  }
}`}
                </code>
              </pre>

              <h3 className="text-lg font-semibold text-white mb-3 mt-6">Threat Types</h3>
              <div className="grid grid-cols-2 gap-2">
                <div className="p-3 rounded-lg bg-card-dark border border-white/10">
                  <code className="text-red-400">c2</code>
                  <p className="text-white/50 text-xs mt-1">Command & Control</p>
                </div>
                <div className="p-3 rounded-lg bg-card-dark border border-white/10">
                  <code className="text-orange-400">phishing</code>
                  <p className="text-white/50 text-xs mt-1">Phishing/Credential Theft</p>
                </div>
                <div className="p-3 rounded-lg bg-card-dark border border-white/10">
                  <code className="text-yellow-400">malware</code>
                  <p className="text-white/50 text-xs mt-1">Malware Distribution</p>
                </div>
                <div className="p-3 rounded-lg bg-card-dark border border-white/10">
                  <code className="text-purple-400">exfiltration</code>
                  <p className="text-white/50 text-xs mt-1">Data Exfiltration</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Error Handling Section */}
      <section id="errors" className="py-16">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <h2 className="text-2xl font-bold text-white">Error Handling</h2>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            <div>
              <p className="text-white/60 mb-6">
                JichoSec uses conventional HTTP response codes. Codes in the 2xx range indicate success, 
                4xx indicate client errors, and 5xx indicate server errors.
              </p>

              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Code</th>
                      <th className="text-left py-3 px-4 text-white/60 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-green-400">200</code></td>
                      <td className="py-3 px-4 text-white/60">Success</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-green-400">201</code></td>
                      <td className="py-3 px-4 text-white/60">Created</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-yellow-400">400</code></td>
                      <td className="py-3 px-4 text-white/60">Bad Request - Invalid parameters</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-yellow-400">401</code></td>
                      <td className="py-3 px-4 text-white/60">Unauthorized - Invalid API key</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-yellow-400">403</code></td>
                      <td className="py-3 px-4 text-white/60">Forbidden - Insufficient permissions</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-yellow-400">404</code></td>
                      <td className="py-3 px-4 text-white/60">Not Found - Resource doesn&apos;t exist</td>
                    </tr>
                    <tr className="border-b border-white/5">
                      <td className="py-3 px-4"><code className="text-orange-400">429</code></td>
                      <td className="py-3 px-4 text-white/60">Too Many Requests - Rate limited</td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4"><code className="text-red-400">500</code></td>
                      <td className="py-3 px-4 text-white/60">Internal Server Error</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-white mb-3">Error Response Format</h3>
              <pre className="bg-card-light rounded-xl p-4 overflow-x-auto text-sm">
                <code className="text-white/80">
{`{
  "success": false,
  "error": {
    "code": "invalid_api_key",
    "message": "The API key provided is invalid or expired.",
    "details": {
      "key_prefix": "js_live_abc...",
      "suggestion": "Generate a new API key from your dashboard."
    }
  },
  "request_id": "req_7x9k2mf8n3"
}`}
                </code>
              </pre>

              <div className="mt-6 p-4 rounded-xl bg-blue-500/10 border border-blue-500/20">
                <p className="text-blue-200 font-medium mb-2">Debugging Tips</p>
                <ul className="text-white/60 text-sm space-y-1">
                  <li>- Include <code className="text-white bg-white/10 px-1 rounded">request_id</code> when contacting support</li>
                  <li>- Check the <code className="text-white bg-white/10 px-1 rounded">details</code> object for actionable suggestions</li>
                  <li>- Enable verbose logging in development with test keys</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Navigation Footer */}
      <section className="py-12 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6">
            <Link 
              href="/docs"
              className="flex items-center gap-2 text-white/60 hover:text-white transition-colors"
            >
              <ChevronRight className="w-4 h-4 rotate-180" />
              Back to Documentation
            </Link>
            <Link 
              href="/docs/integration"
              className="flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary-hover text-white font-medium rounded-full transition-all"
            >
              Integration Guides
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
