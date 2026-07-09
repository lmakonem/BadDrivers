"use client";

import { useState } from "react";
import Link from "next/link";
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import {
  Plug,
  ChevronRight,
  Server,
  Webhook,
  Code,
  Copy,
  Check,
  Shield,
  Zap,
  Package,
  CheckCircle,
  FileCode,
  AlertTriangle
} from "lucide-react";

function CodeBlock({ code, language, title }: { code: string; language: string; title?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group">
      {title && (
        <div className="flex items-center justify-between px-4 py-2 bg-card-dark border-b border-white/10 rounded-t-xl">
          <span className="text-white/60 text-sm">{title}</span>
          <span className="text-white/30 text-xs uppercase">{language}</span>
        </div>
      )}
      <button
        onClick={handleCopy}
        className="absolute top-3 right-3 p-2 rounded-lg bg-white/5 hover:bg-white/10 text-white/50 hover:text-white transition-all opacity-0 group-hover:opacity-100 z-10"
      >
        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      </button>
      <pre className={`bg-card-light p-4 overflow-x-auto ${title ? 'rounded-b-xl' : 'rounded-xl'}`}>
        <code className="text-sm text-white/80 font-mono">{code}</code>
      </pre>
    </div>
  );
}

const siemIntegrations = [
  {
    name: "Splunk",
    logo: "/images/splunk-logo.svg",
    description: "Native Splunk app with dashboards and alert actions",
    features: ["Real-time IOC ingestion", "Custom dashboards", "Alert enrichment", "CIM compliance"],
    setupTime: "15 min"
  },
  {
    name: "IBM QRadar",
    logo: "/images/qradar-logo.svg",
    description: "QRadar app for threat intelligence correlation",
    features: ["Reference set integration", "Custom rules", "Offense enrichment", "Pulse updates"],
    setupTime: "20 min"
  },
  {
    name: "Microsoft Sentinel",
    logo: "/images/sentinel-logo.svg",
    description: "Logic App connector for Azure Sentinel",
    features: ["TI connector", "Workbooks", "Playbooks", "Hunting queries"],
    setupTime: "10 min"
  }
];

const webhookEvents = [
  { event: "indicator.new", description: "New IOC added to database" },
  { event: "indicator.updated", description: "Existing IOC updated (risk score, tags)" },
  { event: "threat.campaign.new", description: "New threat campaign identified" },
  { event: "threat.campaign.updated", description: "Campaign updated with new IOCs" },
  { event: "alert.high_risk", description: "High-risk indicator detected in your watchlist" },
  { event: "analysis.complete", description: "Domain/URL analysis job completed" }
];

export default function IntegrationPage() {
  return (
    <main className="min-h-screen bg-ebony-950">
      <Header />
      
      {/* Hero Section */}
      <section className="pt-40 pb-16 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-purple-500/5 via-transparent to-transparent" />
        <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-[120px]" />
        
        <div className="max-w-[1680px] mx-auto px-8 relative z-10">
          {/* Roadmap notice — these integrations are not yet available */}
          <div className="flex items-start gap-4 rounded-2xl border border-amber-500/40 bg-amber-500/10 p-5 mb-10">
            <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-amber-300 font-semibold">Roadmap — not yet available</p>
              <p className="text-white/70 text-sm mt-1 leading-relaxed">
                The SIEM apps (Splunk, QRadar, Sentinel), SOAR playbooks, webhook event stream,
                and Python SDK described on this page are <span className="text-white/90 font-medium">planned
                integrations</span>, not shippable features today. JichoSec currently exposes a REST
                API at{" "}
                <code className="text-amber-200">https://jichosec.defendanddetect.com/api/v1</code>{" "}
                authenticated with JWT bearer tokens. Treat everything below as a preview of where
                we&apos;re headed — endpoints, package names, and auth details will change before release.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-white/60 mb-6">
            <Link href="/" className="hover:text-white transition-colors">Home</Link>
            <ChevronRight className="w-4 h-4" />
            <Link href="/docs" className="hover:text-white transition-colors">Docs</Link>
            <ChevronRight className="w-4 h-4" />
            <span className="text-white">Integration Guides</span>
          </div>

          <div className="max-w-3xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-xl bg-purple-500/20 flex items-center justify-center">
                <Plug className="w-6 h-6 text-purple-400" />
              </div>
              <h1 className="text-4xl lg:text-5xl font-bold text-white">
                Integration Guides
              </h1>
            </div>
            <p className="text-xl text-white/60 mb-8">
              A preview of how JichoSec will connect to your security stack. From SIEM platforms to
              custom applications, these guides describe the integrations we are building — none are
              generally available yet.
            </p>

            <div className="flex flex-wrap gap-4">
              <a href="#siem" className="inline-flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white/80 rounded-lg border border-white/10 transition-all">
                <Server className="w-4 h-4" />
                SIEM Integration
              </a>
              <a href="#soar" className="inline-flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white/80 rounded-lg border border-white/10 transition-all">
                <Zap className="w-4 h-4" />
                SOAR Playbooks
              </a>
              <a href="#webhooks" className="inline-flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white/80 rounded-lg border border-white/10 transition-all">
                <Webhook className="w-4 h-4" />
                Webhooks
              </a>
              <a href="#python-sdk" className="inline-flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-white/80 rounded-lg border border-white/10 transition-all">
                <Code className="w-4 h-4" />
                Python SDK
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* SIEM Integration Section */}
      <section id="siem" className="py-16 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Server className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">SIEM Integration</h2>
          </div>
          <p className="text-white/60 mb-8 max-w-2xl">
            JichoSec integrates with major SIEM platforms to enrich your security events with 
            real-time threat intelligence. Choose your platform below for setup instructions.
          </p>

          <div className="grid md:grid-cols-3 gap-6 mb-12">
            {siemIntegrations.map((siem) => (
              <div 
                key={siem.name}
                className="p-6 rounded-2xl bg-card-dark border border-white/10 hover:border-primary/30 transition-all"
              >
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center">
                    <Shield className="w-6 h-6 text-primary" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">{siem.name}</h3>
                    <span className="text-white/40 text-sm">Setup: {siem.setupTime}</span>
                  </div>
                </div>
                <p className="text-white/60 text-sm mb-4">{siem.description}</p>
                <ul className="space-y-2">
                  {siem.features.map((feature) => (
                    <li key={feature} className="flex items-center gap-2 text-white/50 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Splunk Setup */}
          <div className="mb-12">
            <h3 className="text-xl font-semibold text-white mb-4">Splunk Setup</h3>
            <div className="grid lg:grid-cols-2 gap-8">
              <div>
                <ol className="space-y-4">
                  <li className="flex gap-4">
                    <span className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold flex-shrink-0">1</span>
                    <div>
                      <p className="text-white font-medium">Install the JichoSec App</p>
                      <p className="text-white/50 text-sm mt-1">
                        Download the JichoSec app from Splunkbase or install via CLI:
                      </p>
                      <code className="block mt-2 bg-card-light rounded-lg p-2 text-sm text-white/80">
                        splunk install app jichosec-ti
                      </code>
                    </div>
                  </li>
                  <li className="flex gap-4">
                    <span className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold flex-shrink-0">2</span>
                    <div>
                      <p className="text-white font-medium">Configure API Key</p>
                      <p className="text-white/50 text-sm mt-1">
                        Navigate to Settings &gt; JichoSec and enter your API key.
                      </p>
                    </div>
                  </li>
                  <li className="flex gap-4">
                    <span className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold flex-shrink-0">3</span>
                    <div>
                      <p className="text-white font-medium">Enable Data Inputs</p>
                      <p className="text-white/50 text-sm mt-1">
                        Configure modular inputs for IOC feeds, choosing update frequency and threat types.
                      </p>
                    </div>
                  </li>
                  <li className="flex gap-4">
                    <span className="w-8 h-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-primary font-bold flex-shrink-0">4</span>
                    <div>
                      <p className="text-white font-medium">Create Correlation Searches</p>
                      <p className="text-white/50 text-sm mt-1">
                        Use provided saved searches or create custom correlations with the jichosec_ioc lookup.
                      </p>
                    </div>
                  </li>
                </ol>
              </div>
              <div>
                <CodeBlock 
                  title="Splunk SPL Query Example"
                  language="spl"
                  code={`index=network sourcetype=firewall
| lookup jichosec_ioc indicator AS dest_ip OUTPUT threat_type, risk_score
| where isnotnull(threat_type)
| eval severity=case(
    risk_score >= 80, "critical",
    risk_score >= 60, "high",
    risk_score >= 40, "medium",
    true(), "low"
)
| stats count BY dest_ip, threat_type, severity
| sort -count`}
                />
              </div>
            </div>
          </div>

          {/* QRadar Setup */}
          <div className="mb-12">
            <h3 className="text-xl font-semibold text-white mb-4">IBM QRadar Setup</h3>
            <CodeBlock 
              title="QRadar Reference Set Update Script"
              language="python"
              code={`#!/usr/bin/env python3
"""JichoSec QRadar Reference Set Integration"""

import requests
from qradariomgr import QRadarAPI

JICHOSEC_API_KEY = "js_live_your_api_key"
QRADAR_HOST = "https://qradar.example.com"
QRADAR_TOKEN = "your_qradar_token"

# Initialize QRadar API
qradar = QRadarAPI(QRADAR_HOST, QRADAR_TOKEN)

# Fetch IOCs from JichoSec
response = requests.get(
    "https://jichosec.defendanddetect.com/api/v1/indicators",
    headers={"Authorization": f"Bearer {JICHOSEC_API_KEY}"},
    params={"type": "ip", "risk_score_min": 70, "limit": 1000}
)

iocs = response.json()["data"]

# Update QRadar Reference Set
ref_set_name = "JichoSec_Malicious_IPs"
for ioc in iocs:
    qradar.add_to_reference_set(ref_set_name, ioc["value"])

print(f"Updated {len(iocs)} indicators in QRadar")`}
            />
          </div>

          {/* Microsoft Sentinel Setup */}
          <div>
            <h3 className="text-xl font-semibold text-white mb-4">Microsoft Sentinel Setup</h3>
            <div className="grid lg:grid-cols-2 gap-8">
              <div>
                <p className="text-white/60 mb-4">
                  Use the JichoSec Logic App connector to ingest threat intelligence into Sentinel&apos;s 
                  ThreatIntelligenceIndicator table.
                </p>
                <ol className="space-y-3">
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                    <span className="text-white/70">Deploy the Logic App ARM template from our GitHub</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                    <span className="text-white/70">Configure API connection with your JichoSec API key</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                    <span className="text-white/70">Enable the Threat Intelligence connector in Sentinel</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                    <span className="text-white/70">Import provided workbooks and analytics rules</span>
                  </li>
                </ol>
              </div>
              <div>
                <CodeBlock 
                  title="KQL Hunting Query"
                  language="kql"
                  code={`// Hunt for connections to JichoSec threat indicators
let ThreatIndicators = ThreatIntelligenceIndicator
| where SourceSystem == "JichoSec"
| where ConfidenceScore >= 70
| where ExpirationDateTime > now()
| summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
| project NetworkIP, DomainName, ThreatType, ConfidenceScore;

CommonSecurityLog
| where TimeGenerated > ago(24h)
| join kind=inner ThreatIndicators on $left.DestinationIP == $right.NetworkIP
| project TimeGenerated, SourceIP, DestinationIP, ThreatType, ConfidenceScore
| sort by TimeGenerated desc`}
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SOAR Playbooks Section */}
      <section id="soar" className="py-16 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Zap className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">SOAR Playbooks</h2>
          </div>
          <p className="text-white/60 mb-8 max-w-2xl">
            Automate your threat response with pre-built SOAR playbooks. Works with 
            Splunk SOAR, Palo Alto XSOAR, and other platforms.
          </p>

          <div className="grid lg:grid-cols-2 gap-8 mb-8">
            <div className="p-6 rounded-2xl bg-card-dark border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-4">IOC Enrichment Playbook</h3>
              <p className="text-white/60 text-sm mb-4">
                Automatically enrich alerts with JichoSec threat intelligence and update ticket severity.
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center">
                    <span className="text-blue-400 text-xs font-bold">1</span>
                  </div>
                  <span className="text-white/70 text-sm">Extract IOCs from alert</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center">
                    <span className="text-blue-400 text-xs font-bold">2</span>
                  </div>
                  <span className="text-white/70 text-sm">Query JichoSec API for threat data</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center">
                    <span className="text-blue-400 text-xs font-bold">3</span>
                  </div>
                  <span className="text-white/70 text-sm">Update alert with risk score & context</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center">
                    <span className="text-blue-400 text-xs font-bold">4</span>
                  </div>
                  <span className="text-white/70 text-sm">Escalate if risk score &gt; 80</span>
                </div>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-card-dark border border-white/10">
              <h3 className="text-lg font-semibold text-white mb-4">Auto-Block Playbook</h3>
              <p className="text-white/60 text-sm mb-4">
                Automatically block high-risk indicators at the firewall and update blocklists.
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center">
                    <span className="text-red-400 text-xs font-bold">1</span>
                  </div>
                  <span className="text-white/70 text-sm">Receive high-risk IOC webhook</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center">
                    <span className="text-red-400 text-xs font-bold">2</span>
                  </div>
                  <span className="text-white/70 text-sm">Validate IOC is not whitelisted</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center">
                    <span className="text-red-400 text-xs font-bold">3</span>
                  </div>
                  <span className="text-white/70 text-sm">Add to Palo Alto EDL / Firewall rule</span>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-card-light border border-white/5">
                  <div className="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center">
                    <span className="text-red-400 text-xs font-bold">4</span>
                  </div>
                  <span className="text-white/70 text-sm">Create audit trail ticket</span>
                </div>
              </div>
            </div>
          </div>

          <CodeBlock 
            title="XSOAR Integration Script"
            language="python"
            code={`"""JichoSec XSOAR Integration"""

def jichosec_lookup_indicator(indicator: str) -> dict:
    """
    Lookup an indicator in JichoSec threat intelligence.
    
    Args:
        indicator: IP address, domain, or URL to lookup
        
    Returns:
        Threat intelligence data including risk score and threat type
    """
    api_key = demisto.params().get('api_key')
    base_url = "https://jichosec.defendanddetect.com/api/v1"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(
        f"{base_url}/indicators/bulk",
        headers=headers,
        json={"indicators": [indicator]}
    )
    
    if response.status_code == 200:
        data = response.json()["data"][0]
        
        if data["found"]:
            return CommandResults(
                outputs_prefix="JichoSec.Indicator",
                outputs_key_field="value",
                outputs={
                    "value": indicator,
                    "type": data["type"],
                    "threat_type": data["threat_type"],
                    "risk_score": data["risk_score"],
                    "first_seen": data["first_seen"],
                    "tags": data.get("tags", [])
                },
                readable_output=tableToMarkdown(
                    f"JichoSec Results for {indicator}",
                    data
                )
            )
    
    return CommandResults(readable_output=f"No results for {indicator}")`}
          />
        </div>
      </section>

      {/* Webhooks Section */}
      <section id="webhooks" className="py-16 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Webhook className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Webhook Setup</h2>
          </div>
          <p className="text-white/60 mb-8 max-w-2xl">
            Receive real-time threat notifications via webhooks. JichoSec sends HTTP POST 
            requests to your endpoint when relevant events occur.
          </p>

          <div className="grid lg:grid-cols-2 gap-8 mb-8">
            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Available Events</h3>
              <div className="space-y-2">
                {webhookEvents.map((event) => (
                  <div 
                    key={event.event}
                    className="flex items-center justify-between p-3 rounded-lg bg-card-dark border border-white/10"
                  >
                    <code className="text-primary text-sm">{event.event}</code>
                    <span className="text-white/50 text-sm">{event.description}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Webhook Configuration</h3>
              <ol className="space-y-4 mb-6">
                <li className="flex gap-4">
                  <span className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-primary text-sm font-bold flex-shrink-0">1</span>
                  <div>
                    <p className="text-white font-medium">Navigate to Settings &gt; Webhooks</p>
                  </div>
                </li>
                <li className="flex gap-4">
                  <span className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-primary text-sm font-bold flex-shrink-0">2</span>
                  <div>
                    <p className="text-white font-medium">Add your endpoint URL</p>
                    <p className="text-white/50 text-sm">Must be HTTPS with valid certificate</p>
                  </div>
                </li>
                <li className="flex gap-4">
                  <span className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-primary text-sm font-bold flex-shrink-0">3</span>
                  <div>
                    <p className="text-white font-medium">Select events to subscribe</p>
                  </div>
                </li>
                <li className="flex gap-4">
                  <span className="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-primary text-sm font-bold flex-shrink-0">4</span>
                  <div>
                    <p className="text-white font-medium">Copy the signing secret</p>
                    <p className="text-white/50 text-sm">Use to verify webhook authenticity</p>
                  </div>
                </li>
              </ol>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            <div>
              <CodeBlock 
                title="Webhook Payload Example"
                language="json"
                code={`{
  "id": "evt_7x9k2mf8n3p4",
  "type": "indicator.new",
  "created": "2024-03-15T14:30:00Z",
  "data": {
    "indicator": {
      "id": "ioc_8x7f9k2m",
      "type": "domain",
      "value": "malicious-c2.example.com",
      "threat_type": "c2",
      "risk_score": 95,
      "tags": ["cobalt-strike", "africa-targeted"],
      "first_seen": "2024-03-15T14:28:00Z"
    }
  },
  "account_id": "acc_your_account"
}`}
              />
            </div>

            <div>
              <CodeBlock 
                title="Webhook Signature Verification (Python)"
                language="python"
                code={`import hmac
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)
WEBHOOK_SECRET = "your_webhook_secret"

def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature."""
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    signature = request.headers.get("X-JichoSec-Signature")
    
    if not verify_signature(request.data, signature):
        return jsonify({"error": "Invalid signature"}), 401
    
    event = request.json
    event_type = event["type"]
    
    if event_type == "indicator.new":
        ioc = event["data"]["indicator"]
        print(f"New IOC: {ioc['value']} ({ioc['threat_type']})")
        # Process the new indicator...
    
    return jsonify({"received": True}), 200`}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Python SDK Section */}
      <section id="python-sdk" className="py-16 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-primary/20 flex items-center justify-center">
              <Package className="w-5 h-5 text-primary" />
            </div>
            <h2 className="text-2xl font-bold text-white">Python SDK</h2>
          </div>
          <p className="text-white/60 mb-8 max-w-2xl">
            The official JichoSec Python SDK provides a convenient way to interact with our API. 
            Supports Python 3.8+ with full type hints and async support.
          </p>

          <div className="grid lg:grid-cols-2 gap-8 mb-8">
            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Installation</h3>
              <CodeBlock 
                language="bash"
                code={`# Install via pip
pip install jichosec

# Or with poetry
poetry add jichosec

# For async support
pip install jichosec[async]`}
              />

              <h3 className="text-lg font-semibold text-white mb-4 mt-8">Quick Start</h3>
              <CodeBlock 
                language="python"
                code={`from jichosec import JichoSecClient

# Initialize the client
client = JichoSecClient(api_key="js_live_your_api_key")

# List recent indicators
indicators = client.indicators.list(
    type="domain",
    threat_type="phishing",
    limit=50
)

for ioc in indicators:
    print(f"{ioc.value} - Risk: {ioc.risk_score}")

# Analyze a domain
result = client.analysis.domain(
    domain="suspicious-site.com",
    deep_scan=True
)

print(f"Risk Score: {result.risk_score}")
print(f"Threat Type: {result.threat_type}")
print(f"DGA Probability: {result.dga_score}")`}
              />
            </div>

            <div>
              <h3 className="text-lg font-semibold text-white mb-4">Async Support</h3>
              <CodeBlock 
                language="python"
                code={`import asyncio
from jichosec import AsyncJichoSecClient

async def main():
    async with AsyncJichoSecClient(api_key="js_live_...") as client:
        # Concurrent lookups
        domains = [
            "domain1.com",
            "domain2.net", 
            "domain3.org"
        ]
        
        tasks = [
            client.analysis.domain(d) 
            for d in domains
        ]
        
        results = await asyncio.gather(*tasks)
        
        for domain, result in zip(domains, results):
            print(f"{domain}: {result.risk_score}")

asyncio.run(main())`}
              />

              <h3 className="text-lg font-semibold text-white mb-4 mt-8">Error Handling</h3>
              <CodeBlock 
                language="python"
                code={`from jichosec import JichoSecClient
from jichosec.exceptions import (
    RateLimitError,
    AuthenticationError,
    NotFoundError
)

client = JichoSecClient(api_key="js_live_...")

try:
    result = client.indicators.get("ioc_invalid")
except AuthenticationError:
    print("Invalid API key")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except NotFoundError:
    print("Indicator not found")`}
              />
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-card-dark border border-white/10">
            <h3 className="text-lg font-semibold text-white mb-4">SDK Features</h3>
            <div className="grid md:grid-cols-3 gap-6">
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Full Type Hints</p>
                  <p className="text-white/50 text-sm">Complete type annotations for IDE support</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Automatic Retries</p>
                  <p className="text-white/50 text-sm">Built-in retry logic with exponential backoff</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Pagination Helpers</p>
                  <p className="text-white/50 text-sm">Iterate through all results automatically</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Async/Await</p>
                  <p className="text-white/50 text-sm">First-class async support for high-performance apps</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Request Logging</p>
                  <p className="text-white/50 text-sm">Debug mode for troubleshooting integrations</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-white font-medium">Rate Limit Handling</p>
                  <p className="text-white/50 text-sm">Automatic rate limit tracking and backoff</p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 flex items-center gap-4">
            <a 
              href="https://github.com/jichosec/jichosec-python"
              target="_blank"
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-white/10 hover:bg-white/20 text-white font-medium rounded-full border border-white/10 transition-all"
            >
              <FileCode className="w-4 h-4" />
              View on GitHub
            </a>
            <a 
              href="https://pypi.org/project/jichosec/"
              target="_blank"
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-white/10 hover:bg-white/20 text-white font-medium rounded-full border border-white/10 transition-all"
            >
              <Package className="w-4 h-4" />
              PyPI Package
            </a>
          </div>
        </div>
      </section>

      {/* Navigation Footer */}
      <section className="py-12 border-t border-white/10">
        <div className="max-w-[1680px] mx-auto px-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-6">
            <Link 
              href="/docs/api"
              className="flex items-center gap-2 text-white/60 hover:text-white transition-colors"
            >
              <ChevronRight className="w-4 h-4 rotate-180" />
              API Reference
            </Link>
            <Link 
              href="/docs"
              className="flex items-center gap-2 px-6 py-3 bg-primary hover:bg-primary-hover text-white font-medium rounded-full transition-all"
            >
              Back to Documentation
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
