#!/usr/bin/env python3
"""
Seed all empty Elasticsearch indices with realistic JichoDNS data.
Run from the repo root: python3 kibana/seed_data.py
"""

import json
import random
import uuid
from datetime import datetime, timedelta

import urllib.request
import urllib.error

ES_URL = "http://192.168.36.51:9200"
ES_AUTH = ("elastic", "jichodns_elastic_2024")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def es_bulk(index: str, docs: list[dict]) -> dict:
    """Bulk index documents into ES using the _bulk API."""
    lines = []
    for doc in docs:
        meta = {"index": {"_index": index, "_id": doc.get("id", str(uuid.uuid4()))}}
        lines.append(json.dumps(meta))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"

    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=body.encode(),
        headers={
            "Content-Type": "application/x-ndjson",
            "Authorization": "Basic " + __import__("base64").b64encode(
                f"{ES_AUTH[0]}:{ES_AUTH[1]}".encode()
            ).decode(),
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def dt(days_ago: float = 0, hours_ago: float = 0) -> str:
    """Return ISO timestamp offset from now."""
    t = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def rand_date(max_days: int = 90) -> str:
    return dt(days_ago=random.uniform(0, max_days))


# ---------------------------------------------------------------------------
# 1. ASSETS
# ---------------------------------------------------------------------------

def seed_assets():
    domains = [
        ("safaricom.co.ke", "KE"), ("kcbgroup.com", "KE"), ("equitybank.co.ke", "KE"),
        ("mtn.com", "ZA"), ("standardbank.co.za", "ZA"), ("fnb.co.za", "ZA"),
        ("airtel.africa", "NG"), ("jumia.com", "NG"), ("flutterwave.com", "NG"),
        ("co-opbank.co.ke", "KE"), ("dtb.co.ke", "KE"), ("nbk.co.ke", "KE"),
    ]
    asset_types = ["domain", "subdomain", "ip_address", "web_application", "cloud_resource"]
    services = ["HTTPS", "HTTP", "SSH", "SMTP", "FTP", "DNS", "RDP", "MySQL", "PostgreSQL"]
    statuses = ["active", "inactive", "unknown"]
    cloud_providers = ["AWS", "GCP", "Azure", "Cloudflare", None]

    subdomains = ["api", "mail", "dev", "staging", "admin", "vpn", "ftp", "cdn", "app", "portal",
                  "auth", "gateway", "dashboard", "internal", "backup", "test", "static", "mobile"]

    docs = []
    for i in range(120):
        base_domain, country = random.choice(domains)
        sub = random.choice(subdomains)
        is_sub = random.random() > 0.3
        hostname = f"{sub}.{base_domain}" if is_sub else base_domain
        asset_type = "subdomain" if is_sub else random.choice(["domain", "ip_address", "web_application"])
        svc_list = random.sample(services, k=random.randint(1, 3))
        discovered = rand_date(60)
        doc = {
            "id": str(uuid.uuid4()),
            "asset_value": hostname,
            "asset_type": asset_type,
            "hostname": hostname,
            "domain": base_domain,
            "ip_address": rand_ip(),
            "country": country,
            "status": random.choice(statuses),
            "service": svc_list[0],
            "services": svc_list,
            "port": random.choice([80, 443, 22, 25, 8080, 8443, 3306, 5432]),
            "protocol": "TCP",
            "os": random.choice(["Ubuntu 22.04", "CentOS 7", "Debian 11", "Windows Server 2019", None]),
            "cloud_provider": random.choice(cloud_providers),
            "cloud_region": random.choice(["af-south-1", "europe-west1", "us-east-1", None]),
            "risk_score": round(random.uniform(5, 95), 1),
            "vulnerability_count": random.randint(0, 12),
            "tags": random.sample(["production", "external", "internal", "critical", "legacy", "dev"], k=random.randint(1, 3)),
            "first_seen": discovered,
            "last_seen": rand_date(max_days=5),
            "created_at": discovered,
            "customer_id": "jichodns-demo",
            "asn": f"AS{random.randint(10000, 60000)}",
            "asn_org": random.choice(["Safaricom PLC", "MTN SA", "Airtel Africa", "Amazon", "Google"]),
        }
        docs.append(doc)

    result = es_bulk("assets", docs)
    errors = result.get("errors", True)
    print(f"[assets] Indexed {len(docs)} docs | errors={errors}")


# ---------------------------------------------------------------------------
# 2. VULNERABILITIES
# ---------------------------------------------------------------------------

def seed_vulnerabilities():
    cves = [
        ("CVE-2024-21413", "critical", "Microsoft Outlook RCE", "remote_code_execution", 9.8),
        ("CVE-2024-1709",  "critical", "ConnectWise ScreenConnect Auth Bypass", "authentication_bypass", 10.0),
        ("CVE-2023-44487", "high",     "HTTP/2 Rapid Reset DoS", "denial_of_service", 7.5),
        ("CVE-2023-4966",  "critical", "Citrix Bleed Session Token Leak", "information_disclosure", 9.4),
        ("CVE-2023-20198", "critical", "Cisco IOS XE Web UI Privilege Escalation", "privilege_escalation", 10.0),
        ("CVE-2024-3400",  "critical", "PAN-OS Command Injection", "command_injection", 10.0),
        ("CVE-2023-46805", "high",     "Ivanti ICS Auth Bypass", "authentication_bypass", 8.2),
        ("CVE-2024-21887", "critical", "Ivanti ICS Command Injection", "command_injection", 9.1),
        ("CVE-2023-42793", "critical", "JetBrains TeamCity Auth Bypass", "authentication_bypass", 9.8),
        ("CVE-2024-0519",  "high",     "Chrome V8 Out-of-Bounds Memory", "memory_corruption", 8.8),
        ("CVE-2023-34048", "critical", "VMware vCenter RCE", "remote_code_execution", 9.8),
        ("CVE-2024-27198", "critical", "JetBrains TeamCity Auth Bypass 2024", "authentication_bypass", 9.8),
        ("CVE-2023-48788", "critical", "Fortinet EMS SQL Injection", "sql_injection", 9.8),
        ("CVE-2024-1086",  "high",     "Linux Kernel Use-After-Free", "privilege_escalation", 7.8),
        (None,             "medium",   "SSL Certificate Expiry Warning", "misconfiguration", 5.0),
        (None,             "medium",   "Missing HTTP Security Headers", "misconfiguration", 4.3),
        (None,             "low",      "HTTP Server Version Disclosure", "information_disclosure", 3.1),
        (None,             "high",     "Exposed Admin Interface", "misconfiguration", 7.2),
        (None,             "medium",   "Weak TLS Cipher Suite", "misconfiguration", 5.9),
        (None,             "low",      "Directory Listing Enabled", "information_disclosure", 3.7),
    ]

    asset_ids = [str(uuid.uuid4()) for _ in range(30)]
    docs = []
    for i in range(150):
        cve_id, severity, title, vuln_type, cvss = random.choice(cves)
        discovered = rand_date(45)
        doc = {
            "id": str(uuid.uuid4()),
            "title": title,
            "cve_id": cve_id,
            "severity": severity,
            "vulnerability_type": vuln_type,
            "cvss_score": cvss,
            "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "asset_id": random.choice(asset_ids),
            "affected_component": random.choice(["web_server", "cms", "vpn", "firewall", "database", "api_gateway"]),
            "affected_version": f"{random.randint(1,15)}.{random.randint(0,9)}.{random.randint(0,9)}",
            "description": f"A {severity} vulnerability affecting {title.lower()} was detected.",
            "remediation": "Apply the latest vendor patch immediately. Review access controls and implement network segmentation.",
            "status": random.choice(["open", "open", "open", "in_progress", "resolved"]),
            "exploit_available": severity in ("critical", "high") and random.random() > 0.4,
            "patch_available": random.random() > 0.3,
            "tags": random.sample(["production", "internet-facing", "critical-system"], k=random.randint(1, 2)),
            "date_discovered": discovered,
            "date_published": rand_date(90),
            "created_at": discovered,
            "updated_at": rand_date(max_days=3),
            "customer_id": "jichodns-demo",
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else [],
        }
        docs.append(doc)

    result = es_bulk("vulnerabilities", docs)
    print(f"[vulnerabilities] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 3. DARKWEB LEAKS
# ---------------------------------------------------------------------------

def seed_darkweb_leaks():
    domains = ["safaricom.co.ke", "kcbgroup.com", "equitybank.co.ke", "mtn.com",
               "standardbank.co.za", "airtel.africa", "jumia.com", "flutterwave.com",
               "company.co.ke", "corp.co.tz", "business.co.ng", "enterprise.co.za"]
    forums = ["BreachForums", "RaidForums Mirror", "Telegram @DataLeaks", "XSS.is",
              "Exploit.in", "Dark Web Market", "Paste Site", "CryptBB"]
    leak_types = ["credentials", "pii", "financial", "corporate", "healthcare"]
    severities = ["critical", "critical", "high", "high", "medium"]

    docs = []
    for i in range(200):
        domain = random.choice(domains)
        discovered = rand_date(90)
        record_count = random.randint(100, 5000000)
        doc = {
            "id": str(uuid.uuid4()),
            "title": f"{domain.split('.')[0].title()} Database Leak",
            "affected_domain": domain,
            "leak_type": random.choice(leak_types),
            "severity": random.choice(severities),
            "record_count": record_count,
            "source_forum": random.choice(forums),
            "data_types": random.sample(["email", "password", "phone", "name", "address",
                                          "id_number", "credit_card", "bank_account"], k=random.randint(2, 5)),
            "status": random.choice(["new", "new", "verified", "investigating", "resolved"]),
            "description": f"Leaked database containing {record_count:,} records from {domain}",
            "sample_data": f"email@{domain}, <hashed_password>, +254XXXXXXXXX",
            "tags": random.sample(["africa", "financial", "telecom", "retail", "corporate"], k=2),
            "date_discovered": discovered,
            "date_posted": rand_date(95),
            "created_at": discovered,
            "updated_at": rand_date(max_days=2),
        }
        docs.append(doc)

    result = es_bulk("darkweb_leaks", docs)
    print(f"[darkweb_leaks] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 4. DARKWEB MENTIONS
# ---------------------------------------------------------------------------

def seed_darkweb_mentions():
    forums = ["BreachForums", "RaidForums", "XSS.is", "Exploit.in", "Telegram", "Dark Web Forum", "IRC #Africa"]
    source_types = ["forum", "telegram", "paste_site", "marketplace", "irc"]
    keywords = ["safaricom", "m-pesa", "kcb bank", "equity bank", "mtn", "airtel",
                "mpesa agent", "mobile money", "kenya banking", "south africa banking"]
    sentiments = ["negative", "negative", "negative", "neutral"]
    mention_types = ["credential_sale", "access_sale", "discussion", "threat", "data_leak", "tutorial"]

    titles = [
        "Selling Safaricom internal API access",
        "M-Pesa agent bypass techniques",
        "KCB Bank employee database for sale",
        "New phishing kit targeting African banks",
        "Equity Bank credential dump available",
        "MTN USSD exploit discussion",
        "African mobile money fraud methods",
        "Airtel Africa admin panel access",
        "Jumia customer data 2024 leak",
        "Flutterwave transaction logs for sale",
        "South Africa banking sector vulnerabilities",
        "Safaricom employee credentials dump",
        "Standard Bank South Africa breach",
        "FNB Online Banking phishing kit",
        "Nigerian bank SWIFT credentials",
    ]

    docs = []
    for i in range(180):
        keyword = random.choice(keywords)
        forum = random.choice(forums)
        discovered = rand_date(90)
        doc = {
            "id": str(uuid.uuid4()),
            "post_title": random.choice(titles),
            "post_content": f"Detailed discussion about {keyword} vulnerabilities and exploitation methods...",
            "keyword": keyword,
            "forum_name": forum,
            "source_type": random.choice(source_types),
            "source_url": f"http://darkweb-{''.join(random.choices('abcdef1234567890', k=16))}.onion/thread/{random.randint(1000,9999)}",
            "author": f"user_{random.randint(100,9999)}",
            "mention_type": random.choice(mention_types),
            "sentiment": random.choice(sentiments),
            "relevance_score": round(random.uniform(0.5, 1.0), 2),
            "status": random.choice(["new", "new", "reviewed", "actioned"]),
            "tags": random.sample(["africa", "financial", "critical", "high-priority"], k=2),
            "date_discovered": discovered,
            "date_posted": rand_date(95),
            "created_at": discovered,
            "updated_at": rand_date(max_days=2),
        }
        docs.append(doc)

    result = es_bulk("darkweb_mentions", docs)
    print(f"[darkweb_mentions] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 5. DATA BREACHES
# ---------------------------------------------------------------------------

def seed_data_breaches():
    breaches = [
        ("East Africa Telecom Breach 2024", "critical", 2400000, ["phone", "name", "transaction_history"]),
        ("Kenya Banking Sector Leak", "critical", 1800000, ["account_number", "name", "email", "id_number"]),
        ("MTN Africa Customer Database", "high", 950000, ["phone", "name", "address"]),
        ("Jumia East Africa Orders Dump", "high", 3200000, ["email", "phone", "address", "orders"]),
        ("African E-Commerce Platform Breach", "high", 1200000, ["email", "password", "address"]),
        ("South Africa Banking Data Leak", "critical", 4500000, ["id_number", "account_number", "credit_score"]),
        ("Flutterwave Transaction Records", "critical", 2800000, ["email", "phone", "transactions", "card_data"]),
        ("Nigerian Telco Customer Data", "high", 7000000, ["phone", "name", "address", "bvn"]),
        ("Safaricom Partner Portal Breach", "high", 120000, ["email", "password", "api_key"]),
        ("Kenya Revenue Authority Leak", "critical", 500000, ["id_number", "tax_pin", "income_data"]),
        ("Equity Bank Mobile App Data", "high", 890000, ["phone", "email", "account_number"]),
        ("Rwanda Telco Subscriber Data", "medium", 430000, ["phone", "name", "address"]),
        ("Nairobi Hospital Patient Records", "critical", 85000, ["name", "id_number", "medical_records"]),
        ("African University Student Database", "medium", 340000, ["email", "name", "id_number"]),
        ("E-Commerce Checkout Data 2023", "high", 560000, ["email", "card_last4", "address"]),
    ]

    docs = []
    for name, severity, records, data_types in breaches:
        discovered = rand_date(180)
        doc = {
            "id": str(uuid.uuid4()),
            "name": name,
            "severity": severity,
            "affected_count": records,
            "data_types": data_types,
            "description": f"Breach affecting {records:,} records. Data includes {', '.join(data_types)}.",
            "status": random.choice(["confirmed", "confirmed", "investigating", "patched"]),
            "source": random.choice(["BreachForums", "HaveIBeenPwned", "Internal Discovery", "Security Researcher"]),
            "relevance_score": round(random.uniform(0.6, 1.0), 2),
            "tags": ["africa", severity],
            "date_discovered": discovered,
            "created_at": discovered,
            "updated_at": rand_date(max_days=30),
        }
        docs.append(doc)

    result = es_bulk("data_breaches", docs)
    print(f"[data_breaches] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 6. BRAND MONITORS
# ---------------------------------------------------------------------------

def seed_brand_monitors():
    brands = [
        ("Safaricom", "safaricom.co.ke", "telecom", ["safaricom", "m-pesa", "mpesa"]),
        ("M-Pesa", "mpesa.com", "mobile_money", ["mpesa", "m-pesa", "safaricom pay"]),
        ("KCB Bank", "kcbgroup.com", "banking", ["kcb", "kcb bank", "kenya commercial bank"]),
        ("Equity Bank", "equitybankgroup.com", "banking", ["equity bank", "equitybank"]),
        ("MTN Group", "mtn.com", "telecom", ["mtn", "mtn mobile money"]),
        ("Airtel Africa", "airtel.africa", "telecom", ["airtel", "airtel money"]),
        ("Standard Bank", "standardbank.co.za", "banking", ["standard bank", "standardbank"]),
        ("First National Bank", "fnb.co.za", "banking", ["fnb", "first national bank"]),
        ("Jumia", "jumia.com", "ecommerce", ["jumia", "jumia kenya", "jumia nigeria"]),
        ("Flutterwave", "flutterwave.com", "fintech", ["flutterwave", "flutter wave"]),
        ("Paystack", "paystack.com", "fintech", ["paystack"]),
        ("Interswitch", "interswitchgroup.com", "fintech", ["interswitch", "quickteller"]),
    ]

    docs = []
    for brand_name, domain, industry, keywords in brands:
        created = rand_date(180)
        doc = {
            "id": str(uuid.uuid4()),
            "brand_name": brand_name,
            "brand_domain": domain,
            "industry": industry,
            "keywords": keywords,
            "monitoring_enabled": True,
            "total_alerts": random.randint(5, 120),
            "active_threats": random.randint(1, 25),
            "last_scan": rand_date(max_days=1),
            "created_at": created,
            "updated_at": rand_date(max_days=7),
            "customer_id": "jichodns-demo",
        }
        docs.append(doc)

    result = es_bulk("brand_monitors", docs)
    print(f"[brand_monitors] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 7. TYPOSQUAT DOMAINS
# ---------------------------------------------------------------------------

def seed_typosquat_domains():
    brands = [
        ("safaricom.co.ke", "Safaricom"),
        ("mpesa.com", "M-Pesa"),
        ("kcbgroup.com", "KCB Bank"),
        ("equitybankgroup.com", "Equity Bank"),
        ("mtn.com", "MTN"),
        ("airtel.africa", "Airtel Africa"),
        ("standardbank.co.za", "Standard Bank"),
        ("flutterwave.com", "Flutterwave"),
    ]
    techniques = ["typo", "homoglyph", "combosquat", "subdomain", "tld_swap", "omission", "addition", "transposition"]
    statuses = ["active", "active", "monitoring", "investigating", "taken_down"]

    typosquat_patterns = {
        "safaricom.co.ke": ["safar1com.co.ke", "safarico.co.ke", "safar-icom.co.ke", "safaricom-pay.co.ke",
                             "safaricam.co.ke", "safarlcom.co.ke", "safaricom.co.com", "xn--safaricom-e4a.co.ke"],
        "mpesa.com": ["m-pesa-pay.com", "mpeza.com", "mpesa-agent.com", "mpesha.com",
                       "m-pesa-kenya.com", "mpesaa.com", "mpesa.co", "m-pesaa.com"],
        "kcbgroup.com": ["kcbgr0up.com", "kcb-group.com", "kcbgrooup.com", "kcb-bank.com"],
        "equitybankgroup.com": ["equitybank.co.ke", "equitybankgrp.com", "equltybank.com", "equity-bank-group.com"],
        "mtn.com": ["mtn-mobile.com", "mtn-money.com", "mtn-africa.com", "mtn-pay.com"],
        "airtel.africa": ["airtel-africa.com", "airtell.africa", "airte1.africa", "airtel-pay.africa"],
        "standardbank.co.za": ["standard-bank.co.za", "standardb4nk.co.za", "standardbankonline.co.za"],
        "flutterwave.com": ["flutterwav.com", "flutter-wave.com", "flutterwave-pay.com", "flutterwaves.com"],
    }

    docs = []
    for original_domain, brand_name in brands:
        variants = typosquat_patterns.get(original_domain, [f"typo-{original_domain}"])
        for typo_domain in variants:
            discovered = rand_date(90)
            risk = round(random.uniform(20, 99), 1)
            is_phishing = risk > 70 and random.random() > 0.3
            doc = {
                "id": str(uuid.uuid4()),
                "original_domain": original_domain,
                "typosquat_domain": typo_domain,
                "brand_name": brand_name,
                "brand_id": str(uuid.uuid4()),
                "technique": random.choice(techniques),
                "similarity_score": round(random.uniform(0.6, 0.99), 2),
                "risk_score": risk,
                "ip_address": rand_ip() if random.random() > 0.3 else None,
                "country": random.choice(["KE", "NG", "ZA", "GH", "RU", "CN", "US", "NL"]),
                "has_website": random.random() > 0.4,
                "has_mx": random.random() > 0.6,
                "is_phishing": is_phishing,
                "status": "active" if is_phishing else random.choice(statuses),
                "ssl_issuer": random.choice(["Let's Encrypt", "Comodo", None, None]),
                "ns_records": [f"ns1.{random.choice(['cloudflare.com', 'godaddy.com', 'namecheap.com'])}"],
                "tags": ["typosquat", brand_name.lower().replace(" ", "_")],
                "date_discovered": discovered,
                "last_checked": rand_date(max_days=1),
                "created_at": discovered,
                "customer_id": "jichodns-demo",
                "asn": f"AS{random.randint(10000, 60000)}",
                "asn_org": random.choice(["Cloudflare", "Amazon", "Namecheap", "GoDaddy", "HostGator"]),
            }
            docs.append(doc)

    result = es_bulk("typosquat_domains", docs)
    print(f"[typosquat_domains] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# 8. BRAND ALERTS
# ---------------------------------------------------------------------------

def seed_brand_alerts():
    brands = ["Safaricom", "M-Pesa", "KCB Bank", "Equity Bank", "MTN", "Airtel Africa",
              "Standard Bank", "Flutterwave"]
    alert_types = ["typosquat_detected", "phishing_detected", "brand_mention", "credential_leak",
                   "lookalike_domain", "social_media_impersonation"]
    severities = ["critical", "critical", "high", "high", "medium", "low"]

    alert_titles = {
        "typosquat_detected": "New typosquat domain registered",
        "phishing_detected": "Active phishing page detected",
        "brand_mention": "Brand mentioned on dark web forum",
        "credential_leak": "Employee credentials found in breach",
        "lookalike_domain": "Lookalike domain using brand SSL",
        "social_media_impersonation": "Fake social media account detected",
    }

    docs = []
    for i in range(250):
        brand = random.choice(brands)
        alert_type = random.choice(alert_types)
        severity = random.choice(severities)
        detected = rand_date(90)
        doc = {
            "id": str(uuid.uuid4()),
            "brand_name": brand,
            "brand_id": str(uuid.uuid4()),
            "title": f"{alert_titles[alert_type]} — {brand}",
            "alert_type": alert_type,
            "severity": severity,
            "description": f"A {severity} {alert_type.replace('_', ' ')} event was detected targeting {brand}.",
            "evidence_url": f"http://{''.join(random.choices('abcdef1234567890', k=12))}.onion/post/{random.randint(100,9999)}",
            "status": random.choice(["new", "new", "acknowledged", "resolved"]),
            "acknowledged": random.random() > 0.6,
            "tags": [brand.lower().replace(" ", "_"), alert_type, severity],
            "detected_at": detected,
            "created_at": detected,
            "updated_at": rand_date(max_days=2),
            "customer_id": "jichodns-demo",
        }
        docs.append(doc)

    result = es_bulk("brand_alerts", docs)
    print(f"[brand_alerts] Indexed {len(docs)} docs | errors={result.get('errors', True)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Seeding JichoDNS Elasticsearch indices...\n")
    seed_assets()
    seed_vulnerabilities()
    seed_darkweb_leaks()
    seed_darkweb_mentions()
    seed_data_breaches()
    seed_brand_monitors()
    seed_typosquat_domains()
    seed_brand_alerts()
    print("\nDone. Verify counts:")
    indices = ["assets", "vulnerabilities", "darkweb_leaks", "darkweb_mentions",
               "data_breaches", "brand_monitors", "typosquat_domains", "brand_alerts"]
    import urllib.request, base64
    for idx in indices:
        req = urllib.request.Request(
            f"{ES_URL}/{idx}/_count",
            headers={"Authorization": "Basic " + base64.b64encode(b"elastic:jichodns_elastic_2024").decode()},
        )
        with urllib.request.urlopen(req) as r:
            count = json.loads(r.read())["count"]
        print(f"  {idx}: {count} docs")
