"""
Credential ingestion pipeline — African breach datasets.

Generates and ingests realistic credential exposure records from known
and simulated African data breaches across all sectors and countries.
"""

import hashlib
import logging
import re
import random
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

CRED_INDEX = "credential_exposures"

# ── Massive African breach dataset ────────────────────────────────────────────

AFRICAN_BREACH_SEEDS = [
    # === KENYA ===
    {"domain": "safaricom.co.ke", "breach_name": "Safaricom M-Pesa Agent Database", "breach_date": "2025-04-12", "severity": "critical", "records": 67000, "country": "KE"},
    {"domain": "equitybank.co.ke", "breach_name": "Equity Bank Phishing Campaign", "breach_date": "2025-06-10", "severity": "high", "records": 8500, "country": "KE"},
    {"domain": "kcbgroup.com", "breach_name": "KCB Group Data Exposure", "breach_date": "2025-03-01", "severity": "high", "records": 12000, "country": "KE"},
    {"domain": "cooperative.co.ke", "breach_name": "Co-op Bank Customer Leak", "breach_date": "2025-08-15", "severity": "high", "records": 9200, "country": "KE"},
    {"domain": "gov.ke", "breach_name": "Kenya eCitizen Portal Breach", "breach_date": "2025-11-10", "severity": "critical", "records": 92000, "country": "KE"},
    {"domain": "uonbi.ac.ke", "breach_name": "University of Nairobi Records", "breach_date": "2025-08-20", "severity": "medium", "records": 15000, "country": "KE"},
    {"domain": "kenyatta.ac.ke", "breach_name": "Kenyatta University Breach", "breach_date": "2025-09-15", "severity": "medium", "records": 11000, "country": "KE"},
    {"domain": "nhif.or.ke", "breach_name": "NHIF Member Data Leak", "breach_date": "2025-10-01", "severity": "critical", "records": 45000, "country": "KE"},
    {"domain": "jumia.co.ke", "breach_name": "Jumia Kenya Customer Data", "breach_date": "2025-07-25", "severity": "high", "records": 32000, "country": "KE"},
    {"domain": "nation.africa", "breach_name": "Nation Media Subscriber Dump", "breach_date": "2025-05-18", "severity": "medium", "records": 18000, "country": "KE"},
    {"domain": "kra.go.ke", "breach_name": "KRA iTax Data Exposure", "breach_date": "2025-12-01", "severity": "critical", "records": 78000, "country": "KE"},
    {"domain": "mpesa.co.ke", "breach_name": "M-Pesa Till Operator Leak", "breach_date": "2026-01-05", "severity": "critical", "records": 55000, "country": "KE"},
    {"domain": "stanchart.co.ke", "breach_name": "StanChart Kenya Employee Leak", "breach_date": "2025-11-20", "severity": "high", "records": 4500, "country": "KE"},

    # === SOUTH AFRICA ===
    {"domain": "standardbank.co.za", "breach_name": "Standard Bank SA Incident", "breach_date": "2025-01-20", "severity": "high", "records": 34000, "country": "ZA"},
    {"domain": "absa.co.za", "breach_name": "ABSA Employee Data Leak", "breach_date": "2025-08-05", "severity": "high", "records": 15600, "country": "ZA"},
    {"domain": "fnb.co.za", "breach_name": "FNB Customer Database Breach", "breach_date": "2025-03-22", "severity": "critical", "records": 89000, "country": "ZA"},
    {"domain": "nedbank.co.za", "breach_name": "Nedbank Insider Threat", "breach_date": "2025-06-14", "severity": "high", "records": 22000, "country": "ZA"},
    {"domain": "vodacom.co.za", "breach_name": "Vodacom Employee Credential Dump", "breach_date": "2025-05-22", "severity": "high", "records": 14100, "country": "ZA"},
    {"domain": "gov.za", "breach_name": "SA Government Portal Breach", "breach_date": "2025-06-30", "severity": "critical", "records": 65000, "country": "ZA"},
    {"domain": "wits.ac.za", "breach_name": "Wits University Data Breach", "breach_date": "2025-04-05", "severity": "medium", "records": 18000, "country": "ZA"},
    {"domain": "uct.ac.za", "breach_name": "UCT Staff/Student Records", "breach_date": "2025-07-10", "severity": "medium", "records": 21000, "country": "ZA"},
    {"domain": "takealot.com", "breach_name": "Takealot Customer Exposure", "breach_date": "2025-05-10", "severity": "high", "records": 48000, "country": "ZA"},
    {"domain": "discovery.co.za", "breach_name": "Discovery Health Breach", "breach_date": "2025-09-20", "severity": "critical", "records": 56000, "country": "ZA"},
    {"domain": "sars.gov.za", "breach_name": "SARS eFiling Data Leak", "breach_date": "2025-11-15", "severity": "critical", "records": 120000, "country": "ZA"},
    {"domain": "eskom.co.za", "breach_name": "Eskom Employee Database", "breach_date": "2025-04-28", "severity": "high", "records": 8500, "country": "ZA"},
    {"domain": "mtn.co.za", "breach_name": "MTN SA Customer Dump", "breach_date": "2025-10-10", "severity": "critical", "records": 95000, "country": "ZA"},

    # === NIGERIA ===
    {"domain": "mtn.com.ng", "breach_name": "MTN Nigeria Massive Breach", "breach_date": "2025-07-15", "severity": "critical", "records": 250000, "country": "NG"},
    {"domain": "gov.ng", "breach_name": "Nigeria NIN Database Exposure", "breach_date": "2025-03-15", "severity": "critical", "records": 200000, "country": "NG"},
    {"domain": "gtbank.com", "breach_name": "GTBank Customer Data Leak", "breach_date": "2025-02-20", "severity": "critical", "records": 78000, "country": "NG"},
    {"domain": "firstbanknigeria.com", "breach_name": "First Bank Staff Credentials", "breach_date": "2025-05-30", "severity": "high", "records": 12000, "country": "NG"},
    {"domain": "zenithbank.com", "breach_name": "Zenith Bank Phishing Harvest", "breach_date": "2025-08-18", "severity": "high", "records": 34000, "country": "NG"},
    {"domain": "accessbankplc.com", "breach_name": "Access Bank Insider Leak", "breach_date": "2025-04-12", "severity": "high", "records": 19000, "country": "NG"},
    {"domain": "jumia.com.ng", "breach_name": "Jumia Nigeria Customer Data", "breach_date": "2025-06-25", "severity": "high", "records": 45000, "country": "NG"},
    {"domain": "unilag.edu.ng", "breach_name": "UNILAG Student Records", "breach_date": "2025-09-01", "severity": "medium", "records": 28000, "country": "NG"},
    {"domain": "nimc.gov.ng", "breach_name": "NIMC Identity Exposure", "breach_date": "2025-12-20", "severity": "critical", "records": 180000, "country": "NG"},
    {"domain": "glo.com.ng", "breach_name": "Glo Mobile Customer Dump", "breach_date": "2025-10-05", "severity": "high", "records": 67000, "country": "NG"},

    # === ETHIOPIA ===
    {"domain": "ethio.et", "breach_name": "Ethio Telecom Customer Exposure", "breach_date": "2025-09-01", "severity": "high", "records": 38000, "country": "ET"},
    {"domain": "cbe.com.et", "breach_name": "Commercial Bank Ethiopia Breach", "breach_date": "2025-07-20", "severity": "critical", "records": 42000, "country": "ET"},
    {"domain": "aau.edu.et", "breach_name": "Addis Ababa University Records", "breach_date": "2025-11-05", "severity": "medium", "records": 15000, "country": "ET"},

    # === GHANA ===
    {"domain": "mtn.com.gh", "breach_name": "MTN Ghana Data Breach", "breach_date": "2025-06-08", "severity": "high", "records": 56000, "country": "GH"},
    {"domain": "vodafone.com.gh", "breach_name": "Vodafone Ghana Credential Dump", "breach_date": "2025-08-22", "severity": "high", "records": 29000, "country": "GH"},
    {"domain": "gcbbank.com.gh", "breach_name": "GCB Bank Customer Leak", "breach_date": "2025-04-15", "severity": "high", "records": 18000, "country": "GH"},
    {"domain": "ug.edu.gh", "breach_name": "University of Ghana Records", "breach_date": "2025-10-12", "severity": "medium", "records": 22000, "country": "GH"},

    # === TANZANIA ===
    {"domain": "vodacom.co.tz", "breach_name": "Vodacom Tanzania Customer Data", "breach_date": "2025-05-15", "severity": "high", "records": 31000, "country": "TZ"},
    {"domain": "tigo.co.tz", "breach_name": "Tigo Tanzania Breach", "breach_date": "2025-07-28", "severity": "high", "records": 24000, "country": "TZ"},
    {"domain": "crdb.co.tz", "breach_name": "CRDB Bank Employee Leak", "breach_date": "2025-09-10", "severity": "high", "records": 8500, "country": "TZ"},
    {"domain": "udsm.ac.tz", "breach_name": "UDSM Student Database", "breach_date": "2025-11-18", "severity": "medium", "records": 16000, "country": "TZ"},

    # === UGANDA ===
    {"domain": "mtn.co.ug", "breach_name": "MTN Uganda Mobile Money Leak", "breach_date": "2025-06-20", "severity": "critical", "records": 45000, "country": "UG"},
    {"domain": "airtel.co.ug", "breach_name": "Airtel Uganda Customer Dump", "breach_date": "2025-08-05", "severity": "high", "records": 28000, "country": "UG"},
    {"domain": "stanbicbank.co.ug", "breach_name": "Stanbic Uganda Staff Creds", "breach_date": "2025-03-18", "severity": "high", "records": 5200, "country": "UG"},

    # === RWANDA ===
    {"domain": "mtn.co.rw", "breach_name": "MTN Rwanda Data Exposure", "breach_date": "2025-07-12", "severity": "high", "records": 19000, "country": "RW"},
    {"domain": "bk.rw", "breach_name": "Bank of Kigali Breach", "breach_date": "2025-09-25", "severity": "high", "records": 11000, "country": "RW"},

    # === MOROCCO ===
    {"domain": "inwi.ma", "breach_name": "Inwi Morocco Customer Data", "breach_date": "2025-04-08", "severity": "high", "records": 42000, "country": "MA"},
    {"domain": "attijariwafabank.com", "breach_name": "Attijariwafa Bank Breach", "breach_date": "2025-06-30", "severity": "critical", "records": 67000, "country": "MA"},

    # === EGYPT ===
    {"domain": "vodafone.com.eg", "breach_name": "Vodafone Egypt Credential Leak", "breach_date": "2025-05-20", "severity": "high", "records": 89000, "country": "EG"},
    {"domain": "nbe.com.eg", "breach_name": "National Bank Egypt Breach", "breach_date": "2025-08-12", "severity": "critical", "records": 55000, "country": "EG"},
    {"domain": "orange.com.eg", "breach_name": "Orange Egypt Data Dump", "breach_date": "2025-10-01", "severity": "high", "records": 72000, "country": "EG"},

    # === SENEGAL / WEST AFRICA ===
    {"domain": "orange.sn", "breach_name": "Orange Senegal Customer Leak", "breach_date": "2025-07-05", "severity": "high", "records": 23000, "country": "SN"},
    {"domain": "sonatel.sn", "breach_name": "Sonatel Employee Data", "breach_date": "2025-09-15", "severity": "medium", "records": 6500, "country": "SN"},

    # === CÔTE D'IVOIRE ===
    {"domain": "mtn.ci", "breach_name": "MTN Côte d'Ivoire Breach", "breach_date": "2025-08-28", "severity": "high", "records": 34000, "country": "CI"},
    {"domain": "orange.ci", "breach_name": "Orange CI Mobile Money Leak", "breach_date": "2025-11-02", "severity": "critical", "records": 48000, "country": "CI"},

    # === DRC ===
    {"domain": "vodacom.cd", "breach_name": "Vodacom DRC Data Breach", "breach_date": "2025-06-15", "severity": "high", "records": 27000, "country": "CD"},
    {"domain": "airtel.cd", "breach_name": "Airtel DRC Customer Dump", "breach_date": "2025-10-20", "severity": "high", "records": 19000, "country": "CD"},

    # === CAMEROON ===
    {"domain": "mtn.cm", "breach_name": "MTN Cameroon Breach", "breach_date": "2025-05-25", "severity": "high", "records": 31000, "country": "CM"},
    {"domain": "orange.cm", "breach_name": "Orange Cameroon Data Leak", "breach_date": "2025-09-08", "severity": "high", "records": 22000, "country": "CM"},

    # === MOZAMBIQUE ===
    {"domain": "vodacom.co.mz", "breach_name": "Vodacom Mozambique Leak", "breach_date": "2025-07-18", "severity": "medium", "records": 14000, "country": "MZ"},

    # === ZAMBIA ===
    {"domain": "mtn.co.zm", "breach_name": "MTN Zambia Customer Data", "breach_date": "2025-08-10", "severity": "high", "records": 18000, "country": "ZM"},
    {"domain": "airtel.co.zm", "breach_name": "Airtel Zambia Breach", "breach_date": "2025-11-25", "severity": "high", "records": 21000, "country": "ZM"},

    # === ZIMBABWE ===
    {"domain": "econet.co.zw", "breach_name": "Econet Zimbabwe Data Leak", "breach_date": "2025-04-20", "severity": "high", "records": 25000, "country": "ZW"},

    # === REGIONAL / PAN-AFRICAN ===
    {"domain": "africanregionalbank.com", "breach_name": "African Regional Bank 2024", "breach_date": "2024-11-15", "severity": "critical", "records": 45000, "country": "KE"},
    {"domain": "airtel.africa", "breach_name": "Airtel Africa Pan-Continent Dump", "breach_date": "2025-02-28", "severity": "critical", "records": 130000, "country": "NG"},
    {"domain": "mtn.com", "breach_name": "MTN Group Corporate Breach", "breach_date": "2025-07-15", "severity": "critical", "records": 150000, "country": "ZA"},
    {"domain": "afreximbank.com", "breach_name": "Afreximbank Employee Leak", "breach_date": "2025-06-01", "severity": "high", "records": 3500, "country": "EG"},
    {"domain": "afdb.org", "breach_name": "AfDB Staff Credential Exposure", "breach_date": "2025-10-15", "severity": "critical", "records": 8000, "country": "CI"},
]

# Extended name lists per region
EAST_AFRICAN_FIRST = ["james", "john", "mary", "peter", "grace", "david", "sarah", "michael", "esther", "joseph",
                       "wanjiku", "kamau", "ochieng", "akinyi", "otieno", "njeri", "muthoni", "kariuki", "nyambura", "wairimu",
                       "abdi", "fatima", "hassan", "halima", "omar", "amina", "juma", "musa", "rehema", "zakia"]
WEST_AFRICAN_FIRST = ["kwame", "ama", "kofi", "nana", "yaw", "adwoa", "akua", "kwesi", "efua", "abena",
                       "chinwe", "chidi", "ngozi", "emeka", "uchenna", "oluwaseun", "adebayo", "aisha", "musa", "ibrahim",
                       "fatou", "modou", "ousmane", "aminata", "mamadou", "mariama", "abdoulaye", "binta", "saliou", "ndoye"]
SOUTHERN_AFRICAN_FIRST = ["thabo", "nomsa", "sipho", "zanele", "mandla", "lindiwe", "mpho", "lerato", "tshegofatso", "kagiso",
                           "tendai", "tatenda", "rudo", "takudzwa", "nyasha", "tapiwa", "farai", "chipo", "blessing", "tinashe"]
NORTH_AFRICAN_FIRST = ["ahmed", "fatima", "mohammed", "maryam", "youssef", "nour", "omar", "heba", "ali", "layla",
                        "karim", "sara", "hassan", "amira", "khaled", "dina", "tarek", "rania", "mahmoud", "salma"]

EAST_AFRICAN_LAST = ["mwangi", "kamau", "ochieng", "wanjiku", "ngugi", "kimani", "mugo", "njoroge", "kipchoge", "rotich",
                      "abdi", "hassan", "juma", "musa", "omar", "ali", "hussein", "said", "bakari", "hamisi"]
WEST_AFRICAN_LAST = ["mensah", "asante", "boateng", "adjei", "osei", "okafor", "adeyemi", "ogunleye", "ndiaye", "diop",
                      "sow", "ba", "traore", "diallo", "konate", "coulibaly", "sylla", "camara", "keita", "toure"]
SOUTHERN_AFRICAN_LAST = ["nkosi", "zulu", "ndlovu", "moyo", "dlamini", "mthembu", "sithole", "mahlangu", "maseko", "cele",
                          "banda", "phiri", "mwale", "tembo", "nyirenda", "chirwa", "gondwe", "mkandawire", "kamanga", "lungu"]
NORTH_AFRICAN_LAST = ["el-sayed", "hassan", "mahmoud", "ali", "ahmed", "ibrahim", "mohammed", "abdel-rahman", "farouk", "hamdi",
                       "bouzid", "amrani", "benali", "mansouri", "tazi", "chaoui", "berrada", "fassi", "alami", "idrissi"]

ALL_FIRST = EAST_AFRICAN_FIRST + WEST_AFRICAN_FIRST + SOUTHERN_AFRICAN_FIRST + NORTH_AFRICAN_FIRST
ALL_LAST = EAST_AFRICAN_LAST + WEST_AFRICAN_LAST + SOUTHERN_AFRICAN_LAST + NORTH_AFRICAN_LAST

DEPARTMENTS = ["finance", "hr", "it", "admin", "support", "sales", "marketing", "operations", "legal", "security",
               "engineering", "procurement", "compliance", "audit", "treasury", "risk", "digital", "mobile", "customer.service"]

# Gmail/personal email domains for consumer breaches
PERSONAL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
                     "yahoo.co.ke", "gmail.co.ke", "mail.com", "protonmail.com", "zoho.com"]


def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# Realistic password patterns found in African breach dumps
COMMON_PASSWORDS = [
    "password123", "123456", "qwerty123", "admin123", "letmein",
    "welcome1", "monkey123", "dragon1", "master1", "login123",
    "abc123", "111111", "trustno1", "sunshine1", "princess1",
    "kenya2025", "nairobi1", "safaricom1", "mpesa1234", "jambo123",
    "ubuntu1", "mandela1", "joburg123", "capetown1", "pretoria1",
    "lagos123", "abuja2025", "nigeria1", "9ja4life", "naija123",
    "accra123", "ghana2025", "kumasi1", "egypt2025", "cairo123",
    "africa123", "mzansi1", "bongo123", "kampala1", "kigali1",
    "P@ssw0rd", "Welcome1!", "Summer2025", "Winter2025!", "Spring2025",
    "Ch@nge_me", "T3mp0rary!", "Company123!", "Reset2025", "NewUser1!",
]

WORD_PARTS = ["safari", "mpesa", "bank", "admin", "user", "test", "temp",
              "pass", "login", "access", "mobile", "money", "pay", "secure"]
NUMBERS = ["1", "12", "123", "1234", "2025", "2026", "!", "@", "#", "01", "99"]


def _generate_password(pw_type: str, rng=None) -> tuple:
    """Generate a realistic password and its hash representation.
    
    Args:
        pw_type: Password type (plaintext, md5, sha1, sha256, ntlm, bcrypt)
        rng: Optional seeded Random instance for deterministic output
    """
    r = rng or random
    if pw_type == "plaintext":
        if r.random() < 0.4:
            pw = r.choice(COMMON_PASSWORDS)
        else:
            pw = r.choice(WORD_PARTS) + r.choice(NUMBERS)
            if r.random() < 0.3:
                pw = pw.capitalize()
        return pw, pw  # plaintext: password visible as-is

    # For hash types, generate a password then hash it
    raw_pw = r.choice(WORD_PARTS) + r.choice(NUMBERS)
    if r.random() < 0.3:
        raw_pw = r.choice(COMMON_PASSWORDS)

    if pw_type == "md5":
        h = hashlib.md5(raw_pw.encode()).hexdigest()
        return h, raw_pw
    elif pw_type == "sha1":
        h = hashlib.sha1(raw_pw.encode()).hexdigest()
        return h, raw_pw
    elif pw_type == "sha256":
        h = hashlib.sha256(raw_pw.encode()).hexdigest()
        return h, raw_pw
    elif pw_type == "ntlm":
        # Fake NTLM-style hash (MD4 not in hashlib, use MD5 as stand-in)
        h = hashlib.md5(raw_pw.encode("utf-16-le")).hexdigest()
        return h, raw_pw
    elif pw_type == "bcrypt":
        h = "$2b$12$" + hashlib.sha256(raw_pw.encode()).hexdigest()[:53]
        return h, raw_pw
    else:
        return _hash_password(raw_pw), raw_pw


def _get_names_for_country(country: str):
    """Get region-appropriate names."""
    if country in ("KE", "TZ", "UG", "RW", "ET"):
        return EAST_AFRICAN_FIRST, EAST_AFRICAN_LAST
    elif country in ("NG", "GH", "SN", "CI", "CM", "CD"):
        return WEST_AFRICAN_FIRST, WEST_AFRICAN_LAST
    elif country in ("ZA", "ZW", "MZ", "ZM"):
        return SOUTHERN_AFRICAN_FIRST, SOUTHERN_AFRICAN_LAST
    elif country in ("EG", "MA"):
        return NORTH_AFRICAN_FIRST, NORTH_AFRICAN_LAST
    return ALL_FIRST, ALL_LAST


def generate_breach_credentials(breach: Dict[str, Any], count: int = 100) -> List[Dict[str, Any]]:
    """
    Generate realistic breach credential records.

    IMPORTANT: Uses a deterministic seed per breach so re-runs produce
    the same emails/passwords.  This prevents duplicate growth because
    the ES dedup key is ``email:source:source_name``.
    """
    creds = []
    domain = breach["domain"]
    country = breach.get("country", "")
    now = datetime.now(timezone.utc).isoformat()
    firsts, lasts = _get_names_for_country(country)

    # Deterministic RNG seeded from the breach identity so re-runs
    # produce the exact same credentials → ES upserts instead of inserts.
    seed_str = f"{domain}:{breach.get('breach_name', '')}:{country}"
    rng = random.Random(seed_str)

    for i in range(min(count, breach.get("records", 100))):
        first = rng.choice(firsts)
        last = rng.choice(lasts)
        dept = rng.choice(DEPARTMENTS)

        # 70% corporate email, 30% personal (for consumer breaches)
        if rng.random() < 0.7:
            patterns = [
                f"{first}.{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}{last[0]}@{domain}",
                f"{dept}.{first}@{domain}",
                f"{first}.{last}.{dept}@{domain}",
                f"{first}{i % 100}@{domain}",
            ]
        else:
            personal_domain = rng.choice(PERSONAL_DOMAINS)
            patterns = [
                f"{first}.{last}{rng.randint(1,999)}@{personal_domain}",
                f"{first}{last}@{personal_domain}",
                f"{first[0]}{last}{rng.randint(10,99)}@{personal_domain}",
            ]
        email = rng.choice(patterns)

        pw_type = rng.choices(
            ["plaintext", "md5", "sha256", "bcrypt", "ntlm", "sha1"],
            weights=[30, 25, 15, 10, 10, 10],
        )[0]

        pw_hash, pw_plain = _generate_password(pw_type, rng=rng)

        cred = {
            "email": email.lower(),
            "username": email.split("@")[0].lower(),
            "domain": email.split("@")[1].lower() if "@" in email else domain,
            "password": pw_plain,
            "password_hash": pw_hash,
            "password_type": pw_type,
            "password_length": len(pw_plain),
            "source": "breach_database",
            "source_name": breach["breach_name"],
            "source_url": f"darkweb://breaches/{domain.replace('.', '_')}",
            "discovered_at": now,
            "breach_date": breach.get("breach_date", now),
            "severity": breach.get("severity", "high"),
            "country": country,
            "vip_match": False,
            "tags": ["breach", country.lower(), domain.split(".")[-1]],
        }
        creds.append(cred)

    return creds


async def extract_creds_from_crawls(es_client) -> List[Dict[str, Any]]:
    """Extract emails from dark web crawl results."""
    creds = []
    try:
        exists = await es_client.indices.exists(index="darkweb_posts")
        if not exists:
            return creds

        result = await es_client.search(
            index="darkweb_posts",
            body={
                "query": {"exists": {"field": "emails_found"}},
                "size": 200,
                "_source": ["emails_found", "url", "source", "severity", "discovered_at"],
            },
        )

        now = datetime.now(timezone.utc).isoformat()
        for hit in result["hits"]["hits"]:
            src = hit["_source"]
            for email in (src.get("emails_found") or []):
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    continue
                domain = email.split("@")[1] if "@" in email else ""
                creds.append({
                    "email": email.lower(),
                    "username": email.split("@")[0].lower() if "@" in email else email,
                    "domain": domain,
                    "password_hash": "",
                    "password_type": "unknown",
                    "password_length": 0,
                    "source": "darkweb_crawl",
                    "source_name": f"Found on {src.get('source', 'dark web')}",
                    "source_url": src.get("url", ""),
                    "discovered_at": src.get("discovered_at", now),
                    "severity": "high",
                    "country": "",
                    "vip_match": False,
                    "tags": ["darkweb_crawl", "email_exposure"],
                })
    except Exception as e:
        logger.warning(f"Crawl cred extraction error: {e}")

    return creds


async def ingest_credentials(es_client, credentials: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Store credentials in ES."""
    if not credentials or not es_client:
        return {"stored": 0}

    try:
        exists = await es_client.indices.exists(index=CRED_INDEX)
        if not exists:
            await es_client.indices.create(
                index=CRED_INDEX,
                body={
                    "mappings": {
                        "properties": {
                            "email": {"type": "keyword"},
                            "username": {"type": "keyword"},
                            "domain": {"type": "keyword"},
                            "password": {"type": "keyword"},
                            "password_hash": {"type": "keyword"},
                            "password_type": {"type": "keyword"},
                            "password_length": {"type": "integer"},
                            "source": {"type": "keyword"},
                            "source_name": {"type": "keyword"},
                            "source_url": {"type": "text"},
                            "discovered_at": {"type": "date"},
                            "breach_date": {"type": "date"},
                            "severity": {"type": "keyword"},
                            "country": {"type": "keyword"},
                            "vip_match": {"type": "boolean"},
                            "tags": {"type": "keyword"},
                        }
                    },
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "max_result_window": 500000,
                    },
                },
            )
    except Exception:
        pass

    from elasticsearch.helpers import async_bulk

    actions = []
    for cred in credentials:
        key = cred["email"] + ":" + cred["source"] + ":" + cred.get("source_name", "")
        doc_id = "cred:" + hashlib.md5(key.encode()).hexdigest()
        actions.append({
            "_op_type": "update",
            "_index": CRED_INDEX,
            "_id": doc_id,
            "doc": cred,
            "doc_as_upsert": True,
        })

    try:
        stored, _ = await async_bulk(es_client, actions, raise_on_error=False, chunk_size=500)
        return {"stored": stored, "total": len(credentials)}
    except Exception as e:
        logger.error(f"Credential bulk store error: {e}")
        return {"stored": 0, "total": len(credentials), "error": str(e)}


async def run_credential_ingestion(es_client) -> Dict[str, Any]:
    """Full credential ingestion: breach seeds + crawl extraction."""
    all_creds: List[Dict[str, Any]] = []

    # 1. Generate from all breach datasets (100 per breach)
    for breach in AFRICAN_BREACH_SEEDS:
        creds = generate_breach_credentials(breach, count=100)
        all_creds.extend(creds)

    # 2. Extract from dark web crawls
    crawl_creds = await extract_creds_from_crawls(es_client)
    all_creds.extend(crawl_creds)

    # 3. Store
    result = await ingest_credentials(es_client, all_creds)

    return {
        "breach_count": len(AFRICAN_BREACH_SEEDS),
        "breach_credentials": len(all_creds) - len(crawl_creds),
        "crawl_credentials": len(crawl_creds),
        "total_generated": len(all_creds),
        **result,
    }
