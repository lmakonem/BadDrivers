"""
Shared brand-domain helpers, used by both the brand API (endpoints/brand.py)
and the brand scanner (services/brand_scan.py) so the "what is this brand's
registrable name" logic has a single source of truth.
"""

from __future__ import annotations

from typing import List

from app.core.ownership import bare_domain

# Words whose IOC matches are false positives (too broad) — brand names that are
# common English/industry words, plus generic subdomain labels that must never
# become a brand IOC search term.
GENERIC_IOC_WORDS = {
    "orange", "telecom", "telkom", "openserve", "mobile", "airtel", "mtn",
    "vodacom", "standard", "first", "national", "bank", "blue", "red",
    "admin", "mail", "portal", "staging", "financing", "autodiscover", "api",
    "app", "cdn", "dev", "www", "webmail", "remote", "vpn", "smtp", "test",
}

# Two-part public suffixes common in African ccTLDs, so we can extract the
# registrable brand label instead of a subdomain label.
TWO_PART_SUFFIXES = {
    "co.ke", "or.ke", "go.ke", "ac.ke", "co.za", "org.za", "gov.za", "ac.za",
    "co.tz", "or.tz", "ac.tz", "go.tz", "co.ug", "ac.ug", "go.ug", "com.ng",
    "gov.ng", "org.ng", "edu.ng", "com.gh", "gov.gh", "gov.cd", "co.zm",
    "co.zw", "org.zw", "com.eg", "gov.eg", "com.dz", "co.ma", "com.tn",
    "co.mz", "co.ao", "co.bw", "co.rw", "co.mw", "co.ci", "com.sn",
}


def registrable_base(domain: str) -> str:
    """
    Registrable brand label of a domain (the SLD before the public suffix):
    safaricom.co.ke -> safaricom, admin.fpi-rdc.cd -> fpi-rdc, www.bmoi.mg -> bmoi.
    Collapses subdomains to the brand so generic subdomain labels
    (admin/mail/portal/...) never become IOC search terms.
    """
    d = bare_domain(domain)
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def specific_brand_terms(domains: List[str], keywords: List[str]) -> List[str]:
    """Distinct, non-generic brand identifiers to match IOCs against."""
    terms = set()
    for d in domains or []:
        b = registrable_base(d).lower()
        if len(b) >= 4 and b not in GENERIC_IOC_WORDS:
            terms.add(b)
    for kw in keywords or []:
        kw = (kw or "").strip().lower()
        if len(kw) >= 4 and kw not in GENERIC_IOC_WORDS:
            terms.add(kw)
    return list(terms)


def apex_domains(domains: List[str]) -> List[str]:
    """One apex (registrable) domain per brand base — the shortest per base."""
    by_base = {}
    for d in domains or []:
        b = registrable_base(d)
        dd = bare_domain(d)
        if b and (b not in by_base or dd.count(".") < by_base[b].count(".")):
            by_base[b] = dd
    return list(by_base.values())
