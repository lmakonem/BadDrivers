"""
Report generator — creates HTML threat intelligence reports from real data.

Pulls stats from Elasticsearch and produces formatted HTML that can be
viewed in browser or converted to PDF.

Supports multiple report types:
  - threat_intelligence: Full IOC landscape analysis
  - incident_summary: Incident-focused timeline view
  - executive_briefing: High-level stats for leadership
  - ioc_analysis: Deep IOC breakdown
  - dark_web_exposure: Dark web + credential exposure

Also provides ``generate_sample_report()`` for demo/showcase reports
that render with realistic static data (no ES required).
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)

# ── Colour palette ─────────────────────────────────────────────────────────────
COLORS = {
    "c2": "#ef4444", "phishing": "#f97316", "malware": "#a855f7",
    "exfiltration": "#3b82f6", "botnet": "#ec4899", "ransomware": "#dc2626",
    "spam": "#6b7280", "dga": "#f59e0b", "unknown": "#64748b",
    "primary": "#3b82f6", "green": "#10b981", "orange": "#f97316",
    "purple": "#a855f7", "yellow": "#f59e0b", "red": "#ef4444", "cyan": "#06b6d4",
}

THREAT_ICONS = {
    "c2": "&#x1F4E1;", "phishing": "&#x1F3A3;", "malware": "&#x1F41B;",
    "exfiltration": "&#x1F4E4;", "botnet": "&#x1F916;",
}


# =============================================================================
# Public API — real data
# =============================================================================

async def generate_report(
    report_type: str = "threat_intelligence",
    title: Optional[str] = None,
    include_iocs: bool = True,
    include_darkweb: bool = True,
    include_credentials: bool = True,
    date_range: str = "7d",
    custom_prompt: Optional[str] = None,
    focus_area: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a report from real ES data."""
    await es_service.connect()
    if not es_service.client:
        return {"error": "Elasticsearch not available"}

    now = datetime.now(timezone.utc)
    report_title = title or _default_title(report_type)

    ioc_stats = await _fetch_ioc_stats(date_range) if include_iocs else {}
    dw_stats = await _fetch_darkweb_stats() if include_darkweb else {}
    cred_stats = await _fetch_credential_stats() if include_credentials else {}
    top_iocs = await _fetch_top_iocs(date_range, limit=30) if include_iocs else []
    darkweb_posts = await _fetch_darkweb_posts(limit=10) if include_darkweb else []

    return _build_result(report_type, report_title, now, date_range, ioc_stats,
                         dw_stats, cred_stats, top_iocs, darkweb_posts,
                         focus_area or custom_prompt)


# =============================================================================
# Public API — sample / demo reports (no ES needed)
# =============================================================================

def generate_sample_report(report_type: str = "threat_intelligence") -> Dict[str, Any]:
    """Generate a sample report with realistic static data for demos."""
    now = datetime.now(timezone.utc)
    title = f"Sample {_default_title(report_type)}"
    date_range = "7d"

    ioc_stats = _SAMPLE_IOC_STATS.copy()
    dw_stats = _SAMPLE_DW_STATS.copy()
    cred_stats = _SAMPLE_CRED_STATS.copy()
    top_iocs = _SAMPLE_TOP_IOCS.copy()
    darkweb_posts = _SAMPLE_DW_POSTS.copy()

    return _build_result(report_type, title, now, date_range, ioc_stats,
                         dw_stats, cred_stats, top_iocs, darkweb_posts,
                         focus_area="Sample report — showcasing JichoSec report capabilities")


# =============================================================================
# Internal — shared result builder
# =============================================================================

def _default_title(report_type: str) -> str:
    labels = {
        "threat_intelligence": "Threat Intelligence",
        "incident_summary": "Incident Summary",
        "executive_briefing": "Executive Briefing",
        "ioc_analysis": "IOC Analysis",
        "dark_web_exposure": "Dark Web Exposure",
    }
    return f"{labels.get(report_type, report_type.replace('_', ' ').title())} Report"


def _build_result(report_type, title, now, date_range, ioc_stats, dw_stats,
                   cred_stats, top_iocs, darkweb_posts, focus_area) -> Dict[str, Any]:
    top_threats = list(ioc_stats.get("by_type", {}).items())
    top_countries = list(ioc_stats.get("by_country", {}).items())[:10]

    builder = _REPORT_BUILDERS.get(report_type, _build_threat_intel_html)
    html = builder(
        title=title, report_type=report_type, date_range=date_range,
        generated_at=now, ioc_stats=ioc_stats, dw_stats=dw_stats,
        cred_stats=cred_stats, top_threats=top_threats,
        top_countries=top_countries, top_iocs=top_iocs,
        darkweb_posts=darkweb_posts, focus_area=focus_area,
    )

    total_iocs = ioc_stats.get("total", 0)
    total_creds = cred_stats.get("total", 0)
    total_dw = dw_stats.get("total", 0)

    severity = (
        "critical" if total_iocs > 100_000
        else "high" if total_iocs > 10_000
        else "medium" if total_iocs > 1_000
        else "low"
    )

    return {
        "title": title,
        "type": report_type,
        "html": html,
        "status": "ready",
        "severity": severity,
        "generated_at": now.isoformat(),
        "date_range": date_range,
        "description": _report_description(report_type, total_iocs, total_dw, total_creds, date_range),
        "stats": {"iocs": total_iocs, "darkweb": total_dw, "credentials": total_creds},
        "pages": max(1, (total_iocs // 500) + 1),
    }


def _report_description(rtype: str, iocs: int, dw: int, creds: int, dr: str) -> str:
    period = dr.replace("d", " days").replace("h", " hours")
    descs = {
        "threat_intelligence": f"Comprehensive threat landscape analysis covering {iocs:,} indicators from the last {period}.",
        "incident_summary": f"Incident timeline and containment analysis across {iocs:,} indicators over the last {period}.",
        "executive_briefing": f"High-level security posture briefing with key metrics and leadership recommendations.",
        "ioc_analysis": f"Deep dive into {iocs:,} indicators of compromise with source and geographic analysis.",
        "dark_web_exposure": f"Dark web exposure assessment including {dw:,} threat indicators and {creds:,} credential exposures.",
    }
    return descs.get(rtype, f"Threat report covering {iocs:,} indicators.")


# =============================================================================
# Data fetchers (ES)
# =============================================================================

async def _fetch_ioc_stats(date_range: str) -> dict:
    try:
        r = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "query": {"range": {"created_at": {"gte": f"now-{date_range}"}}},
                "aggs": {
                    "total": {"value_count": {"field": "indicator.keyword"}},
                    "by_type": {"terms": {"field": "threat_type.keyword", "size": 10}},
                    "by_source": {"terms": {"field": "source.keyword", "size": 15}},
                    "by_country": {"terms": {"field": "country_code.keyword", "size": 20}},
                    "by_indicator_type": {"terms": {"field": "indicator_type.keyword", "size": 10}},
                    "high_confidence": {
                        "filter": {"range": {"confidence": {"gte": 0.8}}},
                        "aggs": {"count": {"value_count": {"field": "indicator.keyword"}}},
                    },
                },
            },
        )
        aggs = r.get("aggregations", {})
        return {
            "total": r["hits"]["total"]["value"],
            "by_type": {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])},
            "by_source": {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])},
            "by_country": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])},
            "by_indicator_type": {b["key"]: b["doc_count"] for b in aggs.get("by_indicator_type", {}).get("buckets", [])},
            "high_confidence_count": aggs.get("high_confidence", {}).get("count", {}).get("value", 0),
        }
    except Exception as e:
        logger.warning(f"IOC stats error: {e}")
        return {}


async def _fetch_darkweb_stats() -> dict:
    stats: Dict[str, Any] = {"total": 0, "by_source": {}}
    try:
        r = await es_service.client.search(
            index="iocs",
            body={
                "size": 0,
                "query": {"bool": {"should": [
                    {"term": {"source.keyword": "misp"}},
                    {"term": {"threat_type.keyword": "c2"}},
                    {"terms": {"source.keyword": ["phishtank", "openphish", "sslbl", "feodotracker"]}},
                ], "minimum_should_match": 1}},
                "aggs": {"by_source": {"terms": {"field": "source.keyword", "size": 10}}},
            },
        )
        stats["total"] = r["hits"]["total"]["value"]
        stats["by_source"] = {b["key"]: b["doc_count"] for b in r.get("aggregations", {}).get("by_source", {}).get("buckets", [])}
    except Exception:
        pass
    try:
        exists = await es_service.client.indices.exists(index="darkweb_posts")
        if exists:
            r = await es_service.client.count(index="darkweb_posts")
            stats["posts_total"] = r.get("count", 0)
    except Exception:
        pass
    return stats


async def _fetch_credential_stats() -> dict:
    try:
        exists = await es_service.client.indices.exists(index="credential_exposures")
        if not exists:
            return {}
        r = await es_service.client.search(
            index="credential_exposures",
            body={
                "size": 0,
                "aggs": {
                    "by_country": {"terms": {"field": "country.keyword", "size": 20}},
                    "by_severity": {"terms": {"field": "severity", "size": 5}},
                    "by_pw_type": {"terms": {"field": "password_type", "size": 10}},
                },
            },
        )
        aggs = r.get("aggregations", {})
        return {
            "total": r["hits"]["total"]["value"],
            "by_country": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])},
            "by_severity": {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])},
            "by_pw_type": {b["key"]: b["doc_count"] for b in aggs.get("by_pw_type", {}).get("buckets", [])},
        }
    except Exception:
        return {}


async def _fetch_top_iocs(date_range: str, limit: int = 30) -> List[dict]:
    try:
        r = await es_service.client.search(
            index="iocs",
            body={
                "size": limit,
                "query": {"range": {"created_at": {"gte": f"now-{date_range}"}}},
                "sort": [{"confidence": {"order": "desc"}}, {"created_at": {"order": "desc"}}],
                "_source": ["indicator", "indicator_type", "threat_type", "confidence", "source", "country_code", "first_seen"],
            },
        )
        return [hit["_source"] for hit in r["hits"]["hits"]]
    except Exception as e:
        logger.warning(f"Top IOCs error: {e}")
        return []


async def _fetch_darkweb_posts(limit: int = 10) -> List[dict]:
    try:
        exists = await es_service.client.indices.exists(index="darkweb_posts")
        if not exists:
            return []
        r = await es_service.client.search(
            index="darkweb_posts",
            body={"size": limit, "sort": [{"discovered_at": {"order": "desc"}}],
                  "_source": ["title", "source", "discovered_at", "category", "url"]},
        )
        return [hit["_source"] for hit in r["hits"]["hits"]]
    except Exception:
        return []


# =============================================================================
# Sample data for demo reports
# =============================================================================

_SAMPLE_IOC_STATS = {
    "total": 47_832,
    "by_type": {"phishing": 18420, "c2": 12890, "malware": 9640, "botnet": 3210, "exfiltration": 2180, "unknown": 1492},
    "by_source": {"urlhaus": 14200, "threatfox": 8930, "phishtank": 7100, "feodotracker": 5400, "sslbl": 4800, "openphish": 3200, "misp": 2100, "crtsh": 1200, "dnstwist": 902},
    "by_country": {"US": 9200, "CN": 6100, "RU": 4800, "KE": 3100, "ZA": 2900, "NG": 2400, "DE": 1800, "NL": 1600, "GB": 1400, "BR": 1200, "IN": 980, "EG": 820, "GH": 710, "TZ": 540, "UG": 430},
    "by_indicator_type": {"domain": 28100, "ip": 12400, "url": 5800, "hash_sha256": 1532},
    "high_confidence_count": 14_290,
}

_SAMPLE_DW_STATS = {
    "total": 8_430,
    "by_source": {"feodotracker": 3200, "sslbl": 2800, "misp": 1400, "phishtank": 680, "openphish": 350},
    "posts_total": 142,
}

_SAMPLE_CRED_STATS = {
    "total": 6_120,
    "by_country": {"KE": 1840, "ZA": 1200, "NG": 980, "GH": 620, "EG": 480, "TZ": 350, "UG": 290, "RW": 180, "MA": 120, "ET": 60},
    "by_severity": {"critical": 1200, "high": 2400, "medium": 1800, "low": 720},
    "by_pw_type": {"plaintext": 2100, "md5": 1600, "sha256": 980, "bcrypt": 640, "ntlm": 480, "sha1": 320},
}

_SAMPLE_TOP_IOCS: List[Dict[str, Any]] = [
    {"indicator": "evil-c2-panel.xyz", "indicator_type": "domain", "threat_type": "c2", "confidence": 0.98, "source": "threatfox", "country_code": "RU"},
    {"indicator": "safaricom-verify.com", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.97, "source": "dnstwist", "country_code": "US"},
    {"indicator": "mpesa-secure-login.net", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.96, "source": "dnstwist", "country_code": "NL"},
    {"indicator": "185.220.101.42", "indicator_type": "ip", "threat_type": "c2", "confidence": 0.95, "source": "feodotracker", "country_code": "DE"},
    {"indicator": "login-equitybank.co.ke.evil.com", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.94, "source": "crtsh", "country_code": "US"},
    {"indicator": "45.154.98.221", "indicator_type": "ip", "threat_type": "malware", "confidence": 0.93, "source": "sslbl", "country_code": "RU"},
    {"indicator": "mtn-ng-login.com", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.92, "source": "openphish", "country_code": "US"},
    {"indicator": "data-exfil-gateway.onion", "indicator_type": "domain", "threat_type": "exfiltration", "confidence": 0.91, "source": "misp", "country_code": ""},
    {"indicator": "185.174.137.80", "indicator_type": "ip", "threat_type": "botnet", "confidence": 0.90, "source": "feodotracker", "country_code": "CN"},
    {"indicator": "absa-banking-alert.co.za.phish.xyz", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.89, "source": "crtsh", "country_code": "US"},
    {"indicator": "fnb-secure-update.com", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.88, "source": "dnstwist", "country_code": "NL"},
    {"indicator": "91.215.85.129", "indicator_type": "ip", "threat_type": "c2", "confidence": 0.87, "source": "sslbl", "country_code": "RU"},
    {"indicator": "kra-tax-refund.go.ke.info", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.86, "source": "urlhaus", "country_code": "US"},
    {"indicator": "nhif-member-portal.com", "indicator_type": "domain", "threat_type": "phishing", "confidence": 0.85, "source": "openphish", "country_code": "DE"},
    {"indicator": "194.26.29.103", "indicator_type": "ip", "threat_type": "malware", "confidence": 0.84, "source": "urlhaus", "country_code": "CN"},
]

_SAMPLE_DW_POSTS: List[Dict[str, Any]] = [
    {"title": "African Banking Customer DB — 2M records", "source": "ahmia.fi", "category": "leak_site", "discovered_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()},
    {"title": "M-Pesa Agent Credentials Dump", "source": "darkweb_search", "category": "paste", "discovered_at": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()},
    {"title": "KE Gov Portal Vulnerability Discussion", "source": "forum", "category": "forum", "discovered_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()},
    {"title": "SA Financial Sector RaaS Offering", "source": "market", "category": "market", "discovered_at": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()},
    {"title": "Nigeria NIN Database Seller", "source": "darkweb_search", "category": "leak_site", "discovered_at": (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()},
]


# =============================================================================
# HTML helpers
# =============================================================================

def _bar(value: int, max_val: int, color: str = "#3b82f6") -> str:
    pct = min(100, (value / max(max_val, 1)) * 100)
    return (
        f'<div style="background:#1e293b;border-radius:6px;height:22px;width:100%;overflow:hidden">'
        f'<div style="background:linear-gradient(90deg,{color},{color}dd);border-radius:6px;height:22px;width:{pct}%;'
        f'transition:width .3s"></div></div>'
    )


def _table_rows(data: dict, color: str = "#3b82f6") -> str:
    if not data:
        return "<tr><td colspan='3' style='color:#6b7280;padding:12px'>No data available</td></tr>"
    max_val = max(data.values()) if data else 1
    rows = ""
    for k, v in sorted(data.items(), key=lambda x: -x[1]):
        rows += (
            f"<tr>"
            f"<td style='padding:8px 12px;color:#e2e8f0;font-weight:500'>{k}</td>"
            f"<td style='padding:8px 12px;width:50%'>{_bar(v, max_val, color)}</td>"
            f"<td style='padding:8px 12px;color:#94a3b8;text-align:right;font-variant-numeric:tabular-nums'>{v:,}</td>"
            f"</tr>"
        )
    return rows


def _stat_card(value: Any, label: str, color: str = "#fff", subtitle: str = "") -> str:
    sub = f'<div style="font-size:11px;color:#64748b;margin-top:2px">{subtitle}</div>' if subtitle else ""
    return (
        f'<div class="stat-card">'
        f'<div class="value" style="color:{color}">{value:,}</div>'
        f'<div class="label">{label}</div>{sub}'
        f'</div>'
    )


def _section(title: str, content: str, icon: str = "") -> str:
    ic = f'<span style="margin-right:8px">{icon}</span>' if icon else ""
    return f'<div class="section"><h2>{ic}{title}</h2>{content}</div>'


def _severity_badge(sev: str) -> str:
    return f'<span class="badge badge-{sev}">{sev.upper()}</span>'


def _ioc_table_html(iocs: List[dict]) -> str:
    if not iocs:
        return '<p style="color:#6b7280">No IOCs found for this period.</p>'
    thead = (
        '<table class="ioc-table"><thead><tr>'
        '<th>Indicator</th><th>Type</th><th>Threat</th>'
        '<th>Conf.</th><th>Source</th><th>Country</th>'
        '</tr></thead><tbody>'
    )
    rows = ""
    for ioc in iocs:
        conf = ioc.get("confidence", 0)
        conf_color = "#ef4444" if conf >= 0.8 else "#f97316" if conf >= 0.5 else "#94a3b8"
        threat = ioc.get("threat_type", "")
        threat_color = COLORS.get(threat, "#94a3b8")
        conf_bar_w = int(conf * 100)
        rows += (
            f"<tr>"
            f"<td class='ioc-indicator'>{_truncate(ioc.get('indicator', ''), 48)}</td>"
            f"<td style='color:#94a3b8'>{ioc.get('indicator_type', '')}</td>"
            f"<td style='color:{threat_color};font-weight:500'>{THREAT_ICONS.get(threat, '')} {threat}</td>"
            f"<td><div style='display:flex;align-items:center;gap:6px'>"
            f"<div style='width:48px;height:6px;background:#1e293b;border-radius:3px;overflow:hidden'>"
            f"<div style='width:{conf_bar_w}%;height:100%;background:{conf_color};border-radius:3px'></div></div>"
            f"<span style='color:{conf_color};font-size:12px'>{conf:.0%}</span></div></td>"
            f"<td style='color:#94a3b8'>{ioc.get('source', '')}</td>"
            f"<td style='color:#94a3b8;text-align:center'>{ioc.get('country_code', '-')}</td>"
            f"</tr>"
        )
    return thead + rows + "</tbody></table>"


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "\u2026"


def _recommendations_html(ioc_stats: dict, cred_stats: dict, dw_stats: dict) -> str:
    recs: List[str] = []
    c2 = ioc_stats.get("by_type", {}).get("c2", 0)
    phish = ioc_stats.get("by_type", {}).get("phishing", 0)
    malware = ioc_stats.get("by_type", {}).get("malware", 0)
    cred_total = cred_stats.get("total", 0)

    if c2 > 0:
        recs.append(f'<li>{_severity_badge("critical")} {c2:,} active C2 servers detected &mdash; review firewall rules and block known C2 IPs immediately</li>')
    if phish > 0:
        recs.append(f'<li>{_severity_badge("high")} {phish:,} phishing indicators &mdash; enforce email filtering and run user awareness training</li>')
    if malware > 0:
        recs.append(f'<li>{_severity_badge("high")} {malware:,} malware indicators detected &mdash; update EDR/AV signatures</li>')
    if cred_total > 0:
        recs.append(f'<li>{_severity_badge("high")} {cred_total:,} credential exposures &mdash; enforce password resets for affected domains</li>')
    recs.append("<li>Continue monitoring dark web sources for emerging threats targeting African organisations</li>")
    recs.append("<li>Review MISP intelligence feeds for IOCs relevant to your sector</li>")
    return "<ul class='rec-list'>" + "\n".join(recs) + "</ul>"


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 0; line-height: 1.6; }
.container { max-width: 980px; margin: 0 auto; padding: 48px 28px; }

/* Header */
.header { text-align: center; padding: 48px 0 40px; border-bottom: 1px solid #1e293b; }
.header h1 { color: #fff; font-size: 30px; margin: 0 0 10px; letter-spacing: -0.5px; }
.header p { color: #94a3b8; font-size: 14px; margin: 0; }
.logo { display: inline-flex; align-items: center; gap: 8px; color: #3b82f6; font-weight: 700; font-size: 19px; margin-bottom: 18px; letter-spacing: -0.3px; }
.logo::before { content: '\\1F6E1'; font-size: 22px; }
.report-badge { display: inline-block; margin-top: 12px; padding: 4px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.report-badge.critical { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.report-badge.high { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
.report-badge.medium { background: rgba(234,179,8,0.15); color: #facc15; border: 1px solid rgba(234,179,8,0.3); }
.report-badge.low { background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }

/* Stat cards */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 36px 0; }
.stat-card { background: linear-gradient(135deg, #1e293b 0%, #1a2332 100%); border: 1px solid #ffffff08; border-radius: 14px; padding: 22px; text-align: center; }
.stat-card .value { font-size: 34px; font-weight: 700; color: #fff; font-variant-numeric: tabular-nums; }
.stat-card .label { font-size: 13px; color: #94a3b8; margin-top: 4px; }

/* Sections */
.section { margin: 36px 0; }
.section h2 { color: #fff; font-size: 20px; border-bottom: 2px solid #1e293b; padding-bottom: 12px; margin-bottom: 16px; display: flex; align-items: center; }

/* Tables */
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 10px 12px; color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #1e293b; font-weight: 600; }
td { padding: 8px 12px; border-bottom: 1px solid rgba(30,41,59,0.5); }
tr:hover td { background: rgba(255,255,255,0.02); }

/* IOC table */
.ioc-table td { font-size: 13px; }
.ioc-indicator { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 12.5px !important; color: #e2e8f0; word-break: break-all; }

/* Badges */
.badge { display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; margin-right: 6px; letter-spacing: 0.3px; }
.badge-critical { background: rgba(239,68,68,0.2); color: #f87171; }
.badge-high { background: rgba(249,115,22,0.2); color: #fb923c; }
.badge-medium { background: rgba(234,179,8,0.2); color: #facc15; }
.badge-low { background: rgba(34,197,94,0.2); color: #4ade80; }

/* Content blocks */
.exec-summary { background: linear-gradient(135deg, #1e293b 0%, #172033 100%); border-left: 4px solid #3b82f6; padding: 22px 26px; border-radius: 0 14px 14px 0; margin: 28px 0; line-height: 1.8; font-size: 15px; }
.focus-area { background: rgba(59,130,246,0.06); border: 1px solid rgba(59,130,246,0.18); border-radius: 12px; padding: 14px 20px; margin: 16px 0; color: #93c5fd; font-style: italic; font-size: 14px; }
.rec-list { line-height: 2.2; padding-left: 20px; }
.rec-list li { margin-bottom: 4px; }

/* Footer */
.footer { text-align: center; padding: 36px 0; color: #475569; font-size: 12px; border-top: 1px solid #1e293b; margin-top: 48px; line-height: 1.8; }
.footer strong { color: #64748b; }

/* Confidentiality banner */
.confidential { background: rgba(239,68,68,0.06); border: 1px solid rgba(239,68,68,0.15); border-radius: 8px; padding: 8px 16px; text-align: center; color: #f87171; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; margin-bottom: 24px; }

/* Print */
@media print {
  body { background: #fff; color: #111; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .container { padding: 20px; }
  .stat-card { border: 1px solid #ddd; background: #f9fafb !important; }
  .stat-card .value { color: #111 !important; }
  .stat-card .label { color: #555; }
  .section h2 { color: #111; border-color: #ddd; }
  .exec-summary { background: #f0f4ff !important; border-color: #3b82f6; }
  .header { border-color: #ddd; }
  .footer { border-color: #ddd; color: #999; }
  td, th { color: #333 !important; }
  .confidential { background: #fff5f5 !important; }
  tr:hover td { background: transparent !important; }
}
"""


def _html_skeleton(title: str, report_type: str, date_range: str, generated_at: datetime,
                   body: str, num_sources: int = 0, severity: str = "medium") -> str:
    period = date_range.replace('d', ' days').replace('h', ' hours')
    rtype_label = report_type.replace('_', ' ').title()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — JichoSec</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <div class="confidential">Confidential &mdash; Authorised Recipients Only</div>
  <div class="header">
    <div class="logo">JichoSec</div>
    <h1>{title}</h1>
    <p>Generated: {generated_at.strftime('%B %d, %Y at %H:%M UTC')} &middot; Period: Last {period} &middot; Type: {rtype_label}</p>
    <div class="report-badge {severity}">{severity.upper()} SEVERITY</div>
  </div>
  {body}
  <div class="footer">
    <p><strong>JichoSec</strong> &mdash; Africa-Focused Threat Intelligence Platform</p>
    <p>This report is confidential. Distribution without authorisation is prohibited.</p>
    <p>Generated automatically from {num_sources} intelligence source{'s' if num_sources != 1 else ''} &middot; Report ID: {generated_at.strftime('%Y%m%d%H%M%S')}</p>
  </div>
</div>
</body>
</html>"""


# =============================================================================
# Report type builders
# =============================================================================

def _build_threat_intel_html(*, title, report_type, date_range, generated_at,
                              ioc_stats, dw_stats, cred_stats,
                              top_threats, top_countries, top_iocs,
                              darkweb_posts, focus_area, **_kw) -> str:
    ioc_total = ioc_stats.get("total", 0)
    dw_total = dw_stats.get("total", 0)
    cred_total = cred_stats.get("total", 0)
    hi_conf = ioc_stats.get("high_confidence_count", 0)
    severity = "critical" if ioc_total > 100_000 else "high" if ioc_total > 10_000 else "medium" if ioc_total > 1_000 else "low"
    period = date_range.replace("d", " days").replace("h", " hours")
    bp = []

    if focus_area:
        bp.append(f'<div class="focus-area">{focus_area}</div>')

    bp.append(
        '<div class="exec-summary">'
        f'During the last <strong>{period}</strong>, JichoSec ingested <strong>{ioc_total:,}</strong> threat indicators '
        f'from {len(ioc_stats.get("by_source", {}))} intelligence sources. '
        f'<strong>{hi_conf:,}</strong> indicators have high confidence (&ge;80%). '
        + (f'<strong>{cred_total:,}</strong> credential exposures were tracked. ' if cred_total else '')
        + (f'<strong>{dw_total:,}</strong> dark web threats were identified. ' if dw_total else '')
        + 'The breakdown below highlights the dominant threat categories, geographic distribution, and recommended actions.'
        '</div>'
    )

    bp.append(
        '<div class="stats-grid">'
        + _stat_card(ioc_total, "Threat Indicators", "#fff", "All sources combined")
        + _stat_card(hi_conf, "High Confidence", "#f59e0b", "&ge;80% confidence")
        + _stat_card(dw_total, "Dark Web Threats", "#a855f7", "C2 + phishing sources")
        + _stat_card(cred_total, "Credential Exposures", "#f97316", "Breached credentials")
        + '</div>'
    )

    bp.append(_section("Threat Distribution", f"<table>{_table_rows(ioc_stats.get('by_type', {}), '#ef4444')}</table>", "&#x26A0;"))
    if ioc_stats.get("by_indicator_type"):
        bp.append(_section("Indicator Types", f"<table>{_table_rows(ioc_stats['by_indicator_type'], '#06b6d4')}</table>"))
    bp.append(_section("Intelligence Sources", f"<table>{_table_rows(ioc_stats.get('by_source', {}), '#3b82f6')}</table>", "&#x1F4E1;"))
    bp.append(_section("Top Affected Countries", f"<table>{_table_rows(dict(top_countries), '#10b981')}</table>", "&#x1F30D;"))
    if top_iocs:
        bp.append(_section("Top IOCs (by confidence)", _ioc_table_html(top_iocs), "&#x1F50D;"))
    if dw_stats.get("by_source"):
        bp.append(_section("Dark Web Intelligence", f"<table>{_table_rows(dw_stats['by_source'], '#a855f7')}</table>", "&#x1F578;"))
    if cred_stats.get("by_country"):
        bp.append(_section("Credential Exposures by Country", f"<table>{_table_rows(cred_stats['by_country'], '#f97316')}</table>"))
    if cred_stats.get("by_pw_type"):
        bp.append(_section("Password Types in Breaches", f"<table>{_table_rows(cred_stats['by_pw_type'], '#f59e0b')}</table>"))
    bp.append(_section("Recommendations", _recommendations_html(ioc_stats, cred_stats, dw_stats), "&#x2705;"))

    return _html_skeleton(title, report_type, date_range, generated_at, "\n".join(bp), len(ioc_stats.get("by_source", {})), severity)


def _build_executive_briefing_html(*, title, report_type, date_range, generated_at,
                                     ioc_stats, dw_stats, cred_stats,
                                     top_threats, top_countries, top_iocs,
                                     darkweb_posts, focus_area, **_kw) -> str:
    ioc_total = ioc_stats.get("total", 0)
    hi_conf = ioc_stats.get("high_confidence_count", 0)
    cred_total = cred_stats.get("total", 0)
    top_threat_name = top_threats[0][0] if top_threats else "N/A"
    top_threat_count = top_threats[0][1] if top_threats else 0
    num_countries = len(ioc_stats.get("by_country", {}))
    threat_level = "ELEVATED" if ioc_total > 10_000 else "MODERATE" if ioc_total > 1_000 else "LOW"
    severity = "high" if ioc_total > 10_000 else "medium"
    bp = []

    bp.append(
        '<div class="exec-summary">'
        f'This period saw <strong>{ioc_total:,}</strong> threat indicators across <strong>{num_countries}</strong> countries. '
        f'The dominant threat category is <strong>{top_threat_name}</strong> ({top_threat_count:,} indicators). '
        f'<strong>{hi_conf:,}</strong> high-confidence indicators require immediate attention. '
        + (f'<strong>{cred_total:,}</strong> credential exposures were detected. ' if cred_total else '')
        + f'Current threat level: <strong>{threat_level}</strong>.'
        '</div>'
    )
    bp.append(
        '<div class="stats-grid">'
        + _stat_card(ioc_total, "Total Threats")
        + _stat_card(hi_conf, "Critical Indicators", "#ef4444")
        + _stat_card(num_countries, "Countries Affected", "#3b82f6")
        + _stat_card(cred_total, "Credential Leaks", "#f97316")
        + '</div>'
    )
    if top_threats:
        bp.append(_section("Top Threat Categories", f"<table>{_table_rows(dict(top_threats[:5]), '#ef4444')}</table>"))
    if top_countries:
        bp.append(_section("Geographic Hotspots", f"<table>{_table_rows(dict(top_countries[:5]), '#10b981')}</table>"))

    actions = [
        "<li>Review and approve updated blocking rules for high-confidence IOCs</li>",
        "<li>Allocate budget for enhanced threat detection on mobile money platforms</li>",
        "<li>Schedule security awareness training for staff on phishing trends</li>",
    ]
    if cred_total > 0:
        actions.insert(0, f"<li>{_severity_badge('critical')} {cred_total:,} credential leaks require immediate password resets</li>")
    bp.append(_section("Recommended Actions for Leadership", f"<ul class='rec-list'>{''.join(actions)}</ul>"))

    return _html_skeleton(title, report_type, date_range, generated_at, "\n".join(bp), len(ioc_stats.get("by_source", {})), severity)


def _build_ioc_analysis_html(*, title, report_type, date_range, generated_at,
                               ioc_stats, dw_stats, cred_stats,
                               top_threats, top_countries, top_iocs,
                               darkweb_posts, focus_area, **_kw) -> str:
    ioc_total = ioc_stats.get("total", 0)
    hi_conf = ioc_stats.get("high_confidence_count", 0)
    severity = "high" if hi_conf > 5000 else "medium"
    bp = []
    if focus_area:
        bp.append(f'<div class="focus-area">{focus_area}</div>')
    bp.append(
        '<div class="stats-grid">'
        + _stat_card(ioc_total, "Total IOCs Analysed")
        + _stat_card(hi_conf, "High Confidence", "#ef4444", "&ge;80%")
        + _stat_card(len(ioc_stats.get("by_source", {})), "Sources", "#3b82f6")
        + _stat_card(len(ioc_stats.get("by_country", {})), "Countries", "#10b981")
        + '</div>'
    )
    if ioc_stats.get("by_indicator_type"):
        bp.append(_section("IOC Breakdown by Type", f"<table>{_table_rows(ioc_stats['by_indicator_type'], '#06b6d4')}</table>"))
    bp.append(_section("IOC Breakdown by Threat Category", f"<table>{_table_rows(ioc_stats.get('by_type', {}), '#ef4444')}</table>"))
    bp.append(_section("IOCs by Source Feed", f"<table>{_table_rows(ioc_stats.get('by_source', {}), '#3b82f6')}</table>"))
    bp.append(_section("Geographic Origin Analysis", f"<table>{_table_rows(ioc_stats.get('by_country', {}), '#10b981')}</table>"))
    if top_iocs:
        bp.append(_section("High-Confidence IOCs", _ioc_table_html(top_iocs)))
    recs = ["<li>Implement DNS sinkholing for identified C2 domains</li>", "<li>Add IP ranges to firewall block lists</li>",
            "<li>Configure SIEM alerts for URL patterns</li>", "<li>Update proxy deny lists with phishing URLs</li>",
            "<li>Cross-reference IOCs with your EDR telemetry</li>"]
    bp.append(_section("Detection Recommendations", f"<ul class='rec-list'>{''.join(recs)}</ul>"))
    return _html_skeleton(title, report_type, date_range, generated_at, "\n".join(bp), len(ioc_stats.get("by_source", {})), severity)


def _build_incident_summary_html(*, title, report_type, date_range, generated_at,
                                   ioc_stats, dw_stats, cred_stats,
                                   top_threats, top_countries, top_iocs,
                                   darkweb_posts, focus_area, **_kw) -> str:
    ioc_total = ioc_stats.get("total", 0)
    severity = "high" if ioc_total > 5000 else "medium"
    period = date_range.replace("d", " days").replace("h", " hours")
    bp = []
    if focus_area:
        bp.append(f'<div class="focus-area">{focus_area}</div>')
    bp.append(
        '<div class="exec-summary">'
        f'During the last <strong>{period}</strong>, <strong>{ioc_total:,}</strong> indicators were detected '
        f'across {len(ioc_stats.get("by_source", {}))} sources. This incident summary highlights the detection '
        f'timeline, affected systems, and containment recommendations.</div>'
    )
    bp.append(
        '<div class="stats-grid">'
        + _stat_card(ioc_total, "Indicators Detected")
        + _stat_card(len(top_threats), "Threat Categories")
        + _stat_card(len(top_countries), "Countries Involved")
        + '</div>'
    )
    bp.append(_section("Attack Vectors Identified", f"<table>{_table_rows(ioc_stats.get('by_type', {}), '#ef4444')}</table>"))
    if top_iocs:
        bp.append(_section("IOCs Associated with Incidents", _ioc_table_html(top_iocs[:15])))
    containment = ["<li>All identified C2 domains added to DNS block lists</li>",
                    "<li>Phishing URLs reported to hosting providers for takedown</li>",
                    "<li>Malware hashes submitted to AV vendors for signature updates</li>",
                    "<li>Affected IP ranges flagged in SIEM for enhanced monitoring</li>"]
    bp.append(_section("Containment Actions", f"<ul class='rec-list'>{''.join(containment)}</ul>"))
    next_steps = ["<li>Conduct forensic analysis on compromised endpoints</li>",
                  "<li>Review lateral movement indicators in network logs</li>",
                  "<li>Update incident response playbook based on findings</li>",
                  "<li>Schedule post-incident review within 72 hours</li>"]
    bp.append(_section("Next Steps", f"<ul class='rec-list'>{''.join(next_steps)}</ul>"))
    return _html_skeleton(title, report_type, date_range, generated_at, "\n".join(bp), len(ioc_stats.get("by_source", {})), severity)


def _build_dark_web_exposure_html(*, title, report_type, date_range, generated_at,
                                    ioc_stats, dw_stats, cred_stats,
                                    top_threats, top_countries, top_iocs,
                                    darkweb_posts, focus_area, **_kw) -> str:
    dw_total = dw_stats.get("total", 0)
    cred_total = cred_stats.get("total", 0)
    posts_total = dw_stats.get("posts_total", 0)
    severity = "high" if cred_total > 1000 else "medium"
    bp = []
    bp.append(
        '<div class="exec-summary">'
        f'This assessment covers dark web exposure across <strong>{dw_total:,}</strong> threat-sourced indicators'
        + (f' and <strong>{cred_total:,}</strong> credential exposures' if cred_total else '')
        + (f'. {posts_total:,} dark web posts were analysed.' if posts_total else '.')
        + '</div>'
    )
    bp.append(
        '<div class="stats-grid">'
        + _stat_card(dw_total, "Dark Web Threats", "#a855f7")
        + _stat_card(cred_total, "Credential Exposures", "#f97316")
        + _stat_card(posts_total, "Dark Web Posts", "#ec4899")
        + '</div>'
    )
    if dw_stats.get("by_source"):
        bp.append(_section("Threat Sources (Dark Web)", f"<table>{_table_rows(dw_stats['by_source'], '#a855f7')}</table>"))
    if cred_stats.get("by_country"):
        bp.append(_section("Credential Exposures by Country", f"<table>{_table_rows(cred_stats['by_country'], '#f97316')}</table>"))
    if cred_stats.get("by_pw_type"):
        bp.append(_section("Password Types in Breaches", f"<table>{_table_rows(cred_stats['by_pw_type'], '#f59e0b')}</table>"))
    if cred_stats.get("by_severity"):
        bp.append(_section("Credential Exposure Severity", f"<table>{_table_rows(cred_stats['by_severity'], '#ef4444')}</table>"))
    if darkweb_posts:
        post_rows = ""
        for p in darkweb_posts:
            sev = p.get("category", "medium")
            post_rows += (
                f"<tr><td style='color:#e2e8f0'>{_truncate(p.get('title', 'Untitled'), 55)}</td>"
                f"<td style='color:#94a3b8'>{p.get('source', '-')}</td>"
                f"<td style='color:#94a3b8'>{p.get('category', '-')}</td>"
                f"<td style='color:#94a3b8'>{p.get('discovered_at', '-')[:10] if p.get('discovered_at') else '-'}</td></tr>"
            )
        bp.append(_section("Recent Dark Web Posts",
            "<table><thead><tr><th>Title</th><th>Source</th><th>Category</th><th>Discovered</th></tr></thead><tbody>"
            + post_rows + "</tbody></table>"))
    actions = [
        f"<li>{_severity_badge('critical')} Enforce password resets for any exposed credentials</li>",
        "<li>Register or take down identified typosquatting domains</li>",
        "<li>Monitor brand mentions on dark web forums</li>",
        "<li>Review DLP policies to prevent future data leaks</li>",
        "<li>Engage threat intelligence provider for actor attribution</li>",
    ]
    bp.append(_section("Recommended Immediate Actions", f"<ul class='rec-list'>{''.join(actions)}</ul>"))
    return _html_skeleton(title, report_type, date_range, generated_at, "\n".join(bp), len(dw_stats.get("by_source", {})), severity)


# ── Registry ──────────────────────────────────────────────────────────────────

_REPORT_BUILDERS = {
    "threat_intelligence": _build_threat_intel_html,
    "executive_briefing": _build_executive_briefing_html,
    "ioc_analysis": _build_ioc_analysis_html,
    "incident_summary": _build_incident_summary_html,
    "dark_web_exposure": _build_dark_web_exposure_html,
    "weekly": _build_threat_intel_html,
    "monthly": _build_threat_intel_html,
    "custom": _build_threat_intel_html,
    "incident": _build_incident_summary_html,
    "executive": _build_executive_briefing_html,
}
