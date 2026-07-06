#!/usr/bin/env python3
"""
Rebuild all Kibana dashboards using the Kibana saved-objects API.
Uses Lens visualizations (Kibana 8.x) with correct field names from each index.
Run: python3 kibana/rebuild_dashboards.py
"""

import json
import uuid
import base64
import urllib.request

KIBANA = "http://192.168.36.51:5601"
AUTH = base64.b64encode(b"elastic:jichodns_elastic_2024").decode()
HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
    "Authorization": f"Basic {AUTH}",
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def api(method: str, path: str, body: dict = None) -> dict:
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"{KIBANA}{path}", data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  ERROR {e.code} on {method} {path}: {e.read().decode()[:300]}")
        return {}


def save_object(obj_type: str, obj_id: str, attrs: dict) -> bool:
    result = api("POST", f"/api/saved_objects/{obj_type}/{obj_id}?overwrite=true", {"attributes": attrs})
    ok = "id" in result
    if not ok:
        print(f"  FAILED saving {obj_type}/{obj_id}")
    return ok


def delete_object(obj_type: str, obj_id: str):
    req = urllib.request.Request(
        f"{KIBANA}/api/saved_objects/{obj_type}/{obj_id}",
        headers=HEADERS, method="DELETE"
    )
    try:
        urllib.request.urlopen(req)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Index pattern helper
# ---------------------------------------------------------------------------

def ensure_index_pattern(pid: str, title: str, time_field: str = "created_at"):
    result = api("POST", f"/api/saved_objects/index-pattern/{pid}?overwrite=true", {
        "attributes": {
            "title": title,
            "timeFieldName": time_field,
        }
    })
    ok = "id" in result
    print(f"  index-pattern '{title}': {'OK' if ok else 'FAILED'}")
    return ok


# ---------------------------------------------------------------------------
# Lens visualization builder
# ---------------------------------------------------------------------------

def metric_vis(title: str, index_id: str, index_title: str, filter_kql: str = "") -> dict:
    """Single metric count."""
    return {
        "title": title,
        "visualizationType": "lnsMetric",
        "type": "lens",
        "references": [{"id": index_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col1"],
                            "columns": {
                                "col1": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "operationType": "count",
                                    "sourceField": "___records___",
                                }
                            },
                        }
                    }
                }
            },
            "filters": [{"query": {"query_string": {"query": filter_kql}}, "meta": {}}] if filter_kql else [],
            "query": {"language": "kuery", "query": filter_kql},
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "metricAccessor": "col1",
            },
        },
    }


def donut_vis(title: str, index_id: str, field: str) -> dict:
    """Donut breakdown by field."""
    return {
        "title": title,
        "visualizationType": "lnsPie",
        "type": "lens",
        "references": [{"id": index_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_bucket", "col_count"],
                            "columns": {
                                "col_bucket": {
                                    "label": field,
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "operationType": "terms",
                                    "sourceField": field,
                                    "params": {"size": 10, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": True},
                                },
                                "col_count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "operationType": "count",
                                    "sourceField": "___records___",
                                },
                            },
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "shape": "donut",
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "primaryGroups": ["col_bucket"],
                    "metric": "col_count",
                }],
            },
        },
    }


def bar_vis(title: str, index_id: str, field: str) -> dict:
    """Horizontal bar by field."""
    return {
        "title": title,
        "visualizationType": "lnsXY",
        "type": "lens",
        "references": [{"id": index_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        "state": {
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        "layer1": {
                            "columnOrder": ["col_bucket", "col_count"],
                            "columns": {
                                "col_bucket": {
                                    "label": field,
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "operationType": "terms",
                                    "sourceField": field,
                                    "params": {"size": 10, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": False},
                                },
                                "col_count": {
                                    "label": "Count",
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "operationType": "count",
                                    "sourceField": "___records___",
                                },
                            },
                        }
                    }
                }
            },
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "legend": {"isVisible": True, "position": "right"},
                "valueLabels": "hide",
                "fittingFunction": "None",
                "layers": [{
                    "layerId": "layer1",
                    "layerType": "data",
                    "seriesType": "bar_horizontal",
                    "xAccessor": "col_bucket",
                    "accessors": ["col_count"],
                }],
            },
        },
    }


def area_vis(title: str, index_id: str, time_field: str, breakdown_field: str = None) -> dict:
    """Area chart over time."""
    columns = {
        "col_time": {
            "label": time_field,
            "dataType": "date",
            "isBucketed": True,
            "operationType": "date_histogram",
            "sourceField": time_field,
            "params": {"interval": "auto"},
        },
        "col_count": {
            "label": "Count",
            "dataType": "number",
            "isBucketed": False,
            "operationType": "count",
            "sourceField": "___records___",
        },
    }
    col_order = ["col_time", "col_count"]
    layer = {
        "layerId": "layer1",
        "layerType": "data",
        "seriesType": "area_stacked",
        "xAccessor": "col_time",
        "accessors": ["col_count"],
    }
    if breakdown_field:
        columns["col_break"] = {
            "label": breakdown_field,
            "dataType": "string",
            "isBucketed": True,
            "operationType": "terms",
            "sourceField": breakdown_field,
            "params": {"size": 5, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": True},
        }
        col_order = ["col_time", "col_break", "col_count"]
        layer["splitAccessor"] = "col_break"

    return {
        "title": title,
        "visualizationType": "lnsXY",
        "type": "lens",
        "references": [{"id": index_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        "state": {
            "datasourceStates": {"formBased": {"layers": {"layer1": {"columnOrder": col_order, "columns": columns}}}},
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "legend": {"isVisible": True, "position": "right"},
                "layers": [layer],
            },
        },
    }


def table_vis(title: str, index_id: str, fields: list[str]) -> dict:
    """Datatable showing specific fields."""
    columns_def = {}
    col_order = []
    for f in fields:
        cid = f"col_{f}"
        col_order.append(cid)
        columns_def[cid] = {
            "label": f.replace("_", " ").title(),
            "dataType": "string",
            "isBucketed": True,
            "operationType": "terms",
            "sourceField": f,
            "params": {"size": 50, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": False},
        }
    col_order.append("col_count")
    columns_def["col_count"] = {
        "label": "Count",
        "dataType": "number",
        "isBucketed": False,
        "operationType": "count",
        "sourceField": "___records___",
    }
    return {
        "title": title,
        "visualizationType": "lnsDatatable",
        "type": "lens",
        "references": [{"id": index_id, "name": "indexpattern-datasource-layer-layer1", "type": "index-pattern"}],
        "state": {
            "datasourceStates": {"formBased": {"layers": {"layer1": {"columnOrder": col_order, "columns": columns_def}}}},
            "filters": [],
            "query": {"language": "kuery", "query": ""},
            "visualization": {
                "layerId": "layer1",
                "layerType": "data",
                "columns": [{"columnId": c} for c in col_order],
            },
        },
    }


# ---------------------------------------------------------------------------
# Dashboard builder
# ---------------------------------------------------------------------------

PANEL_W, PANEL_H = 24, 10

def make_panel(vis_id: str, x: int, y: int, w: int = PANEL_W, h: int = PANEL_H) -> dict:
    return {
        "version": "8.8.0",
        "type": "lens",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": vis_id},
        "panelIndex": vis_id,
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": f"panel_{vis_id}",
    }


def save_dashboard(dash_id: str, title: str, desc: str, vis_ids: list[str], time_from: str = "now-90d") -> bool:
    panels = []
    refs = []
    positions = [
        (0, 0, 16, 8), (16, 0, 16, 8), (32, 0, 16, 8),   # row 1: 3 metrics
        (0, 8, 24, 12), (24, 8, 24, 12),                   # row 2: 2 charts
        (0, 20, 48, 10),                                    # row 3: full-width timeline
        (0, 30, 24, 12), (24, 30, 24, 12),                 # row 4: 2 tables
    ]
    for i, vis_id in enumerate(vis_ids[:8]):
        x, y, w, h = positions[i] if i < len(positions) else (0, 40 + i * 12, 48, 10)
        panel_key = f"p{i}"
        panels.append({
            "version": "8.8.0",
            "type": "lens",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_key},
            "panelIndex": panel_key,
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": f"panel_{panel_key}",
        })
        refs.append({"id": vis_id, "name": f"panel_p{i}", "type": "lens"})

    return save_object("dashboard", dash_id, {
        "title": title,
        "description": desc,
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
        "timeFrom": time_from,
        "timeTo": "now",
        "timeRestore": True,
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    })


# ---------------------------------------------------------------------------
# Build: Threat Intelligence Overview
# ---------------------------------------------------------------------------

def build_threat_intelligence():
    print("\n=== Threat Intelligence Overview ===")
    pid = "iocs-ip-v2"
    ensure_index_pattern(pid, "iocs", "first_seen")

    vids = []

    specs = [
        ("ti-total-iocs",    metric_vis("Total IOCs", pid, "iocs")),
        ("ti-type-donut",    donut_vis("IOCs by Threat Type", pid, "threat_type")),
        ("ti-ind-donut",     donut_vis("IOCs by Indicator Type", pid, "indicator_type")),
        ("ti-source-bar",    bar_vis("Top Sources", pid, "source")),
        ("ti-country-bar",   bar_vis("Top Countries", pid, "country")),
        ("ti-trend-area",    area_vis("IOC Trend Over Time", pid, "first_seen", "threat_type")),
        ("ti-malware-bar",   bar_vis("Top Malware Families", pid, "malware")),
        ("ti-table",         table_vis("Recent IOCs", pid, ["indicator_type", "threat_type", "source", "country"])),
    ]
    for vis_id, attrs in specs:
        ok = save_object("lens", vis_id, attrs)
        print(f"  vis '{attrs['title']}': {'OK' if ok else 'FAIL'}")
        if ok:
            vids.append(vis_id)

    ok = save_dashboard("dash-threat-intelligence", "Threat Intelligence Overview",
                        "Real-time view of IOCs by type, source, and geography", vids)
    print(f"  dashboard: {'OK' if ok else 'FAIL'}")


# ---------------------------------------------------------------------------
# Build: Dark Web Monitoring
# ---------------------------------------------------------------------------

def build_darkweb():
    print("\n=== Dark Web Monitoring ===")
    leaks_pid = "darkweb-leaks-ip-v2"
    mentions_pid = "darkweb-mentions-ip-v2"
    breaches_pid = "data-breaches-ip-v2"

    ensure_index_pattern(leaks_pid, "darkweb_leaks", "date_discovered")
    ensure_index_pattern(mentions_pid, "darkweb_mentions", "date_discovered")
    ensure_index_pattern(breaches_pid, "data_breaches", "date_discovered")

    specs = [
        ("dw-total-leaks",      metric_vis("Leaked Records", leaks_pid, "darkweb_leaks")),
        ("dw-total-mentions",   metric_vis("Dark Web Mentions", mentions_pid, "darkweb_mentions")),
        ("dw-total-breaches",   metric_vis("Data Breaches", breaches_pid, "data_breaches")),
        ("dw-leak-severity",    donut_vis("Leaks by Severity", leaks_pid, "severity")),
        ("dw-mentions-type",    donut_vis("Mentions by Type", mentions_pid, "mention_type")),
        ("dw-leaks-timeline",   area_vis("Leak Discovery Timeline", leaks_pid, "date_discovered", "severity")),
        ("dw-domain-bar",       bar_vis("Most Targeted Domains", leaks_pid, "affected_domain")),
        ("dw-breaches-table",   table_vis("Recent Breaches", breaches_pid, ["severity", "status"])),
    ]
    vids = []
    for vis_id, attrs in specs:
        ok = save_object("lens", vis_id, attrs)
        print(f"  vis '{attrs['title']}': {'OK' if ok else 'FAIL'}")
        if ok:
            vids.append(vis_id)

    ok = save_dashboard("dash-darkweb", "Dark Web Monitoring",
                        "Leaked credentials, data breaches, and threat actor mentions", vids,
                        time_from="now-90d")
    print(f"  dashboard: {'OK' if ok else 'FAIL'}")


# ---------------------------------------------------------------------------
# Build: Attack Surface Management
# ---------------------------------------------------------------------------

def build_asm():
    print("\n=== Attack Surface Management ===")
    assets_pid = "assets-ip-v2"
    vulns_pid = "vulns-ip-v2"

    ensure_index_pattern(assets_pid, "assets", "created_at")
    ensure_index_pattern(vulns_pid, "vulnerabilities", "date_discovered")

    specs = [
        ("asm-total-assets",     metric_vis("Total Assets", assets_pid, "assets")),
        ("asm-total-vulns",      metric_vis("Total Vulnerabilities", vulns_pid, "vulnerabilities")),
        ("asm-critical-vulns",   metric_vis("Critical Vulnerabilities", vulns_pid, "vulnerabilities", "severity: critical")),
        ("asm-asset-type",       donut_vis("Assets by Type", assets_pid, "asset_type")),
        ("asm-vuln-severity",    bar_vis("Vulnerabilities by Severity", vulns_pid, "severity")),
        ("asm-asset-timeline",   area_vis("Asset Discovery Timeline", assets_pid, "created_at", "asset_type")),
        ("asm-services-bar",     bar_vis("Exposed Services", assets_pid, "service")),
        ("asm-vuln-table",       table_vis("Vulnerability Details", vulns_pid, ["severity", "vulnerability_type", "status"])),
    ]
    vids = []
    for vis_id, attrs in specs:
        ok = save_object("lens", vis_id, attrs)
        print(f"  vis '{attrs['title']}': {'OK' if ok else 'FAIL'}")
        if ok:
            vids.append(vis_id)

    ok = save_dashboard("dash-asm", "Attack Surface Management",
                        "Discovered assets, vulnerabilities, and exposed services", vids)
    print(f"  dashboard: {'OK' if ok else 'FAIL'}")


# ---------------------------------------------------------------------------
# Build: Brand Protection
# ---------------------------------------------------------------------------

def build_brand():
    print("\n=== Brand Protection ===")
    monitors_pid = "brand-monitors-ip-v2"
    typosquat_pid = "typosquats-ip-v2"
    alerts_pid = "brand-alerts-ip-v2"

    ensure_index_pattern(monitors_pid, "brand_monitors", "created_at")
    ensure_index_pattern(typosquat_pid, "typosquat_domains", "date_discovered")
    ensure_index_pattern(alerts_pid, "brand_alerts", "detected_at")

    specs = [
        ("brand-monitors-count",  metric_vis("Monitored Brands", monitors_pid, "brand_monitors")),
        ("brand-typosquats-count", metric_vis("Typosquats Detected", typosquat_pid, "typosquat_domains")),
        ("brand-phishing-count",  metric_vis("Active Phishing Sites", typosquat_pid, "typosquat_domains", "is_phishing: true")),
        ("brand-technique-donut", donut_vis("Typosquats by Technique", typosquat_pid, "technique")),
        ("brand-name-bar",        bar_vis("Typosquats by Brand", typosquat_pid, "brand_name")),
        ("brand-timeline",        area_vis("Detection Timeline", typosquat_pid, "date_discovered", "brand_name")),
        ("brand-alert-type",      bar_vis("Alerts by Type", alerts_pid, "alert_type")),
        ("brand-alerts-table",    table_vis("Recent Alerts", alerts_pid, ["severity", "alert_type", "brand_name"])),
    ]
    vids = []
    for vis_id, attrs in specs:
        ok = save_object("lens", vis_id, attrs)
        print(f"  vis '{attrs['title']}': {'OK' if ok else 'FAIL'}")
        if ok:
            vids.append(vis_id)

    ok = save_dashboard("dash-brand", "Brand Protection",
                        "Typosquatting, phishing, and brand impersonation monitoring", vids,
                        time_from="now-90d")
    print(f"  dashboard: {'OK' if ok else 'FAIL'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Rebuilding JichoDNS Kibana dashboards with correct field names...\n")
    build_threat_intelligence()
    build_darkweb()
    build_asm()
    build_brand()
    print("\n=== Summary ===")
    result = api("GET", "/api/saved_objects/_find?type=dashboard&per_page=20")
    total = result.get("total", 0)
    print(f"Total dashboards in Kibana: {total}")
    for obj in result.get("saved_objects", []):
        print(f"  - {obj['attributes']['title']}")
    print("\nOpen Kibana: http://192.168.36.51:5601/app/dashboards")
