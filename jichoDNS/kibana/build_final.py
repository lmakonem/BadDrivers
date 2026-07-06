#!/usr/bin/env python3
"""
Build all 4 JichoDNS Kibana dashboards from scratch with verified field names.

Verified time fields per index:
  iocs              → first_seen
  assets            → created_at
  vulnerabilities   → date_discovered
  darkweb_leaks     → date_discovered
  darkweb_mentions  → date_discovered
  data_breaches     → date_discovered
  brand_monitors    → created_at
  typosquat_domains → date_discovered
  brand_alerts      → detected_at
"""

import json, uuid, base64, urllib.request, urllib.error, os, sys

KIBANA = "http://192.168.36.51:5601"
AUTH   = base64.b64encode(b"elastic:jichodns_elastic_2024").decode()
HDRS   = {"kbn-xsrf":"true","Authorization":f"Basic {AUTH}","Content-Type":"application/json"}

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def api(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"{KIBANA}{path}", data=data, headers=HDRS, method=method)
    try:
        with urllib.request.urlopen(req) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} {method} {path}: {e.read().decode()[:200]}")
        return {}

def post_so(kind, oid, attrs, refs):
    r = api("POST", f"/api/saved_objects/{kind}/{oid}?overwrite=true",
            {"attributes": attrs, "references": refs, "migrationVersion": {}})
    return "id" in r

# ---------------------------------------------------------------------------
# Index patterns  (created directly — most reliable method)
# ---------------------------------------------------------------------------
INDEX_PATTERNS = {
    "ip-iocs":      ("iocs",              "first_seen"),
    "ip-assets":    ("assets",            "created_at"),
    "ip-vulns":     ("vulnerabilities",   "date_discovered"),
    "ip-dw-leaks":  ("darkweb_leaks",     "date_discovered"),
    "ip-dw-ment":   ("darkweb_mentions",  "date_discovered"),
    "ip-dw-breach": ("data_breaches",     "date_discovered"),
    "ip-bm":        ("brand_monitors",    "created_at"),
    "ip-typo":      ("typosquat_domains", "date_discovered"),
    "ip-balerts":   ("brand_alerts",      "detected_at"),
}

def make_index_patterns():
    for pid, (title, tfield) in INDEX_PATTERNS.items():
        ok = post_so("index-pattern", pid,
                     {"title": title, "timeFieldName": tfield,
                      "fields": "[]", "fieldAttrs": "{}", "fieldFormatMap": "{}",
                      "runtimeFieldMap": "{}", "sourceFilters": "[]", "typeMeta": "{}"},
                     [])
        status = "OK" if ok else "FAIL"
        print(f"  index-pattern {title} ({tfield}): {status}")

# ---------------------------------------------------------------------------
# Visualization builders
# ---------------------------------------------------------------------------
def ss_json(pid, kql=""):
    return json.dumps({"query":{"query": kql,"language":"kuery"},"filter":[],"index": pid})

def ip_ref(pid):
    return [{"id": pid, "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern"}]

def make_metric(vid, title, pid, kql=""):
    aggs = [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"}]
    params = {
        "addTooltip": True, "addLegend": False, "type": "metric",
        "metric": {
            "percentageMode": False, "useRanges": False,
            "colorSchema": "Green to Red", "metricColorMode": "None",
            "colorsRange": [{"from":0,"to":100000000}],
            "labels": {"show": True}, "invertColors": False,
            "style": {"bgFill":"#000","bgColor":False,"labelColor":False,
                      "subText":"","fontSize":60}
        }
    }
    ok = post_so("visualization", vid, {
        "title": title,
        "visState": json.dumps({"title":title,"type":"metric","aggs":aggs,"params":params}),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss_json(pid, kql)}
    }, ip_ref(pid))
    print(f"  metric  '{title}': {'OK' if ok else 'FAIL'}")

def make_pie(vid, title, pid, field):
    aggs = [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms",
         "params":{"field":field,"orderBy":"1","order":"desc","size":10,
                   "otherBucket":True,"missingBucket":False},"schema":"segment"}
    ]
    params = {"type":"pie","addTooltip":True,"addLegend":True,"legendPosition":"right",
               "isDonut":True,"labels":{"show":True,"values":True,"last_level":True,"truncate":100}}
    ok = post_so("visualization", vid, {
        "title": title,
        "visState": json.dumps({"title":title,"type":"pie","aggs":aggs,"params":params}),
        "uiStateJSON":"{}","description":"",
        "kibanaSavedObjectMeta":{"searchSourceJSON": ss_json(pid)}
    }, ip_ref(pid))
    print(f"  pie     '{title}': {'OK' if ok else 'FAIL'}")

def make_hbar(vid, title, pid, field):
    aggs = [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"terms",
         "params":{"field":field,"orderBy":"1","order":"desc","size":10,
                   "otherBucket":False,"missingBucket":False},"schema":"segment"}
    ]
    params = {
        "type":"histogram","grid":{"categoryLines":False},
        "categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"left","show":True,
                          "style":{},"scale":{"type":"linear"},
                          "labels":{"show":True,"filter":True,"truncate":200},"title":{}}],
        "valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"bottom",
                       "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                       "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                       "title":{"text":"Count"}}],
        "seriesParams":[{"show":True,"type":"histogram","mode":"normal",
                          "data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1",
                          "drawLinesBetweenPoints":True,"lineWidth":2,"showCircles":True}],
        "addTooltip":True,"addLegend":False,"legendPosition":"right",
        "times":[],"addTimeMarker":False
    }
    ok = post_so("visualization", vid, {
        "title": title,
        "visState": json.dumps({"title":title,"type":"horizontal_bar","aggs":aggs,"params":params}),
        "uiStateJSON":"{}","description":"",
        "kibanaSavedObjectMeta":{"searchSourceJSON": ss_json(pid)}
    }, ip_ref(pid))
    print(f"  hbar    '{title}': {'OK' if ok else 'FAIL'}")

def make_area(vid, title, pid, time_field, split_field=None):
    aggs = [
        {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
        {"id":"2","enabled":True,"type":"date_histogram",
         "params":{"field":time_field,"useNormalizedEsInterval":True,
                   "interval":"auto","drop_partials":False,"min_doc_count":1,
                   "extended_bounds":{}},"schema":"segment"}
    ]
    if split_field:
        aggs.append({"id":"3","enabled":True,"type":"terms",
                      "params":{"field":split_field,"orderBy":"1","order":"desc",
                                "size":5,"otherBucket":True},"schema":"group"})
    params = {
        "type":"area","grid":{"categoryLines":False},
        "categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":True,
                          "style":{},"scale":{"type":"linear"},
                          "labels":{"show":True,"filter":True,"truncate":100},"title":{}}],
        "valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left",
                       "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                       "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                       "title":{"text":"Count"}}],
        "seriesParams":[{"show":True,"type":"area","mode":"stacked",
                          "data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1",
                          "drawLinesBetweenPoints":True,"lineWidth":2,
                          "interpolate":"linear","showCircles":True}],
        "addTooltip":True,"addLegend":True,"legendPosition":"right",
        "times":[],"addTimeMarker":False
    }
    ok = post_so("visualization", vid, {
        "title": title,
        "visState": json.dumps({"title":title,"type":"area","aggs":aggs,"params":params}),
        "uiStateJSON":"{}","description":"",
        "kibanaSavedObjectMeta":{"searchSourceJSON": ss_json(pid)}
    }, ip_ref(pid))
    print(f"  area    '{title}': {'OK' if ok else 'FAIL'}")

def make_search(vid, title, pid, columns, sort_field):
    refs = [{"id":pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern"}]
    ok = post_so("search", vid, {
        "title": title,
        "columns": columns,
        "sort": [[sort_field, "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query":{"query":"","language":"kuery"},
                                             "filter":[],"index":pid})
        }
    }, refs)
    print(f"  search  '{title}': {'OK' if ok else 'FAIL'}")

# ---------------------------------------------------------------------------
# Dashboard builder
# ---------------------------------------------------------------------------
GRID = [
    (0, 0, 16, 8), (16, 0, 16, 8), (32, 0, 16, 8),   # row 1 — 3 metrics
    (0, 8, 24, 14), (24, 8, 24, 14),                   # row 2 — 2 charts
    (0, 22, 48, 12),                                    # row 3 — timeline
    (0, 34, 24, 12), (24, 34, 24, 12),                 # row 4 — 2 tables
]

def make_dashboard(did, title, desc, panels, time_from="now-90d"):
    """panels = list of (vis_id, vis_type)  e.g. ('my-viz','visualization')"""
    panel_objs, refs = [], []
    for i, (vid, vtype) in enumerate(panels[:8]):
        x,y,w,h = GRID[i]
        key = f"p{i}"
        panel_objs.append({
            "version":"7.11.0","type":vtype,
            "gridData":{"x":x,"y":y,"w":w,"h":h,"i":key},
            "panelIndex":key,"embeddableConfig":{},
            "panelRefName":f"panel_{key}"
        })
        refs.append({"id":vid,"name":f"panel_p{i}","type":vtype})
    ok = post_so("dashboard", did, {
        "title": title, "description": desc,
        "panelsJSON": json.dumps(panel_objs),
        "optionsJSON": json.dumps({"useMargins":True,"syncColors":False,"hidePanelTitles":False}),
        "timeFrom": time_from, "timeTo": "now", "timeRestore": True,
        "refreshInterval": {"pause": False, "value": 60000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query":{"query":"","language":"kuery"},"filter":[]})
        }
    }, refs)
    print(f"  DASHBOARD '{title}': {'OK' if ok else 'FAIL'}")

# ---------------------------------------------------------------------------
# Build each dashboard
# ---------------------------------------------------------------------------
def build_threat_intel():
    print("\n── Threat Intelligence Overview ──")
    pid = "ip-iocs"
    make_metric("ti-total",   "Total IOCs",           pid)
    make_pie(   "ti-types",   "IOCs by Threat Type",  pid, "threat_type")
    make_pie(   "ti-inds",    "IOCs by Indicator",    pid, "indicator_type")
    make_hbar(  "ti-sources", "Top Sources",          pid, "source")
    make_hbar(  "ti-country", "Top Countries",        pid, "country")
    make_area(  "ti-trend",   "IOC Trend",            pid, "first_seen", "threat_type")
    make_search("ti-tbl",     "Recent IOCs",          pid,
                ["indicator_type","threat_type","source","country"], "first_seen")
    make_dashboard("db-ti", "Threat Intelligence Overview",
        "Real-time IOC view: threat types, sources, geography",
        [("ti-total","visualization"),("ti-types","visualization"),("ti-inds","visualization"),
         ("ti-sources","visualization"),("ti-country","visualization"),
         ("ti-trend","visualization"),("ti-tbl","search")],
        time_from="now-30d")

def build_darkweb():
    print("\n── Dark Web Monitoring ──")
    lp, mp, bp = "ip-dw-leaks", "ip-dw-ment", "ip-dw-breach"
    make_metric("dw-nleaks",    "Leaked Records",       lp)
    make_metric("dw-nment",     "Dark Web Mentions",    mp)
    make_metric("dw-nbreach",   "Data Breaches",        bp)
    make_pie(   "dw-sev",       "Leaks by Severity",    lp, "severity")
    make_hbar(  "dw-domains",   "Targeted Domains",     lp, "affected_domain")
    make_area(  "dw-timeline",  "Leak Timeline",        lp, "date_discovered", "severity")
    make_search("dw-tbl",       "Recent Leaks",         lp,
                ["title","affected_domain","severity","record_count","status"], "date_discovered")
    make_dashboard("db-dw", "Dark Web Monitoring",
        "Leaked credentials, data breaches, and threat actor mentions",
        [("dw-nleaks","visualization"),("dw-nment","visualization"),("dw-nbreach","visualization"),
         ("dw-sev","visualization"),("dw-domains","visualization"),
         ("dw-timeline","visualization"),("dw-tbl","search")])

def build_asm():
    print("\n── Attack Surface Management ──")
    ap, vp = "ip-assets", "ip-vulns"
    make_metric("asm-nassets",  "Total Assets",            ap)
    make_metric("asm-nvulns",   "Total Vulnerabilities",   vp)
    make_metric("asm-ncrit",    "Critical Vulns",          vp, "severity:critical")
    make_pie(   "asm-atype",    "Assets by Type",          ap, "asset_type")
    make_hbar(  "asm-vsev",     "Vulns by Severity",       vp, "severity")
    make_area(  "asm-disc",     "Asset Discovery",         ap, "created_at", "asset_type")
    make_hbar(  "asm-svc",      "Exposed Services",        ap, "service")
    make_search("asm-vtbl",     "Vulnerabilities",         vp,
                ["title","severity","vulnerability_type","cve_id","status"], "date_discovered")
    make_dashboard("db-asm", "Attack Surface Management",
        "Discovered assets, vulnerabilities, and exposed services",
        [("asm-nassets","visualization"),("asm-nvulns","visualization"),("asm-ncrit","visualization"),
         ("asm-atype","visualization"),("asm-vsev","visualization"),
         ("asm-disc","visualization"),("asm-svc","visualization"),("asm-vtbl","search")])

def build_brand():
    print("\n── Brand Protection ──")
    mn, tp, al = "ip-bm", "ip-typo", "ip-balerts"
    make_metric("bp-nmon",      "Monitored Brands",      mn)
    make_metric("bp-ntypo",     "Typosquats Detected",   tp)
    make_metric("bp-nphish",    "Phishing Sites",        tp, "is_phishing:true")
    make_pie(   "bp-tech",      "By Technique",          tp, "technique")
    make_hbar(  "bp-brand",     "By Brand",              tp, "brand_name")
    make_area(  "bp-timeline",  "Detection Timeline",    tp, "date_discovered", "brand_name")
    make_hbar(  "bp-atype",     "Alert Types",           al, "alert_type")
    make_search("bp-tbl",       "Recent Alerts",         al,
                ["title","brand_name","alert_type","severity","status"], "detected_at")
    make_dashboard("db-brand", "Brand Protection",
        "Typosquatting, phishing, and brand impersonation monitoring",
        [("bp-nmon","visualization"),("bp-ntypo","visualization"),("bp-nphish","visualization"),
         ("bp-tech","visualization"),("bp-brand","visualization"),
         ("bp-timeline","visualization"),("bp-atype","visualization"),("bp-tbl","search")])

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Step 1: Creating index patterns...")
    make_index_patterns()

    print("\nStep 2: Building visualizations and dashboards...")
    build_threat_intel()
    build_darkweb()
    build_asm()
    build_brand()

    print("\n\nStep 3: Verify — final dashboard list:")
    r = api("GET", "/api/saved_objects/_find?type=dashboard&per_page=20")
    for o in r.get("saved_objects", []):
        did = o["id"]
        title = o["attributes"]["title"]
        panels = json.loads(o["attributes"].get("panelsJSON","[]"))
        print(f"\n  {title} ({len(panels)} panels)")
        print(f"  → http://192.168.36.51:5601/app/dashboards#/view/{did}")
