#!/usr/bin/env python3
"""
Generate NDJSON files for all 4 dashboards and import them via the bulk import endpoint.
Uses legacy 'visualization' type (agg-based) which is reliably importable via the saved-objects API.
"""

import json, uuid, base64, urllib.request, urllib.error, os

KIBANA = "http://192.168.36.51:5601"
AUTH   = base64.b64encode(b"elastic:jichodns_elastic_2024").decode()
OUT    = os.path.join(os.path.dirname(__file__), "dashboards_v2")
os.makedirs(OUT, exist_ok=True)

# ── helpers ─────────────────────────────────────────────────────────────────

def _req(method, path, body=None, content_type="application/json"):
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        f"{KIBANA}{path}", data=data,
        headers={"kbn-xsrf": "true", "Authorization": f"Basic {AUTH}",
                 "Content-Type": content_type},
        method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        txt = e.read().decode()[:400]
        print(f"  HTTP {e.code} {method} {path}: {txt}")
        return {}

def bulk_import(filepath):
    with open(filepath, "rb") as f:
        boundary = "----FormBoundary" + uuid.uuid4().hex
        body  = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                 f"filename=\"{os.path.basename(filepath)}\"\r\n"
                 f"Content-Type: application/octet-stream\r\n\r\n").encode()
        body += f.read()
        body += f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        f"{KIBANA}/api/saved_objects/_import?overwrite=true",
        data=body,
        headers={"kbn-xsrf": "true", "Authorization": f"Basic {AUTH}",
                 "Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())
            ok = result.get("success", False)
            print(f"  import {os.path.basename(filepath)}: {'OK' if ok else 'PARTIAL'} "
                  f"({result.get('successCount',0)} objects)")
            if not ok:
                for e in result.get("errors", [])[:3]:
                    print(f"    ERR: {e}")
            return ok
    except urllib.error.HTTPError as e:
        print(f"  FAIL import: {e.read().decode()[:300]}")
        return False

# ── object builders ──────────────────────────────────────────────────────────

TS = "2024-01-15T12:00:00.000Z"

def obj(otype, oid, attrs, refs=None):
    return {"type": otype, "id": oid, "attributes": attrs,
            "references": refs or [],
            "migrationVersion": {},
            "updated_at": TS, "version": "WzEsMV0="}

def index_pattern(pid, title, time_field):
    return obj("index-pattern", pid,
                {"title": title, "timeFieldName": time_field,
                 "fields": "[]", "fieldAttrs": "{}", "fieldFormatMap": "{}",
                 "runtimeFieldMap": "{}", "sourceFilters": "[]", "typeMeta": "{}"},
                refs=[])

# ---------- vis builders ----------

def metric(vid, title, index_pid, kql=""):
    aggs = [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"}]
    params = {"addTooltip":True,"addLegend":False,"type":"metric",
               "metric":{"percentageMode":False,"useRanges":False,
                         "colorSchema":"Green to Red","metricColorMode":"None",
                         "colorsRange":[{"from":0,"to":10000000}],
                         "labels":{"show":True},"invertColors":False,
                         "style":{"bgFill":"#000","bgColor":False,"labelColor":False,
                                  "subText":"","fontSize":60}}}
    search = json.dumps({"query":{"query":kql,"language":"kuery"},"filter":[]})
    return obj("visualization", vid,
                {"title":title,"visState":json.dumps({"title":title,"type":"metric",
                    "aggs":aggs,"params":params}),
                 "uiStateJSON":"{}","description":"",
                 "kibanaSavedObjectMeta":{"searchSourceJSON":search}},
                refs=[{"id":index_pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type":"index-pattern"}])

def pie(vid, title, index_pid, field):
    aggs = [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"terms","params":{"field":field,
              "orderBy":"1","order":"desc","size":10,"otherBucket":True,
              "missingBucket":False},"schema":"segment"}]
    params = {"type":"pie","addTooltip":True,"addLegend":True,
               "legendPosition":"right","isDonut":True,
               "labels":{"show":True,"values":True,"last_level":True,"truncate":100}}
    search = json.dumps({"query":{"query":"","language":"kuery"},"filter":[]})
    return obj("visualization", vid,
                {"title":title,"visState":json.dumps({"title":title,"type":"pie",
                    "aggs":aggs,"params":params}),
                 "uiStateJSON":"{}","description":"",
                 "kibanaSavedObjectMeta":{"searchSourceJSON":search}},
                refs=[{"id":index_pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type":"index-pattern"}])

def hbar(vid, title, index_pid, field):
    aggs = [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"terms","params":{"field":field,
              "orderBy":"1","order":"desc","size":10,"otherBucket":False,
              "missingBucket":False},"schema":"segment"}]
    val_axes = [{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"bottom",
                  "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                  "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                  "title":{"text":"Count"}}]
    cat_axes = [{"id":"CategoryAxis-1","type":"category","position":"left","show":True,
                  "style":{},"scale":{"type":"linear"},"labels":{"show":True,"filter":True,
                  "truncate":200},"title":{}}]
    series  = [{"show":True,"type":"histogram","mode":"normal",
                 "data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1",
                 "drawLinesBetweenPoints":True,"lineWidth":2,"showCircles":True}]
    params  = {"type":"histogram","grid":{"categoryLines":False},
                "categoryAxes":cat_axes,"valueAxes":val_axes,"seriesParams":series,
                "addTooltip":True,"addLegend":False,"legendPosition":"right",
                "times":[],"addTimeMarker":False}
    search  = json.dumps({"query":{"query":"","language":"kuery"},"filter":[]})
    return obj("visualization", vid,
                {"title":title,"visState":json.dumps({"title":title,
                    "type":"horizontal_bar","aggs":aggs,"params":params}),
                 "uiStateJSON":"{}","description":"",
                 "kibanaSavedObjectMeta":{"searchSourceJSON":search}},
                refs=[{"id":index_pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type":"index-pattern"}])

def area(vid, title, index_pid, time_field, split_field=None):
    aggs = [{"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"date_histogram",
              "params":{"field":time_field,"useNormalizedEsInterval":True,
                        "interval":"auto","drop_partials":False,"min_doc_count":1,
                        "extended_bounds":{}},"schema":"segment"}]
    if split_field:
        aggs.append({"id":"3","enabled":True,"type":"terms",
                      "params":{"field":split_field,"orderBy":"1","order":"desc",
                                "size":5,"otherBucket":False},"schema":"group"})
    val_axes = [{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left",
                  "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                  "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                  "title":{"text":"Count"}}]
    cat_axes = [{"id":"CategoryAxis-1","type":"category","position":"bottom","show":True,
                  "style":{},"scale":{"type":"linear"},
                  "labels":{"show":True,"filter":True,"truncate":100},"title":{}}]
    series   = [{"show":True,"type":"area","mode":"stacked",
                  "data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1",
                  "drawLinesBetweenPoints":True,"lineWidth":2,
                  "interpolate":"linear","showCircles":True}]
    params   = {"type":"area","grid":{"categoryLines":False},
                 "categoryAxes":cat_axes,"valueAxes":val_axes,"seriesParams":series,
                 "addTooltip":True,"addLegend":True,"legendPosition":"right",
                 "times":[],"addTimeMarker":False}
    search   = json.dumps({"query":{"query":"","language":"kuery"},"filter":[]})
    return obj("visualization", vid,
                {"title":title,"visState":json.dumps({"title":title,"type":"area",
                    "aggs":aggs,"params":params}),
                 "uiStateJSON":"{}","description":"",
                 "kibanaSavedObjectMeta":{"searchSourceJSON":search}},
                refs=[{"id":index_pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type":"index-pattern"}])

def discover(vid, title, index_pid, columns, sort_field):
    search = json.dumps({"query":{"query":"","language":"kuery"},"filter":[],
                          "index":index_pid})
    return obj("search", vid,
                {"title":title,"columns":columns,
                 "sort":[[sort_field,"desc"]],
                 "kibanaSavedObjectMeta":{"searchSourceJSON":search}},
                refs=[{"id":index_pid,"name":"kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type":"index-pattern"}])

def dashboard(did, title, desc, panels_refs, time_from="now-90d"):
    panels = []
    refs   = []
    layout = [(0,0,16,8),(16,0,16,8),(32,0,16,8),
              (0,8,24,14),(24,8,24,14),
              (0,22,48,12),
              (0,34,24,12),(24,34,24,12)]
    for i,(vid,vtype) in enumerate(panels_refs[:8]):
        x,y,w,h = layout[i] if i < len(layout) else (0,50+i*12,48,12)
        key = f"p{i}"
        panels.append({"version":"8.8.0","type":vtype,
                        "gridData":{"x":x,"y":y,"w":w,"h":h,"i":key},
                        "panelIndex":key,"embeddableConfig":{"enhancements":{}},
                        "panelRefName":f"panel_{key}"})
        refs.append({"id":vid,"name":f"panel_p{i}","type":vtype})
    return obj("dashboard", did,
                {"title":title,"description":desc,
                 "panelsJSON":json.dumps(panels),
                 "optionsJSON":json.dumps({"useMargins":True,"syncColors":False,
                                            "hidePanelTitles":False}),
                 "timeFrom":time_from,"timeTo":"now","timeRestore":True,
                 "refreshInterval":{"pause":False,"value":60000},
                 "kibanaSavedObjectMeta":{"searchSourceJSON":
                    json.dumps({"query":{"query":"","language":"kuery"},"filter":[]})}},
                refs=refs)

# ── write helper ─────────────────────────────────────────────────────────────

def write_ndjson(name, objects):
    path = os.path.join(OUT, f"{name}.ndjson")
    with open(path, "w") as f:
        for o in objects:
            f.write(json.dumps(o) + "\n")
    return path

# ── Dashboard 1: Threat Intelligence ─────────────────────────────────────────

def make_threat_intel():
    pid = "iocs-v3"
    objects = [
        index_pattern(pid, "iocs", "first_seen"),
        metric("ti3-total",   "Total IOCs",              pid),
        pie(   "ti3-type",    "IOCs by Threat Type",     pid, "threat_type"),
        pie(   "ti3-src",     "IOCs by Source",          pid, "source"),
        hbar(  "ti3-country", "Top Countries",           pid, "country"),
        hbar(  "ti3-ind",     "Indicator Types",         pid, "indicator_type"),
        area(  "ti3-trend",   "IOC Trend Over Time",     pid, "first_seen", "threat_type"),
        discover("ti3-disc",  "Recent IOCs", pid,
                 ["indicator_type","threat_type","source","country"], "first_seen"),
    ]
    panels = [("ti3-total","visualization"),("ti3-type","visualization"),
              ("ti3-src","visualization"),("ti3-country","visualization"),
              ("ti3-ind","visualization"),("ti3-trend","visualization"),
              ("ti3-disc","search")]
    objects.append(dashboard("dash3-ti","Threat Intelligence Overview",
        "Real-time IOC view by threat type, source, and geography", panels, "now-30d"))
    return write_ndjson("threat-intelligence", objects)

# ── Dashboard 2: Dark Web ─────────────────────────────────────────────────────

def make_darkweb():
    lp  = "dw-leaks-v3"
    mp  = "dw-mentions-v3"
    bp  = "dw-breaches-v3"
    objects = [
        index_pattern(lp, "darkweb_leaks",    "date_discovered"),
        index_pattern(mp, "darkweb_mentions",  "date_discovered"),
        index_pattern(bp, "data_breaches",     "date_discovered"),
        metric("dw3-leaks",    "Leaked Records",       lp),
        metric("dw3-mentions", "Dark Web Mentions",    mp),
        metric("dw3-breaches", "Data Breaches",        bp),
        pie(   "dw3-sev",      "Leaks by Severity",    lp, "severity"),
        hbar(  "dw3-domains",  "Top Affected Domains", lp, "affected_domain"),
        area(  "dw3-timeline", "Leak Timeline",        lp, "date_discovered", "severity"),
        hbar(  "dw3-types",    "Mention Types",        mp, "mention_type"),
        discover("dw3-disc",   "Recent Leaks", lp,
                 ["title","affected_domain","severity","record_count","status"], "date_discovered"),
    ]
    panels = [("dw3-leaks","visualization"),("dw3-mentions","visualization"),
              ("dw3-breaches","visualization"),("dw3-sev","visualization"),
              ("dw3-domains","visualization"),("dw3-timeline","visualization"),
              ("dw3-types","visualization"),("dw3-disc","search")]
    objects.append(dashboard("dash3-dw","Dark Web Monitoring",
        "Leaked credentials, data breaches, and threat actor mentions", panels))
    return write_ndjson("dark-web", objects)

# ── Dashboard 3: ASM ─────────────────────────────────────────────────────────

def make_asm():
    ap = "asm-assets-v3"
    vp = "asm-vulns-v3"
    objects = [
        index_pattern(ap, "assets",          "created_at"),
        index_pattern(vp, "vulnerabilities",  "date_discovered"),
        metric("asm3-assets",  "Total Assets",            ap),
        metric("asm3-vulns",   "Total Vulnerabilities",   vp),
        metric("asm3-critical","Critical Vulns",          vp, "severity:critical"),
        pie(   "asm3-atype",   "Assets by Type",          ap, "asset_type"),
        hbar(  "asm3-vsev",    "Vulns by Severity",       vp, "severity"),
        area(  "asm3-disc",    "Asset Discovery Timeline",ap, "created_at", "asset_type"),
        hbar(  "asm3-svc",     "Exposed Services",        ap, "service"),
        discover("asm3-vtbl",  "Vulnerabilities", vp,
                 ["title","severity","vulnerability_type","cve_id","status"], "date_discovered"),
    ]
    panels = [("asm3-assets","visualization"),("asm3-vulns","visualization"),
              ("asm3-critical","visualization"),("asm3-atype","visualization"),
              ("asm3-vsev","visualization"),("asm3-disc","visualization"),
              ("asm3-svc","visualization"),("asm3-vtbl","search")]
    objects.append(dashboard("dash3-asm","Attack Surface Management",
        "Discovered assets, vulnerabilities, and exposed services", panels))
    return write_ndjson("asm", objects)

# ── Dashboard 4: Brand Protection ────────────────────────────────────────────

def make_brand():
    tp = "brand-typo-v3"
    al = "brand-alerts-v3"
    mn = "brand-monitors-v3"
    objects = [
        index_pattern(mn, "brand_monitors",   "created_at"),
        index_pattern(tp, "typosquat_domains","date_discovered"),
        index_pattern(al, "brand_alerts",     "detected_at"),
        metric("bp3-monitors",  "Monitored Brands",      mn),
        metric("bp3-typosquats","Typosquats Detected",   tp),
        metric("bp3-phishing",  "Active Phishing Sites", tp, "is_phishing:true"),
        pie(   "bp3-technique", "Typosquats by Technique",tp,"technique"),
        hbar(  "bp3-brand",     "Typosquats by Brand",   tp, "brand_name"),
        area(  "bp3-timeline",  "Detection Timeline",    tp, "date_discovered","brand_name"),
        hbar(  "bp3-atype",     "Alert Types",           al, "alert_type"),
        discover("bp3-disc",    "Recent Alerts", al,
                 ["title","brand_name","alert_type","severity","status"], "detected_at"),
    ]
    panels = [("bp3-monitors","visualization"),("bp3-typosquats","visualization"),
              ("bp3-phishing","visualization"),("bp3-technique","visualization"),
              ("bp3-brand","visualization"),("bp3-timeline","visualization"),
              ("bp3-atype","visualization"),("bp3-disc","search")]
    objects.append(dashboard("dash3-brand","Brand Protection",
        "Typosquatting, phishing, and brand impersonation monitoring", panels))
    return write_ndjson("brand-protection", objects)

# ── main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating NDJSON files...")
    files = [make_threat_intel(), make_darkweb(), make_asm(), make_brand()]

    print("\nImporting into Kibana...")
    for f in files:
        bulk_import(f)

    print("\nFinal dashboard list:")
    r = _req("GET", "/api/saved_objects/_find?type=dashboard&per_page=20")
    for o in r.get("saved_objects", []):
        t = o["attributes"]["title"]
        did = o["id"]
        print(f"  {t}")
        print(f"    http://192.168.36.51:5601/app/dashboards#/view/{did}")
