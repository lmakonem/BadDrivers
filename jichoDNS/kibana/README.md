# JichoDNS Kibana Dashboards

Pre-configured Kibana dashboards for the JichoDNS threat intelligence platform.

## Available Dashboards

### 1. Threat Intelligence Overview
**File:** `dashboards/threat-intelligence-overview.ndjson`

Comprehensive view of IOCs including:
- Total IOC count metric
- IOCs by threat type (pie chart)
- IOCs by indicator type (bar chart)
- IOCs by source feed (pie chart)
- Geographic distribution (region map)
- IOC trend over time (line chart)
- Top countries (horizontal bar)
- Recent IOCs data table

### 2. Dark Web Monitoring
**File:** `dashboards/dark-web-monitoring.ndjson`

Monitor dark web threats:
- Total leaked credentials metric
- Total dark web mentions metric
- Total data breaches metric
- Leaks by severity (donut chart)
- Mentions by source type (bar chart)
- Leaks timeline (area chart)
- Breaches by severity (gauge)
- Recent leaks data table

### 3. Attack Surface Management
**File:** `dashboards/attack-surface-management.ndjson`

Track your attack surface:
- Total discovered assets metric
- Total vulnerabilities metric
- Critical vulnerabilities metric
- Assets by type (donut chart)
- Vulnerabilities by severity (bar chart)
- Asset discovery timeline (line chart)
- Exposed services (tag cloud)
- Recent vulnerabilities table
- Asset inventory table

### 4. Brand Protection
**File:** `dashboards/brand-protection.ndjson`

Protect your brand:
- Monitored brands metric
- Typosquats detected metric
- Active phishing sites metric
- Typosquats by technique (donut chart)
- Typosquats by brand (bar chart)
- Discovery timeline (area chart)
- Risk score distribution (histogram)
- Typosquat domains table
- Brand alerts table

## Import Instructions

### Via Kibana UI

1. Navigate to **Stack Management** > **Saved Objects**
2. Click **Import**
3. Select the `.ndjson` file for the dashboard you want to import
4. Click **Import**
5. If prompted about index patterns, select "Check for existing objects" and "Overwrite conflicts"

### Via API

```bash
# Set your Kibana credentials
KIBANA_URL="http://192.168.36.51:5601"
KIBANA_USER="elastic"
KIBANA_PASS="jichodns_elastic_2024"

# Import Threat Intelligence Overview
curl -X POST "${KIBANA_URL}/api/saved_objects/_import" \
  -u "${KIBANA_USER}:${KIBANA_PASS}" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards/threat-intelligence-overview.ndjson

# Import Dark Web Monitoring
curl -X POST "${KIBANA_URL}/api/saved_objects/_import" \
  -u "${KIBANA_USER}:${KIBANA_PASS}" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards/dark-web-monitoring.ndjson

# Import Attack Surface Management
curl -X POST "${KIBANA_URL}/api/saved_objects/_import" \
  -u "${KIBANA_USER}:${KIBANA_PASS}" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards/attack-surface-management.ndjson

# Import Brand Protection
curl -X POST "${KIBANA_URL}/api/saved_objects/_import" \
  -u "${KIBANA_USER}:${KIBANA_PASS}" \
  -H "kbn-xsrf: true" \
  --form file=@dashboards/brand-protection.ndjson
```

## Required Elasticsearch Indices

Make sure the following indices exist in Elasticsearch:

| Index | Description |
|-------|-------------|
| `iocs` | Indicators of Compromise |
| `darkweb_leaks` | Leaked credentials |
| `darkweb_mentions` | Dark web mentions |
| `data_breaches` | Data breach records |
| `assets` | Discovered assets |
| `vulnerabilities` | Vulnerability findings |
| `brand_monitors` | Brand monitoring configs |
| `typosquat_domains` | Typosquat detections |
| `brand_alerts` | Brand protection alerts |

## Customization

After importing, you can customize the dashboards:

1. **Time Range**: Each dashboard has a default time range (30 or 90 days)
2. **Refresh Interval**: Default is 60 seconds
3. **Filters**: Add filters by clicking the + icon in the filter bar
4. **Visualizations**: Click any panel to drill down or edit

## Color Scheme

Dashboards use colors consistent with the JichoDNS/SOCRadar theme:
- Primary: `#fe4562` (red)
- Background: `#0d0e1a` (dark navy)
- Cards: `#191A34` (dark purple)

## Troubleshooting

### Index Pattern Not Found
If you see "Index pattern not found" errors:
1. Go to **Stack Management** > **Data Views**
2. Create a data view for the missing index
3. Set the time field appropriately (usually `discovered_at` or `first_seen`)

### Empty Visualizations
If visualizations show no data:
1. Check that the index has data: `GET /index_name/_count`
2. Verify the time range includes data
3. Check field mappings match the visualization configuration

### Permission Errors
Ensure the Kibana user has read access to all required indices.
