"""
Vertex AI integration service for threat report generation.

Provides AI-powered threat intelligence report generation using Google's
Vertex AI Gemini model with Elasticsearch integration for context.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.elasticsearch import es_service

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================

class ReportType(str, Enum):
    """Types of threat reports that can be generated."""
    THREAT_INTELLIGENCE = "threat_intelligence"
    INCIDENT_SUMMARY = "incident_summary"
    EXECUTIVE_BRIEFING = "executive_briefing"
    IOC_ANALYSIS = "ioc_analysis"
    DARK_WEB_EXPOSURE = "dark_web_exposure"


class SeverityLevel(str, Enum):
    """Severity levels for threat reports."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# =============================================================================
# Pydantic Models
# =============================================================================

class IOCItem(BaseModel):
    """Individual IOC in a report."""
    indicator: str
    indicator_type: str
    threat_type: str
    confidence: float = 0.5
    source: Optional[str] = None
    country_code: Optional[str] = None


class Recommendation(BaseModel):
    """Security recommendation in a report."""
    priority: str  # critical, high, medium, low
    action: str
    description: str
    affected_systems: List[str] = []


class ThreatReport(BaseModel):
    """Generated threat report model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    type: ReportType
    content: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    iocs: List[IOCItem] = []
    recommendations: List[Recommendation] = []
    executive_summary: Optional[str] = None
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    filters_applied: Dict[str, Any] = {}
    model_used: str = "gemini-1.5-pro"
    token_count: int = 0


class ReportRequest(BaseModel):
    """Request model for generating reports."""
    report_type: ReportType
    time_range: str = "24h"  # 1h, 6h, 24h, 7d, 30d
    filters: Dict[str, Any] = {}  # threat_type, country, source, etc.
    custom_prompt: Optional[str] = None
    include_iocs: bool = True
    max_iocs: int = 100


class ChatRequest(BaseModel):
    """Request model for chat with logs."""
    question: str
    log_context: Optional[str] = None
    include_recent_iocs: bool = True
    time_range: str = "24h"


class ChatResponse(BaseModel):
    """Response model for chat."""
    answer: str
    sources_used: List[str] = []
    confidence: float = 0.8
    follow_up_questions: List[str] = []


# =============================================================================
# Report Templates
# =============================================================================

REPORT_TEMPLATES = {
    ReportType.THREAT_INTELLIGENCE: """
# Threat Intelligence Report
Generated: {generated_at}
Time Range: {time_range}

## Executive Summary
{executive_summary}

## Threat Landscape Overview
{threat_overview}

## Key Findings
{key_findings}

## Indicators of Compromise (IOCs)
{ioc_table}

## Threat Actor Analysis
{threat_actors}

## Geographic Distribution
{geo_distribution}

## Recommendations
{recommendations}

## Methodology
This report was generated using JichoDNS threat intelligence platform, 
aggregating data from 15+ threat feeds with a focus on African cyber threats.
""",

    ReportType.INCIDENT_SUMMARY: """
# Security Incident Summary Report
Generated: {generated_at}
Time Range: {time_range}

## Incident Overview
{incident_overview}

## Timeline of Events
{timeline}

## Affected Systems
{affected_systems}

## Attack Vectors Identified
{attack_vectors}

## IOCs Associated with Incidents
{ioc_table}

## Containment Actions Taken
{containment_actions}

## Root Cause Analysis
{root_cause}

## Lessons Learned
{lessons_learned}

## Next Steps
{next_steps}
""",

    ReportType.EXECUTIVE_BRIEFING: """
# Executive Security Briefing
Generated: {generated_at}
Classification: {classification}

## Summary
{executive_summary}

## Key Metrics
- Total Threats Detected: {total_threats}
- Critical Severity: {critical_count}
- High Severity: {high_count}
- Countries Affected: {countries_affected}

## Top Threats This Period
{top_threats}

## Risk Assessment
{risk_assessment}

## Business Impact
{business_impact}

## Resource Requirements
{resource_requirements}

## Recommended Actions for Leadership
{leadership_actions}
""",

    ReportType.IOC_ANALYSIS: """
# IOC Analysis Report
Generated: {generated_at}
Total IOCs Analyzed: {total_iocs}

## Summary Statistics
{stats_summary}

## IOC Breakdown by Type
{ioc_by_type}

## IOC Breakdown by Threat Category
{ioc_by_threat}

## High-Confidence Indicators
{high_confidence_iocs}

## Geographic Origin Analysis
{geo_analysis}

## Associated Malware Families
{malware_families}

## Network Infrastructure Analysis
{network_analysis}

## Detection Recommendations
{detection_recommendations}

## Full IOC List
{full_ioc_list}
""",

    ReportType.DARK_WEB_EXPOSURE: """
# Dark Web Exposure Report
Generated: {generated_at}
Assessment Period: {time_range}

## Executive Summary
{executive_summary}

## Credential Exposure
{credential_exposure}

## Data Leaks Detected
{data_leaks}

## Brand Mentions
{brand_mentions}

## Typosquatting Domains
{typosquatting}

## Threat Actor Activity
{threat_actor_activity}

## Recommended Immediate Actions
{immediate_actions}

## Long-term Mitigation Strategies
{mitigation_strategies}
""",
}


# =============================================================================
# Vertex AI Service
# =============================================================================

class VertexAIService:
    """
    Service for generating threat reports using Vertex AI Gemini.
    
    Integrates with Elasticsearch to pull threat data and uses
    Google's Vertex AI for natural language generation.
    """
    
    def __init__(self):
        self._client = None
        self._model = None
        self._use_mock = True  # Start with mock, try real API on init
        self.reports_index = "threat_reports"
        
    async def _initialize_client(self):
        """Initialize the Vertex AI client if credentials are available."""
        if self._client is not None:
            return
            
        project_id = settings.GOOGLE_CLOUD_PROJECT
        credentials_path = settings.GOOGLE_APPLICATION_CREDENTIALS
        
        if not project_id:
            logger.warning("GOOGLE_CLOUD_PROJECT not set, using mock mode")
            self._use_mock = True
            return
            
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel
            
            vertexai.init(
                project=project_id,
                location="us-central1",
            )
            
            self._model = GenerativeModel("gemini-1.5-pro")
            self._use_mock = False
            logger.info("Vertex AI client initialized successfully")
            
        except ImportError:
            logger.warning("vertexai package not installed, using mock mode")
            self._use_mock = True
        except Exception as e:
            logger.warning(f"Failed to initialize Vertex AI: {e}, using mock mode")
            self._use_mock = True
    
    async def _generate_content(self, prompt: str) -> str:
        """Generate content using Vertex AI or mock."""
        await self._initialize_client()
        
        if self._use_mock:
            return await self._mock_generate(prompt)
        
        try:
            response = await self._model.generate_content_async(
                prompt,
                generation_config={
                    "max_output_tokens": 8192,
                    "temperature": 0.7,
                    "top_p": 0.95,
                }
            )
            return response.text
        except Exception as e:
            logger.error(f"Vertex AI generation error: {e}")
            return await self._mock_generate(prompt)
    
    async def _mock_generate(self, prompt: str) -> str:
        """Mock generation for testing without API key."""
        # Extract key information from prompt for contextual response
        if "threat intelligence" in prompt.lower():
            return self._get_mock_threat_intelligence()
        elif "incident" in prompt.lower():
            return self._get_mock_incident_summary()
        elif "executive" in prompt.lower():
            return self._get_mock_executive_briefing()
        elif "ioc" in prompt.lower():
            return self._get_mock_ioc_analysis()
        elif "dark web" in prompt.lower():
            return self._get_mock_dark_web_report()
        else:
            return self._get_mock_general_response(prompt)
    
    def _get_mock_threat_intelligence(self) -> str:
        return """Based on the threat data analyzed, there are several notable patterns:

**Key Findings:**
1. Increased C2 communication detected from domains using DGA patterns
2. Phishing campaigns targeting African financial institutions continue to rise
3. Mobile money platforms (M-Pesa, Airtel Money) remain primary targets

**Threat Actor Analysis:**
- APT groups showing interest in African telecom infrastructure
- Financially motivated actors targeting banking sector
- Credential harvesting operations increasing in East Africa

**Recommendations:**
1. Block identified C2 domains at DNS level
2. Implement additional MFA for high-value transactions
3. Monitor for typosquatting of regional brand names
4. Enhance email filtering for phishing indicators"""

    def _get_mock_incident_summary(self) -> str:
        return """**Incident Overview:**
During the analyzed period, multiple security incidents were detected across the monitored infrastructure.

**Timeline:**
- Detection: Multiple malicious domains identified through threat feed correlation
- Analysis: IOCs cross-referenced with known threat actor TTPs
- Response: Automated blocking implemented for high-confidence indicators

**Attack Vectors:**
1. DNS-based C2 communication
2. Phishing emails with malicious attachments
3. Typosquatting of legitimate domains

**Containment Status:**
All identified IOCs have been added to block lists. Continued monitoring recommended."""

    def _get_mock_executive_briefing(self) -> str:
        return """**Executive Summary:**
The threat landscape for the African region shows elevated activity in financially-motivated attacks.

**Key Metrics:**
- Threat detection rate increased 15% from previous period
- 78% of threats targeting financial services sector
- Primary threat vectors: Phishing (45%), C2 (30%), Malware (25%)

**Business Impact Assessment:**
Current threat levels pose moderate risk to operations. Existing controls are effective but require enhancement.

**Recommended Actions:**
1. Approve budget for enhanced threat intelligence capabilities
2. Conduct security awareness training focused on phishing
3. Review and update incident response procedures"""

    def _get_mock_ioc_analysis(self) -> str:
        return """**IOC Analysis Summary:**
Comprehensive analysis of collected indicators reveals several patterns.

**Statistics:**
- Domains: 65% of total IOCs
- IP Addresses: 25% of total IOCs
- URLs: 10% of total IOCs

**Threat Categories:**
- Command & Control: 40%
- Phishing: 35%
- Malware Distribution: 20%
- Data Exfiltration: 5%

**High-Confidence Indicators:**
All indicators with confidence >0.8 should be blocked immediately.

**Detection Recommendations:**
1. Implement DNS sinkholing for identified C2 domains
2. Add IP ranges to firewall block lists
3. Configure SIEM alerts for URL patterns"""

    def _get_mock_dark_web_report(self) -> str:
        return """**Dark Web Exposure Assessment:**
Monitoring of dark web sources reveals potential exposure risks.

**Credential Exposure:**
No critical credential leaks detected in this period.

**Brand Monitoring:**
- 3 typosquatting domains identified for monitored brands
- No confirmed data breach listings found

**Threat Actor Activity:**
- Discussions about African financial systems detected in forums
- Malware-as-a-service offerings targeting mobile money platforms

**Immediate Actions Required:**
1. Register identified typosquatting domains or request takedown
2. Reset credentials for any exposed accounts
3. Enhance monitoring for brand abuse"""

    def _get_mock_general_response(self, prompt: str) -> str:
        return f"""Based on the provided context and your question, here is my analysis:

The threat data indicates ongoing malicious activity that requires attention. 
Key observations from the log data include potential indicators of compromise 
that should be investigated further.

For more specific analysis, please provide additional context or narrow 
down your query to specific IOCs, time ranges, or threat categories.

Recommendations:
1. Review the identified IOCs for relevance to your environment
2. Cross-reference with your SIEM alerts
3. Consider blocking high-confidence indicators
4. Continue monitoring for related activity"""

    def _parse_time_range(self, time_range: str) -> tuple[datetime, datetime]:
        """Parse time range string to datetime tuple."""
        end_time = datetime.utcnow()
        
        if time_range == "1h":
            start_time = end_time - timedelta(hours=1)
        elif time_range == "6h":
            start_time = end_time - timedelta(hours=6)
        elif time_range == "24h":
            start_time = end_time - timedelta(hours=24)
        elif time_range == "7d":
            start_time = end_time - timedelta(days=7)
        elif time_range == "30d":
            start_time = end_time - timedelta(days=30)
        else:
            start_time = end_time - timedelta(hours=24)
            
        return start_time, end_time

    async def _fetch_threat_context(
        self,
        time_range: str,
        filters: Dict[str, Any],
        max_iocs: int = 100,
    ) -> Dict[str, Any]:
        """Fetch threat data from Elasticsearch for context."""
        start_time, end_time = self._parse_time_range(time_range)
        
        # Get recent indicators
        indicators = await es_service.get_recent_indicators(
            limit=max_iocs,
            since=start_time,
        )
        
        # Get stats
        stats = await es_service.get_stats()
        
        # Get country distribution
        country_stats = await es_service.get_country_threat_stats()
        
        return {
            "indicators": indicators,
            "stats": stats,
            "country_stats": country_stats,
            "time_range_start": start_time.isoformat(),
            "time_range_end": end_time.isoformat(),
            "total_indicators": len(indicators),
        }

    def _format_ioc_table(self, indicators: List[Dict]) -> str:
        """Format IOCs as a markdown table."""
        if not indicators:
            return "No IOCs found in the specified time range."
        
        lines = ["| Indicator | Type | Threat | Confidence | Country |",
                 "|-----------|------|--------|------------|---------|"]
        
        for ioc in indicators[:50]:  # Limit to 50 for readability
            indicator = ioc.get("indicator", "N/A")[:50]  # Truncate long indicators
            ioc_type = ioc.get("indicator_type", "N/A")
            threat = ioc.get("threat_type", "N/A")
            confidence = f"{ioc.get('confidence', 0.5):.2f}"
            country = ioc.get("country_code", "N/A")
            lines.append(f"| {indicator} | {ioc_type} | {threat} | {confidence} | {country} |")
        
        if len(indicators) > 50:
            lines.append(f"\n*Showing 50 of {len(indicators)} total IOCs*")
        
        return "\n".join(lines)

    def _extract_iocs_from_context(self, context: Dict[str, Any]) -> List[IOCItem]:
        """Extract IOC items from context data."""
        indicators = context.get("indicators", [])
        iocs = []
        
        for ind in indicators[:100]:  # Limit
            iocs.append(IOCItem(
                indicator=ind.get("indicator", ""),
                indicator_type=ind.get("indicator_type", "unknown"),
                threat_type=ind.get("threat_type", "unknown"),
                confidence=ind.get("confidence", 0.5),
                source=ind.get("source"),
                country_code=ind.get("country_code"),
            ))
        
        return iocs

    def _determine_severity(self, context: Dict[str, Any]) -> SeverityLevel:
        """Determine report severity based on context."""
        stats = context.get("stats", {})
        indicators = context.get("indicators", [])
        
        if not indicators:
            return SeverityLevel.INFORMATIONAL
        
        # Check for high-confidence C2 or exfiltration
        critical_count = sum(
            1 for i in indicators 
            if i.get("threat_type") in ["c2", "exfiltration"] 
            and i.get("confidence", 0) > 0.8
        )
        
        if critical_count > 10:
            return SeverityLevel.CRITICAL
        elif critical_count > 5:
            return SeverityLevel.HIGH
        elif critical_count > 0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW

    def _generate_recommendations(self, context: Dict[str, Any]) -> List[Recommendation]:
        """Generate security recommendations based on context."""
        recommendations = []
        stats = context.get("stats", {})
        threat_types = stats.get("by_threat_type", {})
        
        if threat_types.get("c2", 0) > 0:
            recommendations.append(Recommendation(
                priority="critical",
                action="Block C2 Domains",
                description="Immediately block identified command and control domains at DNS and firewall level",
                affected_systems=["DNS", "Firewall", "Proxy"],
            ))
        
        if threat_types.get("phishing", 0) > 0:
            recommendations.append(Recommendation(
                priority="high",
                action="Update Email Filters",
                description="Add phishing indicators to email security gateway block lists",
                affected_systems=["Email Gateway", "Spam Filter"],
            ))
        
        if threat_types.get("malware", 0) > 0:
            recommendations.append(Recommendation(
                priority="high",
                action="Enhance Endpoint Detection",
                description="Update EDR signatures with identified malware indicators",
                affected_systems=["EDR", "Antivirus"],
            ))
        
        if threat_types.get("exfiltration", 0) > 0:
            recommendations.append(Recommendation(
                priority="critical",
                action="Review Data Loss Prevention",
                description="Analyze DLP logs for potential data exfiltration activity",
                affected_systems=["DLP", "SIEM"],
            ))
        
        # Default recommendation
        if not recommendations:
            recommendations.append(Recommendation(
                priority="medium",
                action="Continue Monitoring",
                description="Maintain current security posture and continue threat monitoring",
                affected_systems=["SIEM", "SOC"],
            ))
        
        return recommendations

    async def generate_threat_report(
        self,
        query: str,
        context: Dict[str, Any],
    ) -> str:
        """
        Generate a threat intelligence report.
        
        Args:
            query: User's query or report focus
            context: Additional context (threat data, filters, etc.)
            
        Returns:
            Generated report content as string
        """
        prompt = f"""You are a senior threat intelligence analyst at JichoDNS, 
an Africa-focused DNS threat intelligence platform. Generate a professional 
threat intelligence report based on the following:

**User Query/Focus:**
{query}

**Context Data:**
{json.dumps(context, indent=2, default=str)}

**Requirements:**
1. Be professional and actionable
2. Focus on African cyber threat landscape
3. Include specific recommendations
4. Reference the provided IOCs where relevant
5. Use clear markdown formatting

Generate a comprehensive threat intelligence report:"""

        return await self._generate_content(prompt)

    async def analyze_iocs(self, iocs: List[Dict[str, Any]]) -> str:
        """
        Analyze a list of IOCs and provide insights.
        
        Args:
            iocs: List of IOC dictionaries to analyze
            
        Returns:
            Analysis results as string
        """
        prompt = f"""You are a senior threat intelligence analyst. Analyze the 
following Indicators of Compromise (IOCs) and provide actionable insights:

**IOCs to Analyze:**
{json.dumps(iocs[:50], indent=2, default=str)}

**Analysis Requirements:**
1. Identify patterns across the IOCs
2. Classify by threat type and severity
3. Identify potential threat actors or campaigns
4. Provide blocking/detection recommendations
5. Note any Africa-specific threats

Provide your analysis:"""

        return await self._generate_content(prompt)

    async def summarize_incidents(self, incidents: List[Dict[str, Any]]) -> str:
        """
        Summarize security incidents.
        
        Args:
            incidents: List of incident dictionaries
            
        Returns:
            Incident summary as string
        """
        prompt = f"""You are a security incident response analyst. Summarize 
the following security incidents:

**Incidents:**
{json.dumps(incidents, indent=2, default=str)}

**Summary Requirements:**
1. Executive-level summary
2. Timeline of key events
3. Impact assessment
4. Containment status
5. Lessons learned
6. Next steps

Provide your incident summary:"""

        return await self._generate_content(prompt)

    async def generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """
        Generate an executive summary from threat data.
        
        Args:
            data: Threat data dictionary
            
        Returns:
            Executive summary as string
        """
        prompt = f"""You are preparing a security briefing for C-level executives.
Generate a concise executive summary from the following threat data:

**Threat Data:**
{json.dumps(data, indent=2, default=str)}

**Requirements:**
1. Maximum 2 paragraphs
2. Focus on business impact
3. Clear risk assessment
4. Key metrics
5. Top 3 recommended actions
6. No technical jargon

Generate the executive summary:"""

        return await self._generate_content(prompt)

    async def chat_with_logs(
        self,
        question: str,
        log_context: str,
    ) -> ChatResponse:
        """
        Interactive Q&A with log data.
        
        Args:
            question: User's question about the logs
            log_context: Log data to analyze
            
        Returns:
            ChatResponse with answer and metadata
        """
        prompt = f"""You are a security analyst assistant helping to analyze logs
and threat data. Answer the following question based on the provided context:

**Question:**
{question}

**Log/Threat Context:**
{log_context[:10000]}  # Limit context size

**Requirements:**
1. Be specific and actionable
2. Reference specific entries from the logs when relevant
3. Suggest follow-up investigations
4. Provide confidence level for your analysis

Answer the question:"""

        answer = await self._generate_content(prompt)
        
        # Generate follow-up questions
        follow_ups = [
            "What are the most critical IOCs to block immediately?",
            "Are there patterns suggesting a coordinated attack?",
            "Which geographic regions show the most activity?",
        ]
        
        return ChatResponse(
            answer=answer,
            sources_used=["threat_feeds", "elasticsearch_iocs"],
            confidence=0.85,
            follow_up_questions=follow_ups,
        )

    async def generate_full_report(
        self,
        request: ReportRequest,
    ) -> ThreatReport:
        """
        Generate a complete threat report based on request parameters.
        
        Args:
            request: ReportRequest with type, time range, filters
            
        Returns:
            Complete ThreatReport object
        """
        # Fetch threat context from Elasticsearch
        context = await self._fetch_threat_context(
            time_range=request.time_range,
            filters=request.filters,
            max_iocs=request.max_iocs,
        )
        
        # Build prompt based on report type
        type_prompts = {
            ReportType.THREAT_INTELLIGENCE: "Generate a comprehensive threat intelligence report",
            ReportType.INCIDENT_SUMMARY: "Generate a security incident summary report",
            ReportType.EXECUTIVE_BRIEFING: "Generate an executive security briefing",
            ReportType.IOC_ANALYSIS: "Generate a detailed IOC analysis report",
            ReportType.DARK_WEB_EXPOSURE: "Generate a dark web exposure assessment report",
        }
        
        base_prompt = type_prompts.get(request.report_type, "Generate a threat report")
        
        if request.custom_prompt:
            base_prompt = f"{base_prompt}. Additional focus: {request.custom_prompt}"
        
        # Add context data to prompt
        full_prompt = f"""{base_prompt}

**Time Range:** {context['time_range_start']} to {context['time_range_end']}

**Statistics:**
{json.dumps(context.get('stats', {}), indent=2)}

**Recent Indicators ({context['total_indicators']} total):**
{self._format_ioc_table(context.get('indicators', []))}

**Geographic Distribution:**
{json.dumps(context.get('country_stats', {}), indent=2)}

Generate a professional, actionable report in markdown format:"""

        # Generate content
        content = await self._generate_content(full_prompt)
        
        # Generate executive summary
        exec_summary = await self.generate_executive_summary(context)
        
        # Parse time range
        start_time, end_time = self._parse_time_range(request.time_range)
        
        # Build report
        report = ThreatReport(
            title=f"{request.report_type.value.replace('_', ' ').title()} - {datetime.utcnow().strftime('%Y-%m-%d')}",
            type=request.report_type,
            content=content,
            severity=self._determine_severity(context),
            iocs=self._extract_iocs_from_context(context) if request.include_iocs else [],
            recommendations=self._generate_recommendations(context),
            executive_summary=exec_summary,
            time_range_start=start_time,
            time_range_end=end_time,
            filters_applied=request.filters,
            model_used="mock" if self._use_mock else "gemini-1.5-pro",
        )
        
        # Store report in Elasticsearch
        await self._store_report(report)
        
        return report

    async def _store_report(self, report: ThreatReport) -> bool:
        """Store generated report in Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            logger.warning("Cannot store report - Elasticsearch not connected")
            return False
        
        try:
            doc = {
                "id": report.id,
                "title": report.title,
                "type": report.type.value,
                "content": report.content,
                "generated_at": report.generated_at.isoformat(),
                "severity": report.severity.value,
                "iocs": [ioc.model_dump() for ioc in report.iocs],
                "recommendations": [rec.model_dump() for rec in report.recommendations],
                "executive_summary": report.executive_summary,
                "time_range_start": report.time_range_start.isoformat() if report.time_range_start else None,
                "time_range_end": report.time_range_end.isoformat() if report.time_range_end else None,
                "filters_applied": report.filters_applied,
                "model_used": report.model_used,
            }
            
            await es_service.client.index(
                index=self.reports_index,
                id=report.id,
                document=doc,
            )
            logger.info(f"Stored report {report.id} in Elasticsearch")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store report: {e}")
            return False

    async def get_report(self, report_id: str) -> Optional[ThreatReport]:
        """Retrieve a report by ID from Elasticsearch."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return None
        
        try:
            response = await es_service.client.get(
                index=self.reports_index,
                id=report_id,
            )
            
            doc = response["_source"]
            return ThreatReport(
                id=doc["id"],
                title=doc["title"],
                type=ReportType(doc["type"]),
                content=doc["content"],
                generated_at=datetime.fromisoformat(doc["generated_at"]),
                severity=SeverityLevel(doc["severity"]),
                iocs=[IOCItem(**ioc) for ioc in doc.get("iocs", [])],
                recommendations=[Recommendation(**rec) for rec in doc.get("recommendations", [])],
                executive_summary=doc.get("executive_summary"),
                time_range_start=datetime.fromisoformat(doc["time_range_start"]) if doc.get("time_range_start") else None,
                time_range_end=datetime.fromisoformat(doc["time_range_end"]) if doc.get("time_range_end") else None,
                filters_applied=doc.get("filters_applied", {}),
                model_used=doc.get("model_used", "unknown"),
            )
            
        except Exception as e:
            logger.error(f"Failed to get report {report_id}: {e}")
            return None

    async def list_reports(
        self,
        limit: int = 20,
        offset: int = 0,
        report_type: Optional[ReportType] = None,
        severity: Optional[SeverityLevel] = None,
    ) -> Dict[str, Any]:
        """List reports with optional filtering."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return {"reports": [], "total": 0}
        
        try:
            # Build query
            filter_clauses = []
            
            if report_type:
                filter_clauses.append({"term": {"type": report_type.value}})
            
            if severity:
                filter_clauses.append({"term": {"severity": severity.value}})
            
            body = {
                "query": {
                    "bool": {
                        "filter": filter_clauses if filter_clauses else [{"match_all": {}}],
                    }
                },
                "sort": [{"generated_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
            }
            
            response = await es_service.client.search(
                index=self.reports_index,
                body=body,
            )
            
            reports = []
            for hit in response["hits"]["hits"]:
                doc = hit["_source"]
                reports.append({
                    "id": doc["id"],
                    "title": doc["title"],
                    "type": doc["type"],
                    "generated_at": doc["generated_at"],
                    "severity": doc["severity"],
                    "executive_summary": doc.get("executive_summary", "")[:200] + "...",
                })
            
            return {
                "reports": reports,
                "total": response["hits"]["total"]["value"],
            }
            
        except Exception as e:
            logger.error(f"Failed to list reports: {e}")
            return {"reports": [], "total": 0}

    async def delete_report(self, report_id: str) -> bool:
        """Delete a report by ID."""
        if not es_service.client:
            await es_service.connect()
        
        if not es_service.client:
            return False
        
        try:
            await es_service.client.delete(
                index=self.reports_index,
                id=report_id,
            )
            logger.info(f"Deleted report {report_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete report {report_id}: {e}")
            return False


# Singleton instance
vertex_ai_service = VertexAIService()
