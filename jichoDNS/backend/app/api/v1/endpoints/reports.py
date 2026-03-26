"""
Reports API endpoints - AI-powered threat report generation.

Provides endpoints for generating, retrieving, and managing
AI-generated threat intelligence reports using Vertex AI.
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.vertex_ai import (
    vertex_ai_service,
    ReportRequest,
    ReportType,
    SeverityLevel,
    ThreatReport,
    ChatRequest,
    ChatResponse,
    IOCItem,
    Recommendation,
)

router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================

class ReportSummary(BaseModel):
    """Summary view of a report for listing."""
    id: str
    title: str
    type: str
    generated_at: str
    severity: str
    executive_summary: str


class ReportListResponse(BaseModel):
    """Response for listing reports."""
    reports: List[ReportSummary]
    total: int
    page: int
    page_size: int


class ReportResponse(BaseModel):
    """Full report response."""
    id: str
    title: str
    type: str
    content: str
    generated_at: datetime
    severity: str
    iocs: List[IOCItem] = []
    recommendations: List[Recommendation] = []
    executive_summary: Optional[str] = None
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    filters_applied: dict = {}
    model_used: str = "gemini-1.5-pro"


class GenerateReportRequest(BaseModel):
    """Request body for generating a report."""
    report_type: ReportType = Field(
        description="Type of report to generate"
    )
    time_range: str = Field(
        default="24h",
        description="Time range for data: 1h, 6h, 24h, 7d, 30d"
    )
    filters: dict = Field(
        default_factory=dict,
        description="Filters: threat_type, country, source, etc."
    )
    custom_prompt: Optional[str] = Field(
        default=None,
        description="Custom instructions for the AI"
    )
    include_iocs: bool = Field(
        default=True,
        description="Whether to include IOC list in report"
    )
    max_iocs: int = Field(
        default=100,
        ge=1,
        le=500,
        description="Maximum IOCs to include"
    )


class ChatWithDataRequest(BaseModel):
    """Request body for chatting with threat data."""
    question: str = Field(
        description="Question about threat data or logs"
    )
    log_context: Optional[str] = Field(
        default=None,
        description="Additional log context to analyze"
    )
    include_recent_iocs: bool = Field(
        default=True,
        description="Include recent IOCs in context"
    )
    time_range: str = Field(
        default="24h",
        description="Time range for IOC context"
    )


class ChatWithDataResponse(BaseModel):
    """Response from chat endpoint."""
    answer: str
    sources_used: List[str] = []
    confidence: float
    follow_up_questions: List[str] = []


class DeleteResponse(BaseModel):
    """Response for delete operations."""
    success: bool
    message: str


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/generate", response_model=ReportResponse)
async def generate_report(request: GenerateReportRequest):
    """
    Generate a new AI-powered threat report.
    
    Report types:
    - **threat_intelligence**: Comprehensive threat landscape analysis
    - **incident_summary**: Security incident summary and timeline
    - **executive_briefing**: High-level executive summary
    - **ioc_analysis**: Detailed IOC breakdown and analysis
    - **dark_web_exposure**: Dark web monitoring and exposure report
    
    The report is generated using Google Vertex AI (Gemini) and stored
    in Elasticsearch for future retrieval.
    """
    try:
        # Convert to internal request model
        report_request = ReportRequest(
            report_type=request.report_type,
            time_range=request.time_range,
            filters=request.filters,
            custom_prompt=request.custom_prompt,
            include_iocs=request.include_iocs,
            max_iocs=request.max_iocs,
        )
        
        # Generate the report
        report = await vertex_ai_service.generate_full_report(report_request)
        
        return ReportResponse(
            id=report.id,
            title=report.title,
            type=report.type.value,
            content=report.content,
            generated_at=report.generated_at,
            severity=report.severity.value,
            iocs=report.iocs,
            recommendations=report.recommendations,
            executive_summary=report.executive_summary,
            time_range_start=report.time_range_start,
            time_range_end=report.time_range_end,
            filters_applied=report.filters_applied,
            model_used=report.model_used,
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {str(e)}"
        )


@router.get("", response_model=ReportListResponse)
async def list_reports(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    report_type: Optional[str] = Query(
        default=None,
        description="Filter by report type"
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: critical, high, medium, low, informational"
    ),
):
    """
    List all generated reports with pagination and filtering.
    
    Returns a summary view of reports sorted by generation date (newest first).
    """
    try:
        # Parse filters
        type_filter = None
        if report_type:
            try:
                type_filter = ReportType(report_type)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid report_type. Must be one of: {[t.value for t in ReportType]}"
                )
        
        severity_filter = None
        if severity:
            try:
                severity_filter = SeverityLevel(severity)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid severity. Must be one of: {[s.value for s in SeverityLevel]}"
                )
        
        offset = (page - 1) * page_size
        
        result = await vertex_ai_service.list_reports(
            limit=page_size,
            offset=offset,
            report_type=type_filter,
            severity=severity_filter,
        )
        
        reports = [
            ReportSummary(
                id=r["id"],
                title=r["title"],
                type=r["type"],
                generated_at=r["generated_at"],
                severity=r["severity"],
                executive_summary=r.get("executive_summary", ""),
            )
            for r in result["reports"]
        ]
        
        return ReportListResponse(
            reports=reports,
            total=result["total"],
            page=page,
            page_size=page_size,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list reports: {str(e)}"
        )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: str):
    """
    Get a specific report by ID.
    
    Returns the full report content including IOCs, recommendations,
    and all analysis details.
    """
    report = await vertex_ai_service.get_report(report_id)
    
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report {report_id} not found"
        )
    
    return ReportResponse(
        id=report.id,
        title=report.title,
        type=report.type.value,
        content=report.content,
        generated_at=report.generated_at,
        severity=report.severity.value,
        iocs=report.iocs,
        recommendations=report.recommendations,
        executive_summary=report.executive_summary,
        time_range_start=report.time_range_start,
        time_range_end=report.time_range_end,
        filters_applied=report.filters_applied,
        model_used=report.model_used,
    )


@router.post("/chat", response_model=ChatWithDataResponse)
async def chat_with_data(request: ChatWithDataRequest):
    """
    Interactive Q&A with threat data and logs.
    
    Ask questions about IOCs, threat patterns, or provide log data
    for AI-powered analysis.
    
    Examples:
    - "What are the most critical threats from the last 24 hours?"
    - "Are there any patterns in the C2 domains?"
    - "Summarize the phishing activity targeting Kenya"
    """
    try:
        # Build log context
        log_context = request.log_context or ""
        
        # Add recent IOCs to context if requested
        if request.include_recent_iocs:
            from app.services.elasticsearch import es_service
            from datetime import timedelta
            
            # Parse time range
            time_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
            hours = time_map.get(request.time_range, 24)
            since = datetime.utcnow() - timedelta(hours=hours)
            
            indicators = await es_service.get_recent_indicators(
                limit=50,
                since=since,
            )
            
            if indicators:
                ioc_summary = "\n".join([
                    f"- {i.get('indicator')} ({i.get('threat_type')}, confidence: {i.get('confidence', 0.5):.2f})"
                    for i in indicators[:20]
                ])
                log_context = f"**Recent IOCs:**\n{ioc_summary}\n\n{log_context}"
        
        # Get chat response
        response = await vertex_ai_service.chat_with_logs(
            question=request.question,
            log_context=log_context,
        )
        
        return ChatWithDataResponse(
            answer=response.answer,
            sources_used=response.sources_used,
            confidence=response.confidence,
            follow_up_questions=response.follow_up_questions,
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Chat failed: {str(e)}"
        )


@router.delete("/{report_id}", response_model=DeleteResponse)
async def delete_report(report_id: str):
    """
    Delete a report by ID.
    
    Permanently removes the report from the database.
    """
    # First check if report exists
    report = await vertex_ai_service.get_report(report_id)
    
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report {report_id} not found"
        )
    
    success = await vertex_ai_service.delete_report(report_id)
    
    if success:
        return DeleteResponse(
            success=True,
            message=f"Report {report_id} deleted successfully"
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to delete report"
        )


@router.get("/types/available")
async def get_report_types():
    """
    Get available report types and their descriptions.
    """
    return {
        "report_types": [
            {
                "value": ReportType.THREAT_INTELLIGENCE.value,
                "name": "Threat Intelligence Report",
                "description": "Comprehensive threat landscape analysis with IOCs, threat actors, and recommendations",
            },
            {
                "value": ReportType.INCIDENT_SUMMARY.value,
                "name": "Incident Summary Report",
                "description": "Security incident timeline, affected systems, containment actions, and lessons learned",
            },
            {
                "value": ReportType.EXECUTIVE_BRIEFING.value,
                "name": "Executive Briefing",
                "description": "High-level summary for leadership with key metrics, risk assessment, and business impact",
            },
            {
                "value": ReportType.IOC_ANALYSIS.value,
                "name": "IOC Analysis Report",
                "description": "Detailed breakdown of indicators by type, threat category, and geographic origin",
            },
            {
                "value": ReportType.DARK_WEB_EXPOSURE.value,
                "name": "Dark Web Exposure Report",
                "description": "Assessment of credential leaks, brand mentions, and typosquatting activity",
            },
        ],
        "severity_levels": [
            {"value": s.value, "name": s.value.title()}
            for s in SeverityLevel
        ],
        "time_ranges": [
            {"value": "1h", "name": "Last Hour"},
            {"value": "6h", "name": "Last 6 Hours"},
            {"value": "24h", "name": "Last 24 Hours"},
            {"value": "7d", "name": "Last 7 Days"},
            {"value": "30d", "name": "Last 30 Days"},
        ],
    }
