"""Analysis endpoints - DNS analysis and DGA detection."""

from typing import List
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class DomainAnalysisRequest(BaseModel):
    domain: str


class DomainAnalysisResponse(BaseModel):
    domain: str
    entropy: float
    length: int
    label_count: int
    digit_ratio: float
    consonant_ratio: float
    vowel_ratio: float
    has_digits: bool
    tld: str
    is_dga_like: bool
    dga_score: float
    impossible_ngrams: List[str]
    classification: str  # benign, suspicious, malicious
    confidence: float


@router.post("/domain", response_model=DomainAnalysisResponse)
async def analyze_domain(request: DomainAnalysisRequest):
    """
    Analyze a domain for DGA-like characteristics.
    
    Performs entropy analysis, n-gram detection, and linguistic analysis.
    """
    from app.services.dns_analysis import analyze_domain as do_analysis
    return do_analysis(request.domain)


class BulkAnalysisRequest(BaseModel):
    domains: List[str]


@router.post("/domains/bulk")
async def analyze_domains_bulk(request: BulkAnalysisRequest):
    """Analyze multiple domains in bulk."""
    from app.services.dns_analysis import analyze_domain as do_analysis
    results = [do_analysis(d) for d in request.domains[:100]]  # Limit to 100
    return {"results": results}
