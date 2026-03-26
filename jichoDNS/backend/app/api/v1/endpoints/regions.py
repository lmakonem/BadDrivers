"""Region endpoints - African country and ASN threat data."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Query
from pydantic import BaseModel
from datetime import datetime

from app.services.elasticsearch import es_service

router = APIRouter()

# African countries with basic centroid coordinates
AFRICAN_COUNTRIES = {
    "DZ": {"name": "Algeria", "lat": 28.03, "lon": 1.66},
    "AO": {"name": "Angola", "lat": -11.20, "lon": 17.87},
    "BJ": {"name": "Benin", "lat": 9.31, "lon": 2.32},
    "BW": {"name": "Botswana", "lat": -22.33, "lon": 24.68},
    "BF": {"name": "Burkina Faso", "lat": 12.24, "lon": -1.56},
    "BI": {"name": "Burundi", "lat": -3.37, "lon": 29.92},
    "CV": {"name": "Cabo Verde", "lat": 16.00, "lon": -24.01},
    "CM": {"name": "Cameroon", "lat": 7.37, "lon": 12.35},
    "CF": {"name": "Central African Republic", "lat": 6.61, "lon": 20.94},
    "TD": {"name": "Chad", "lat": 15.45, "lon": 18.73},
    "KM": {"name": "Comoros", "lat": -11.88, "lon": 43.87},
    "CG": {"name": "Congo", "lat": -0.23, "lon": 15.83},
    "CD": {"name": "DR Congo", "lat": -4.04, "lon": 21.76},
    "CI": {"name": "Côte d'Ivoire", "lat": 7.54, "lon": -5.55},
    "DJ": {"name": "Djibouti", "lat": 11.83, "lon": 42.59},
    "EG": {"name": "Egypt", "lat": 26.82, "lon": 30.80},
    "GQ": {"name": "Equatorial Guinea", "lat": 1.65, "lon": 10.27},
    "ER": {"name": "Eritrea", "lat": 15.18, "lon": 39.78},
    "SZ": {"name": "Eswatini", "lat": -26.52, "lon": 31.47},
    "ET": {"name": "Ethiopia", "lat": 9.15, "lon": 40.49},
    "GA": {"name": "Gabon", "lat": -0.80, "lon": 11.61},
    "GM": {"name": "Gambia", "lat": 13.44, "lon": -15.31},
    "GH": {"name": "Ghana", "lat": 7.95, "lon": -1.02},
    "GN": {"name": "Guinea", "lat": 9.95, "lon": -9.70},
    "GW": {"name": "Guinea-Bissau", "lat": 11.80, "lon": -15.18},
    "KE": {"name": "Kenya", "lat": -0.02, "lon": 37.91},
    "LS": {"name": "Lesotho", "lat": -29.61, "lon": 28.23},
    "LR": {"name": "Liberia", "lat": 6.43, "lon": -9.43},
    "LY": {"name": "Libya", "lat": 26.34, "lon": 17.23},
    "MG": {"name": "Madagascar", "lat": -18.77, "lon": 46.87},
    "MW": {"name": "Malawi", "lat": -13.25, "lon": 34.30},
    "ML": {"name": "Mali", "lat": 17.57, "lon": -4.00},
    "MR": {"name": "Mauritania", "lat": 21.01, "lon": -10.94},
    "MU": {"name": "Mauritius", "lat": -20.35, "lon": 57.55},
    "MA": {"name": "Morocco", "lat": 31.79, "lon": -7.09},
    "MZ": {"name": "Mozambique", "lat": -18.67, "lon": 35.53},
    "NA": {"name": "Namibia", "lat": -22.96, "lon": 18.49},
    "NE": {"name": "Niger", "lat": 17.61, "lon": 8.08},
    "NG": {"name": "Nigeria", "lat": 9.08, "lon": 8.68},
    "RW": {"name": "Rwanda", "lat": -1.94, "lon": 29.87},
    "ST": {"name": "São Tomé and Príncipe", "lat": 0.19, "lon": 6.61},
    "SN": {"name": "Senegal", "lat": 14.50, "lon": -14.45},
    "SC": {"name": "Seychelles", "lat": -4.68, "lon": 55.49},
    "SL": {"name": "Sierra Leone", "lat": 8.46, "lon": -11.78},
    "SO": {"name": "Somalia", "lat": 5.15, "lon": 46.20},
    "ZA": {"name": "South Africa", "lat": -30.56, "lon": 22.94},
    "SS": {"name": "South Sudan", "lat": 6.88, "lon": 31.31},
    "SD": {"name": "Sudan", "lat": 12.86, "lon": 30.22},
    "TZ": {"name": "Tanzania", "lat": -6.37, "lon": 34.89},
    "TG": {"name": "Togo", "lat": 8.62, "lon": 0.82},
    "TN": {"name": "Tunisia", "lat": 33.89, "lon": 9.54},
    "UG": {"name": "Uganda", "lat": 1.37, "lon": 32.29},
    "ZM": {"name": "Zambia", "lat": -13.13, "lon": 27.85},
    "ZW": {"name": "Zimbabwe", "lat": -19.02, "lon": 29.15},
}


class RegionScore(BaseModel):
    region_type: str  # country or asn
    region_id: str
    region_name: str
    c2_risk: float
    exfil_risk: float
    phishing_risk: float
    overall_risk: float
    indicator_count: int
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timestamp: datetime


class RegionListResponse(BaseModel):
    items: List[RegionScore]
    timestamp: datetime


@router.get("/countries", response_model=RegionListResponse)
async def list_country_scores(
    min_risk: float = Query(0.0, ge=0, le=1, description="Minimum risk score"),
):
    """
    Get threat risk scores for African countries.
    
    Returns aggregated C2, exfiltration, and phishing risk scores.
    """
    # TODO: Implement database query
    return RegionListResponse(
        items=[],
        timestamp=datetime.utcnow(),
    )


@router.get("/countries/{country_code}", response_model=RegionScore)
async def get_country_score(country_code: str):
    """Get detailed threat score for a specific country."""
    # TODO: Implement database query
    return RegionScore(
        region_type="country",
        region_id=country_code.upper(),
        region_name="Unknown",
        c2_risk=0.0,
        exfil_risk=0.0,
        phishing_risk=0.0,
        overall_risk=0.0,
        indicator_count=0,
        timestamp=datetime.utcnow(),
    )


@router.get("/asns", response_model=RegionListResponse)
async def list_asn_scores(
    country: Optional[str] = Query(None, description="Filter by country code"),
    min_risk: float = Query(0.0, ge=0, le=1),
):
    """
    Get threat risk scores for African ASNs.
    """
    # TODO: Implement database query
    return RegionListResponse(
        items=[],
        timestamp=datetime.utcnow(),
    )


@router.get("/map")
async def get_map_data():
    """
    Get GeoJSON data for the threat map visualization.
    
    Returns point features for African countries with threat data.
    """
    # Get threat stats from Elasticsearch
    country_stats = await es_service.get_country_threat_stats()
    
    features = []
    
    # Create a feature for each African country
    for country_code, country_info in AFRICAN_COUNTRIES.items():
        stats = country_stats.get(country_code, {})
        total_threats = stats.get("total", 0)
        
        # Calculate risk score (0-100) based on threat count
        # Using logarithmic scale for better visualization
        if total_threats > 0:
            import math
            risk_score = min(100, int(math.log10(total_threats + 1) * 30))
        else:
            risk_score = 0
        
        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [country_info["lon"], country_info["lat"]]
            },
            "properties": {
                "country_code": country_code,
                "country_name": country_info["name"],
                "total_threats": total_threats,
                "c2_count": stats.get("c2", 0),
                "malware_count": stats.get("malware", 0),
                "phishing_count": stats.get("phishing", 0),
                "risk_score": risk_score,
                "has_data": total_threats > 0,
            }
        }
        features.append(feature)
    
    # Also add any non-African countries that have threat data
    for country_code, stats in country_stats.items():
        if country_code not in AFRICAN_COUNTRIES and country_code:
            # For non-African countries, we'll skip them for now
            # as this is an Africa-focused platform
            pass
    
    return {
        "type": "FeatureCollection",
        "features": features,
    }
