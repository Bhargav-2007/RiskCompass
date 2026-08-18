"""
API routes for vulnerability management.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, date

from app.repository import (
    get_vulnerability_by_cve,
    create_vulnerability,
    list_vulnerabilities,
    get_asset,
    create_asset,
    list_assets,
    get_asset_vulnerability,
    create_asset_vulnerability,
    update_asset_vulnerability,
    list_asset_vulnerabilities,
    get_risk_score_by_asset_vulnerability,
    create_risk_score,
    update_risk_score,
    list_risk_scores,
    create_threat_intelligence,
    get_threat_intelligence_by_vulnerability
)
from app.db import database, vulnerabilities, assets, asset_vulnerabilities, risk_scores, threat_intelligence

router = APIRouter()


# Vulnerability endpoints
@router.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "healthy"}


@router.get("/vulnerabilities/", response_model=List[Dict[str, Any]])
async def read_vulnerabilities(
    kev: Optional[bool] = Query(None, description="Filter by KEV status"),
    min_epss: Optional[float] = Query(None, description="Minimum EPSS score"),
    max_epss: Optional[float] = Query(None, description="Maximum EPSS score"),
    min_cvss: Optional[float] = Query(None, description="Minimum CVSS v3 score"),
    max_cvss: Optional[float] = Query(None, description="Maximum CVSS v3 score"),
    cwe_id: Optional[str] = Query(None, description="Filter by CWE ID"),
    limit: int = Query(100, description="Limit number of results"),
    offset: int = Query(0, description="Offset for pagination")
):
    """
    List vulnerabilities with optional filtering.
    """
    vulns = await list_vulnerabilities(
        kev=kev,
        min_epss=min_epss,
        max_epss=max_epss,
        min_cvss=min_cvss,
        max_cvss=max_cvss,
        cwe_id=cwe_id,
        limit=limit,
        offset=offset
    )
    return vulns


@router.post("/vulnerabilities/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_vulnerability_endpoint(vulnerability: Dict[str, Any]):
    """
    Create a new vulnerability.
    """
    # Check if vulnerability already exists
    existing = await get_vulnerability_by_cve(vulnerability["cve_id"])
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vulnerability with CVE ID {vulnerability['cve_id']} already exists"
        )
    
    # Create vulnerability
    vuln_id = await create_vulnerability(vulnerability)
    
    # Return created vulnerability
    created = await get_vulnerability_by_cve(vulnerability["cve_id"])
    return created


@router.get("/vulnerabilities/{cve_id}", response_model=Dict[str, Any])
async def read_vulnerability(cve_id: str = Path(..., description="CVE ID of the vulnerability")):
    """
    Get a specific vulnerability by CVE ID.
    """
    vulnerability = await get_vulnerability_by_cve(cve_id)
    if not vulnerability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability with CVE ID {cve_id} not found"
        )
    return vulnerability


# Asset endpoints
@router.get("/assets/", response_model=List[Dict[str, Any]])
async def read_assets(
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    internet_exposure: Optional[bool] = Query(None, description="Filter by internet exposure"),
    limit: int = Query(100, description="Limit number of results"),
    offset: int = Query(0, description="Offset for pagination")
):
    """
    List assets with optional filtering.
    """
    assets_list = await list_assets(
        asset_type=asset_type,
        internet_exposure=internet_exposure,
        limit=limit,
        offset=offset
    )
    return assets_list


@router.post("/assets/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_asset_endpoint(asset: Dict[str, Any]):
    """
    Create a new asset.
    """
    asset_id = await create_asset(asset)
    created = await get_asset(asset_id)
    return created


@router.get("/assets/{asset_id}", response_model=Dict[str, Any])
async def read_asset(asset_id: uuid.UUID = Path(..., description="Asset ID")):
    """
    Get a specific asset by ID.
    """
    asset_obj = await get_asset(asset_id)
    if not asset_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with ID {asset_id} not found"
        )
    return asset_obj


# Asset-Vulnerability endpoints
@router.post("/asset-vulnerabilities/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_asset_vulnerability_endpoint(av: Dict[str, Any]):
    """
    Create a new asset-vulnerability link.
    """
    av_id = await create_asset_vulnerability(av)
    created = await get_asset_vulnerability(av["asset_id"], av["vulnerability_id"])
    return created


@router.get("/asset-vulnerabilities/", response_model=List[Dict[str, Any]])
async def read_asset_vulnerabilities(
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by asset ID"),
    vulnerability_id: Optional[uuid.UUID] = Query(None, description="Filter by vulnerability ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Limit number of results"),
    offset: int = Query(0, description="Offset for pagination")
):
    """
    List asset-vulnerability links with optional filtering.
    """
    av_list = await list_asset_vulnerabilities(
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        status=status,
        limit=limit,
        offset=offset
    )
    return av_list


@router.patch("/asset-vulnerabilities/{av_id}", response_model=Dict[str, Any])
async def update_asset_vulnerability_endpoint(
    av_id: uuid.UUID = Path(..., description="Asset-Vulnerability ID"),
    update_data: Dict[str, Any] = None
):
    """
    Update an asset-vulnerability link.
    """
    await update_asset_vulnerability(av_id, update_data or {})
    # Note: We don't have a direct get by av_id, but we could add one
    # For now, return a simple success message
    return {"message": "Asset-vulnerability updated successfully"}


# Risk score endpoints
@router.get("/risk/summary", response_model=Dict[str, Any])
async def get_risk_summary():
    """
    Get a summary of risk scores.
    """
    # This is a simplified version - in practice, you'd want to use aggregate queries
    risk_scores_list = await list_risk_scores(limit=1000)
    
    total = len(risk_scores_list)
    p0_count = len([rs for rs in risk_scores_list if rs.get("priority_tier") == "P0"])
    p1_count = len([rs for rs in risk_scores_list if rs.get("priority_tier") == "P1"])
    p2_count = len([rs for rs in risk_scores_list if rs.get("priority_tier") == "P2"])
    p3_count = len([rs for rs in risk_scores_list if rs.get("priority_tier") == "P3"])
    
    avg_risk = sum([rs.get("dynamic_risk_score", 0) for rs in risk_scores_list]) / total if total > 0 else 0
    
    return {
        "total_vulnerabilities": total,
        "p0_count": p0_count,
        "p1_count": p1_count,
        "p2_count": p2_count,
        "p3_count": p3_count,
        "average_risk_score": round(avg_risk, 2)
    }


@router.get("/risk/top", response_model=List[Dict[str, Any]])
async def get_top_risks(limit: int = Query(10, description="Number of top risks to return")):
    """
    Get top risk vulnerabilities.
    """
    # Get all risk scores sorted by dynamic_risk_score descending
    risk_scores_list = await list_risk_scores(limit=1000)  # Get a large number to sort
    sorted_risks = sorted(risk_scores_list, key=lambda x: x.get("dynamic_risk_score", 0), reverse=True)
    top_risks = sorted_risks[:limit]
    
    # Enrich with vulnerability and asset details
    enriched_risks = []
    for risk in top_risks:
        # Get asset vulnerability link
        av_id = risk.get("asset_vulnerability_id")
        if av_id:
            # We don't have a direct get by av_id, but we can fetch from asset_vulnerabilities table
            # For simplicity, we'll just return the risk score with the ID
            # In a real implementation, you'd want to join with vulnerabilities and assets
            enriched_risks.append(risk)
    
    return enriched_risks


# Threat intelligence endpoints
@router.post("/threat-intelligence/", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_threat_intelligence_endpoint(ti: Dict[str, Any]):
    """
    Create a new threat intelligence record.
    """
    ti_id = await create_threat_intelligence(ti)
    created = await get_threat_intelligence_by_vulnerability(ti["vulnerability_id"])
    return created[0] if created else {}


# Additional endpoints for ML model integration (placeholders)
@router.post("/ml/train", response_model=Dict[str, Any])
async def train_model_endpoint():
    """
    Trigger ML model training (placeholder).
    """
    # In practice, this would trigger a background job
    return {"message": "Model training initiated"}


@router.post("/ml/predict/{av_id}", response_model=Dict[str, Any])
async def predict_risk_endpoint(av_id: uuid.UUID = Path(..., description="Asset-Vulnerability ID")):
    """
    Predict risk for an asset-vulnerability pair (placeholder).
    """
    # In practice, this would use the ML model to predict risk
    return {
        "asset_vulnerability_id": str(av_id),
        "ml_risk_score": 75.5,
        "dynamic_risk_score": 78.2,
        "priority_tier": "P1"
    }