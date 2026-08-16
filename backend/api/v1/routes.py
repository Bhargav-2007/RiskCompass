"""
FastAPI API Endpoints for Dynamic Vulnerability Intelligence & Risk Scoring Platform
Defines routes for vulnerability ingestion and risk analytics.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Path
from typing import List, Optional, Dict, Any
from datetime import datetime, date
from pydantic import BaseModel, Field
import uuid

# Initialize router
router = APIRouter(prefix="/api/v1", tags=["vulnerability-risk"])

# =============================================================================
# PYDANTIC MODELS FOR REQUEST/RESPONSE
# =============================================================================

# Vulnerability Models
class VulnerabilityBase(BaseModel):
    cve_id: str = Field(..., example="CVE-2023-12345")
    cvss_v3_score: Optional[float] = Field(None, ge=0.0, le=10.0, example=7.5)
    cvss_v3_vector: Optional[str] = Field(None, example="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cvss_v4_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_v4_vector: Optional[str] = None
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, example=0.65)
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0)
    kev: bool = Field(False, example=False)
    kev_date: Optional[date] = None
    cwe_id: Optional[str] = Field(None, example="CWE-79")
    description: Optional[str] = None
    references: Optional[List[Dict[str, str]]] = None
    exploit_available: bool = Field(False)
    exploit_maturity: Optional[str] = Field(None, example="functional")  # none, proof-of-concept, functional, weaponized
    published_date: datetime
    modified_date: datetime

class VulnerabilityCreate(VulnerabilityBase):
    pass

class VulnerabilityResponse(VulnerabilityBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# Asset Models
class AssetBase(BaseModel):
    asset_tag: Optional[str] = Field(None, example="ASSET-00123")
    hostname: Optional[str] = Field(None, example="web-server-01")
    ip_address: Optional[str] = Field(None, example="192.168.1.100")
    mac_address: Optional[str] = None
    asset_type: str = Field(..., example="server")  # server, web-app, database, cloud-storage, api
    os: Optional[str] = Field(None, example="Ubuntu 20.04")
    os_version: Optional[str] = Field(None, example="20.04.5 LTS")
    internet_exposure: bool = Field(False)
    data_sensitivity: str = Field(..., example="confidential")  # public, internal, confidential, restricted
    business_importance: int = Field(..., ge=1, le=5, example=4)  # 1-5 scale
    owner_team: Optional[str] = Field(None, example="Platform Team")
    owner_email: Optional[str] = Field(None, example="platform@example.com")
    cloud_provider: Optional[str] = Field(None, example="aws")  # aws, azure, gcp, on-premise
    cloud_region: Optional[str] = Field(None, example="us-east-1")
    cloud_instance_type: Optional[str] = Field(None, example="t3.medium")
    tags: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    id: uuid.UUID
    asset_criticality_score: float
    created_at: datetime
    updated_at: datetime
    last_scanned: Optional[datetime]

    class Config:
        orm_mode = True

# Asset-Vulnerability Mapping
class AssetVulnerabilityBase(BaseModel):
    asset_id: uuid.UUID
    vulnerability_id: uuid.UUID
    status: str = Field("open", example="open")  # open, patched, mitigated, false-positive, risk-accepted
    detected_at: Optional[datetime] = None
    patched_at: Optional[datetime] = None
    asset_specific_cvss: Optional[float] = Field(None, ge=0.0, le=10.0)
    exploitability_adjustment: Optional[float] = Field(None, ge=0.0, le=1.0)
    on_attack_path_to_crown_jewel: bool = Field(False)
    attack_path_probability: Optional[float] = Field(None, ge=0.0, le=1.0)
    asset_specific_business_impact: Optional[float] = Field(None, ge=0.0)  # in USD

class AssetVulnerabilityCreate(AssetVulnerabilityBase):
    pass

class AssetVulnerabilityResponse(AssetVulnerabilityBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# Risk Score Models
class RiskScoreBase(BaseModel):
    # Component scores (0-100)
    cvss_base_score: float = Field(..., ge=0.0, le=100.0)
    epss_component: float = Field(..., ge=0.0, le=100.0)
    kev_component: float = Field(..., ge=0.0, le=100.0)
    asset_criticality_component: float = Field(..., ge=0.0, le=100.0)
    exposure_component: float = Field(..., ge=0.0, le=100.0)
    exploit_availability_component: float = Field(..., ge=0.0, le=100.0)
    threat_activity_component: float = Field(..., ge=0.0, le=100.0)
    vulnerability_age_component: float = Field(..., ge=0.0, le=100.0)
    business_impact_component: float = Field(..., ge=0.0, le=100.0)
    # ML model output
    ml_risk_score: float = Field(..., ge=0.0, le=100.0)
    # Final score and tier
    dynamic_risk_score: float = Field(..., ge=0.0, le=100.0, example=85.5)
    priority_tier: str = Field(..., example="P0")  # P0, P1, P2, P3
    # Explainability
    top_contributing_factors: Optional[List[Dict[str, Any]]] = None
    shap_values: Optional[Dict[str, float]] = None
    natural_language_explanation: Optional[str] = None
    # Feedback
    actual_exploited: Optional[bool] = None
    exploited_at: Optional[datetime] = None

class RiskScoreCreate(RiskScoreBase):
    asset_vulnerability_id: uuid.UUID

class RiskScoreResponse(RiskScoreBase):
    id: uuid.UUID
    asset_vulnerability_id: uuid.UUID
    calculated_at: datetime
    model_version: str
    calculation_duration_ms: int

    class Config:
        orm_mode = True

# Analytics Models
class RiskSummary(BaseModel):
    total_vulnerabilities: int
    p0_count: int
    p1_count: int
    p2_count: int
    p3_count: int
    average_risk_score: float
    max_risk_score: float
    trending_up: int  # Count of vulnerabilities with increasing risk
    trending_down: int  # Count of vulnerabilities with decreasing risk

class TopRiskItem(BaseModel):
    id: uuid.UUID
    cve_id: str
    asset_hostname: str
    dynamic_risk_score: float
    priority_tier: str
    business_impact_usd: Optional[float] = None
    days_since_published: int

class RiskTrendsPoint(BaseModel):
    date: date
    average_risk_score: float
    p0_count: int
    p1_count: int

# =============================================================================
# VULNERABILITY INGESTION ENDPOINTS
# =============================================================================

@router.post("/vulnerabilities/", response_model=VulnerabilityResponse, status_code=201)
async def create_vulnerability(
    vulnerability: VulnerabilityCreate,
):
    """
    Ingest a single vulnerability record.
    """
    # In practice: check if CVE exists, update if newer, else create
    # For now, we'll simulate creation
    vuln_id = uuid.uuid4()
    return VulnerabilityResponse(
        id=vuln_id,
        **vulnerability.dict(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

@router.post("/vulnerabilities/batch", response_model=List[VulnerabilityResponse], status_code=201)
async def create_vulnerabilities_batch(
    vulnerabilities: List[VulnerabilityCreate],
    background_tasks: BackgroundTasks,
):
    """
    Ingest a batch of vulnerability records (e.g., from NVD feed).
    Triggers background risk scoring for new/updated vulnerabilities.
    """
    # Simulate batch creation
    results = []
    for vuln in vulnerabilities:
        vuln_id = uuid.uuid4()
        results.append(VulnerabilityResponse(
            id=vuln_id,
            **vulnerability.dict(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        ))
    
    # Trigger background task for risk scoring (would be implemented with Celery)
    background_tasks.add_task(trigger_risk_rescoring, [v.cve_id for v in vulnerabilities])
    
    return results

@router.get("/vulnerabilities/{cve_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    cve_id: str = Path(..., example="CVE-2023-12345"),
):
    """
    Retrieve a vulnerability by its CVE ID.
    """
    # Simulate retrieval - return mock data for any CVE ID
    # In practice: query database for CVE
    return VulnerabilityResponse(
        id=uuid.uuid4(),
        cve_id=cve_id,
        cvss_v3_score=7.5,
        epss_score=0.65,
        kev=False,
        published_date=datetime.utcnow(),
        modified_date=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

@router.get("/vulnerabilities/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    kev: Optional[bool] = Query(None, description="Filter by KEV status"),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum EPSS score"),
    max_epss: Optional[float] = Query(None, ge=0.0, le=1.0, description="Maximum EPSS score"),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum CVSS score"),
    max_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Maximum CVSS score"),
    cwe_id: Optional[str] = Query(None, description="Filter by CWE ID"),
    limit: int = Query(100, ge=1, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    List vulnerabilities with filtering and pagination.
    """
    # Simulate list - in practice would query with filters
    # Return empty list for now
    return []

# =============================================================================
# RISK ANALYTICS ENDPOINTS
# =============================================================================

@router.get("/risk/summary", response_model=RiskSummary)
async def get_risk_summary():
    """
    Get summary statistics of risk scores across all assets.
    """
    # Simulate summary data
    return RiskSummary(
        total_vulnerabilities=1245,
        p0_count=34,
        p1_count=89,
        p2_count=256,
        p3_count=866,
        average_risk_score=42.3,
        max_risk_score=98.7,
        trending_up=12,
        trending_down=45
    )

@router.get("/risk/top", response_model=List[TopRiskItem])
async def get_top_risk_vulnerabilities(
    limit: int = Query(10, ge=1, le=100, description="Number of top risks to return"),
    priority_tier: Optional[str] = Query(None, regex="^(P0|P1|P2|P3)$", description="Filter by priority tier"),
):
    """
    Get top N vulnerabilities by risk score.
    """
    # Simulate top risks
    top_risks = []
    for i in range(min(limit, 5)):  # Return up to 5 for demo
        top_risks.append(TopRiskItem(
            id=uuid.uuid4(),
            cve_id=f"CVE-2023-{1000+i:05d}",
            asset_hostname=f"web-server-{i+1:02d}",
            dynamic_risk_score=95.0 - (i * 2.5),
            priority_tier="P0" if i < 2 else "P1",
            business_impact_usd=2500000.0 + (i * 500000),
            days_since_published=30 + (i * 10)
        ))
    return top_risks

@router.get("/risk/trends", response_model=List[RiskTrendsPoint])
async def get_risk_trends(
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
):
    """
    Get risk score trends over time (daily averages).
    """
    # Simulate trend data
    from datetime import timedelta
    trends = []
    base_score = 40.0
    for i in range(days):
        date_point = date.today() - timedelta(days=days-i-1)
        # Simulate some variation
        score = base_score + (i % 7) - 3
        trends.append(RiskTrendsPoint(
            date=date_point,
            average_risk_score=max(0, min(100, score)),
            p0_count=max(0, int((score - 70) / 5)) if score > 70 else 0,
            p1_count=max(0, int((score - 50) / 3)) if score > 50 else 0
        ))
    return trends

@router.get("/assets/{asset_id}/risk", response_model=List[RiskScoreResponse])
async def get_asset_risk_details(
    asset_id: uuid.UUID = Path(..., example="123e4567-e89b-12d3-a456-426614174000"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Get risk scores for all vulnerabilities associated with a specific asset.
    """
    # Simulate asset risk details
    # In practice: join asset_vulnerabilities, vulnerabilities, risk_scores
    risks = []
    for i in range(3):  # Return 3 sample risks
        risks.append(RiskScoreResponse(
            id=uuid.uuid4(),
            asset_vulnerability_id=uuid.uuid4(),
            cvss_base_score=75.0,
            epss_component=65.0,
            kev_component=20.0,
            asset_criticality_component=80.0,
            exposure_component=90.0,
            exploit_availability_component=70.0,
            threat_activity_component=60.0,
            vulnerability_age_component=30.0,
            business_impact_component=85.0,
            ml_risk_score=78.5,
            dynamic_risk_score=72.3,
            priority_tier="P1",
            top_contributing_factors=[
                {"factor": "Internet Exposure", "percentage": 25},
                {"factor": "Business Impact", "percentage": 20},
                {"factor": "EPSS Score", "percentage": 18}
            ],
            natural_language_explanation="This vulnerability is prioritized due to high asset criticality, internet exposure, and significant business impact potential.",
            calculated_at=datetime.utcnow(),
            model_version="xgboost-v1.2.0",
            calculation_duration_ms=125
        ))
    return risks

@router.post("/risk/recalculate", status_code=202)
async def trigger_risk_recalculation(
    background_tasks: BackgroundTasks,
    asset_ids: Optional[List[uuid.UUID]] = Query(None, description="List of asset IDs to recalculate (if empty, recalculate all)"),
    cve_ids: Optional[List[str]] = Query(None, description="List of CVE IDs to recalculate (if empty, recalculate all)"),
):
    """
    Trigger recalculation of risk scores for specified assets or vulnerabilities.
    Typically called when new threat intelligence, EPSS updates, or asset changes occur.
    """
    # Determine scope
    scope = "all"
    if asset_ids:
        scope = f"assets:{len(asset_ids)}"
    elif cve_ids:
        scope = f"cves:{len(cve_ids)}"
    
    # Add background task for recalculation (would be implemented with Celery)
    background_tasks.add_task(trigger_risk_rescoring, asset_ids=asset_ids, cve_ids=cve_ids)
    
    return {
        "message": f"Risk recalculation triggered for scope: {scope}",
        "status": "processing"
    }

# =============================================================================
# BACKGROUND TASK FUNCTIONS (PLACEHOLDERS)
# =============================================================================

async def trigger_risk_rescoring(
    asset_ids: Optional[List[uuid.UUID]] = None,
    cve_ids: Optional[List[str]] = None
):
    """
    Background task to recalculate risk scores.
    In practice, this would:
    1. Query for affected asset-vulnerability pairs
    2. Extract features for each pair
    3. Run ML model inference
    4. Update risk_scores table
    5. Send notifications for priority changes
    """
    # Placeholder implementation
    print(f"Starting risk rescoring for assets: {asset_ids}, CVEs: {cve_ids}")
    # Simulate work
    import asyncio
    await asyncio.sleep(2)
    print("Risk rescoring completed")

# =============================================================================
# HEALTH CHECK
# =============================================================================

@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "healthy", "timestamp": datetime.utcnow()}