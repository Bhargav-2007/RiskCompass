"""
Repository layer for database operations.
"""

import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, date

from .db import database, vulnerabilities, assets, asset_vulnerabilities, risk_scores, threat_intelligence


# Vulnerability operations
async def get_vulnerability_by_cve(cve_id: str) -> Optional[dict]:
    query = vulnerabilities.select().where(vulnerabilities.c.cve_id == cve_id)
    result = await database.fetch_one(query)
    if result:
        result = dict(result)
        # Ensure the id is a string
        if result['id'] is not None:
            result['id'] = str(result['id'])
    return result


async def create_vulnerability(vulnerability_data: dict) -> uuid.UUID:
    # Ensure we have an ID for the vulnerability
    if 'id' not in vulnerability_data:
        vulnerability_data['id'] = str(uuid.uuid4())
    query = vulnerabilities.insert().values(**vulnerability_data)
    await database.execute(query)
    return uuid.UUID(vulnerability_data['id'])


async def list_vulnerabilities(
    kev: Optional[bool] = None,
    min_epss: Optional[float] = None,
    max_epss: Optional[float] = None,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    cwe_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[dict]:
    query = vulnerabilities.select()
    if kev is not None:
        query = query.where(vulnerabilities.c.kev == kev)
    if min_epss is not None:
        query = query.where(vulnerabilities.c.epss_score >= min_epss)
    if max_epss is not None:
        query = query.where(vulnerabilities.c.epss_score <= max_epss)
    if min_cvss is not None:
        query = query.where(vulnerabilities.c.cvss_v3_score >= min_cvss)
    if max_cvss is not None:
        query = query.where(vulnerabilities.c.cvss_v3_score <= max_cvss)
    if cwe_id is not None:
        query = query.where(vulnerabilities.c.cwe_id == cwe_id)
    query = query.limit(limit).offset(offset)
    rows = await database.fetch_all(query)
    # Ensure ids are strings
    result = []
    for row in rows:
        row = dict(row)
        if row['id'] is not None:
            row['id'] = str(row['id'])
        result.append(row)
    return result


# Asset operations
async def get_asset(asset_id: uuid.UUID) -> Optional[dict]:
    query = assets.select().where(assets.c.id == asset_id)
    result = await database.fetch_one(query)
    if result:
        result = dict(result)
        # Ensure the id is a string
        if result['id'] is not None:
            result['id'] = str(result['id'])
    return result


async def create_asset(asset_data: dict) -> uuid.UUID:
    # Ensure we have an ID for the asset
    if 'id' not in asset_data:
        asset_data['id'] = str(uuid.uuid4())
    query = assets.insert().values(**asset_data)
    await database.execute(query)
    return uuid.UUID(asset_data['id'])


async def list_assets(
    asset_type: Optional[str] = None,
    internet_exposure: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[dict]:
    query = assets.select()
    if asset_type is not None:
        query = query.where(assets.c.asset_type == asset_type)
    if internet_exposure is not None:
        query = query.where(assets.c.internet_exposure == internet_exposure)
    query = query.limit(limit).offset(offset)
    rows = await database.fetch_all(query)
    # Ensure ids are strings
    result = []
    for row in rows:
        row = dict(row)
        if row['id'] is not None:
            row['id'] = str(row['id'])
        result.append(row)
    return result


# Asset-Vulnerability operations
async def get_asset_vulnerability(asset_id: uuid.UUID, vulnerability_id: uuid.UUID) -> Optional[dict]:
    query = asset_vulnerabilities.select().where(
        (asset_vulnerabilities.c.asset_id == asset_id) &
        (asset_vulnerabilities.c.vulnerability_id == vulnerability_id)
    )
    result = await database.fetch_one(query)
    if result:
        result = dict(result)
        # Ensure the id is a string
        if result['id'] is not None:
            result['id'] = str(result['id'])
    return result


async def create_asset_vulnerability(av_data: dict) -> uuid.UUID:
    # Ensure we have an ID for the asset-vulnerability link
    if 'id' not in av_data:
        av_data['id'] = str(uuid.uuid4())
    query = asset_vulnerabilities.insert().values(**av_data)
    await database.execute(query)
    return uuid.UUID(av_data['id'])


async def update_asset_vulnerability(
    av_id: uuid.UUID,
    update_data: dict,
) -> None:
    query = asset_vulnerabilities.update().where(asset_vulnerabilities.c.id == av_id).values(**update_data)
    await database.execute(query)


async def list_asset_vulnerabilities(
    asset_id: Optional[uuid.UUID] = None,
    vulnerability_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[dict]:
    query = asset_vulnerabilities.select()
    if asset_id is not None:
        query = query.where(asset_vulnerabilities.c.asset_id == asset_id)
    if vulnerability_id is not None:
        query = query.where(asset_vulnerabilities.c.vulnerability_id == vulnerability_id)
    if status is not None:
        query = query.where(asset_vulnerabilities.c.status == status)
    query = query.limit(limit).offset(offset)
    rows = await database.fetch_all(query)
    # Ensure ids are strings
    result = []
    for row in rows:
        row = dict(row)
        if row['id'] is not None:
            row['id'] = str(row['id'])
        result.append(row)
    return result


# Risk score operations
async def get_risk_score_by_asset_vulnerability(av_id: uuid.UUID) -> Optional[dict]:
    query = risk_scores.select().where(risk_scores.c.asset_vulnerability_id == av_id)
    result = await database.fetch_one(query)
    if result:
        result = dict(result)
        # Ensure the id is a string
        if result['id'] is not None:
            result['id'] = str(result['id'])
    return result


async def create_risk_score(risk_data: dict) -> uuid.UUID:
    # Ensure we have an ID for the risk score
    if 'id' not in risk_data:
        risk_data['id'] = str(uuid.uuid4())
    query = risk_scores.insert().values(**risk_data)
    await database.execute(query)
    return uuid.UUID(risk_data['id'])


async def update_risk_score(
    risk_id: uuid.UUID,
    update_data: dict,
) -> None:
    query = risk_scores.update().where(risk_scores.c.id == risk_id).values(**update_data)
    await database.execute(query)


async def list_risk_scores(
    priority_tier: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[dict]:
    query = risk_scores.select()
    if priority_tier is not None:
        query = query.where(risk_scores.c.priority_tier == priority_tier)
    query = query.limit(limit).offset(offset)
    rows = await database.fetch_all(query)
    # Ensure ids are strings
    result = []
    for row in rows:
        row = dict(row)
        if row['id'] is not None:
            row['id'] = str(row['id'])
        result.append(row)
    return result


# Threat intelligence operations
async def create_threat_intelligence(ti_data: dict) -> uuid.UUID:
    # Ensure we have an ID for the threat intelligence record
    if 'id' not in ti_data:
        ti_data['id'] = str(uuid.uuid4())
    query = threat_intelligence.insert().values(**ti_data)
    await database.execute(query)
    return uuid.UUID(ti_data['id'])


async def get_threat_intelligence_by_vulnerability(vulnerability_id: uuid.UUID) -> List[dict]:
    query = threat_intelligence.select().where(threat_intelligence.c.vulnerability_id == vulnerability_id)
    rows = await database.fetch_all(query)
    # Ensure ids are strings
    result = []
    for row in rows:
        row = dict(row)
        if row['id'] is not None:
            row['id'] = str(row['id'])
        result.append(row)
    return result