"""
Data ingestion script for NVD, EPSS, and KEV data.
Fetches vulnerability data and updates the PostgreSQL database.
"""
import os
import json
import logging
import time
from datetime import datetime, timedelta
import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/riskcompass"
)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# API endpoints
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/kev/known_exploited_vulnerabilities.json"

# Rate limiting
NVD_RATE_LIMIT = 0.6  # seconds between requests (NVD allows 5 requests per 30 seconds)
EPSS_RATE_LIMIT = 0.1  # be gentle with EPSS API

def fetch_kev_set() -> set:
    """Fetch the KEV catalog and return a set of CVE IDs."""
    logger.info("Fetching KEV catalog from CISA...")
    try:
        response = httpx.get(KEV_JSON_URL, timeout=30.0)
        response.raise_for_status()
        data = response.json()
        kev_set = {item['cveID'] for item in data.get('vulnerabilities', [])}
        logger.info(f"Fetched {len(kev_set)} KEV entries")
        return kev_set
    except Exception as e:
        logger.error(f"Failed to fetch KEV catalog: {e}")
        return set()

def fetch_epss_score(cve_id: str) -> float:
    """Fetch EPSS score for a given CVE ID."""
    try:
        params = {'cve': cve_id}
        response = httpx.get(EPSS_API_BASE, params=params, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        if data.get('data'):
            return float(data['data'][0]['epss'])
        else:
            logger.warning(f"No EPSS data found for {cve_id}")
            return 0.0
    except Exception as e:
        logger.warning(f"Failed to fetch EPSS for {cve_id}: {e}")
        return 0.0

def fetch_nvd_cves(last_days: int = 30) -> list:
    """Fetch CVE IDs modified in the last N days from NVD."""
    # Calculate date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=last_days)
    
    # Format for NVD API (ISO 8601)
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
    
    params = {
        'lastModStartDate': start_str,
        'lastModEndDate': end_str,
        'resultsPerPage': 2000,  # Max allowed by NVD API
        'startIndex': 0
    }
    
    logger.info(f"Fetching CVEs modified between {start_str} and {end_str}")
    all_cves = []
    
    while True:
        try:
            response = httpx.get(NVD_API_BASE, params=params, timeout=30.0)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                break
                
            all_cves.extend(vulnerabilities)
            
            # Check for pagination
            total_results = data.get('totalResults', 0)
            if len(all_cves) >= total_results:
                break
                
            params['startIndex'] += len(vulnerabilities)
            time.sleep(NVD_RATE_LIMIT)  # Rate limiting
            
        except Exception as e:
            logger.error(f"Error fetching from NVD: {e}")
            break
    
    logger.info(f"Fetched {len(all_cves)} CVE records from NVD")
    return all_cves

def parse_nvd_cve(nvd_item: dict) -> dict:
    """Parse NVD CVE item into a dictionary of fields."""
    cve = nvd_item.get('cve', {})
    cve_id = cve.get('id')
    
    # Extract CVSS v3.1 score
    cvss_v3_score = None
    cvss_v3_vector = None
    metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics:
        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
        cvss_v3_score = cvss_data.get('baseScore')
        cvss_v3_vector = cvss_data.get('vectorString')
    elif 'cvssMetricV30' in metrics:
        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
        cvss_v3_score = cvss_data.get('baseScore')
        cvss_v3_vector = cvss_data.get('vectorString')
    
    # Extract CVSS v4.0 if available
    cvss_v4_score = None
    cvss_v4_vector = None
    if 'cvssMetricV40' in metrics:
        cvss_data = metrics['cvssMetricV40'][0].get('cvssData', {})
        cvss_v4_score = cvss_data.get('baseScore')
        cvss_v4_vector = cvss_data.get('vectorString')
    
    # Extract description (English)
    description = ""
    for desc in cve.get('descriptions', []):
        if desc.get('lang') == 'en':
            description = desc.get('value', '')
            break
    
    # Extract CWE
    cwe_id = None
    weaknesses = cve.get('weaknesses', [])
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en':
                value = desc.get('value')
                if value and value.startswith('CWE-'):
                    cwe_id = value
                    break
        if cwe_id:
            break
    
    # Extract references (simplified as JSONB)
    references = []
    for ref in cve.get('references', []):
        references.append({
            'url': ref.get('url'),
            'source': ref.get('source'),
            'tags': ref.get('tags', [])
        })
    
    # Extract dates
    published_date = cve.get('published')
    modified_date = cve.get('lastModified')
    
    return {
        'cve_id': cve_id,
        'cvss_v3_score': cvss_v3_score,
        'cvss_v3_vector': cvss_v3_vector,
        'cvss_v4_score': cvss_v4_score,
        'cvss_v4_vector': cvss_v4_vector,
        'cwe_id': cwe_id,
        'description': description,
        'references': json.dumps(references) if references else None,
        'published_date': published_date,
        'modified_date': modified_date
    }

def upsert_vulnerability(session, cve_data: dict, epss_score: float, kev: bool):
    """Insert or update a vulnerability record."""
    # Check if CVE exists
    existing = session.execute(
        text("SELECT id FROM vulnerabilities WHERE cve_id = :cve_id"),
        {'cve_id': cve_data['cve_id']}
    ).fetchone()
    
    if existing:
        # Update
        update_sql = """
            UPDATE vulnerabilities SET
                cvss_v3_score = :cvss_v3_score,
                cvss_v3_vector = :cvss_v3_vector,
                cvss_v4_score = :cvss_v4_score,
                cvss_v4_vector = :cvss_v4_vector,
                epss_score = :epss_score,
                epss_percentile = :epss_percentile,
                kev = :kev,
                kev_date = CASE WHEN :kev AND kev_date IS NULL THEN NOW() ELSE kev_date END,
                cwe_id = :cwe_id,
                description = :description,
                references = :references,
                published_date = :published_date,
                modified_date = :modified_date,
                updated_at = NOW()
            WHERE cve_id = :cve_id
        """
        # Note: EPSS percentile not fetched here; would need separate EPSS API call for percentile
        # We'll set it to 0 for now and note it can be updated later
        session.execute(text(update_sql), {
            'cvss_v3_score': cve_data['cvss_v3_score'],
            'cvss_v3_vector': cve_data['cvss_v3_vector'],
            'cvss_v4_score': cve_data['cvss_v4_score'],
            'cvss_v4_vector': cve_data['cvss_v4_vector'],
            'epss_score': epss_score,
            'epss_percentile': 0.0,  # Placeholder
            'kev': kev,
            'cwe_id': cve_data['cwe_id'],
            'description': cve_data['description'],
            'references': cve_data['references'],
            'published_date': cve_data['published_date'],
            'modified_date': cve_data['modified_date'],
            'cve_id': cve_data['cve_id']
        })
        logger.debug(f"Updated vulnerability {cve_data['cve_id']}")
    else:
        # Insert
        insert_sql = """
            INSERT INTO vulnerabilities (
                cve_id, cvss_v3_score, cvss_v3_vector, cvss_v4_score, cvss_v4_vector,
                epss_score, epss_percentile, kev, kev_date, cwe_id, description,
                references, published_date, modified_date
            ) VALUES (
                :cve_id, :cvss_v3_score, :cvss_v3_vector, :cvss_v4_score, :cvss_v4_vector,
                :epss_score, :epss_percentile, :kev, 
                CASE WHEN :kev THEN NOW() ELSE NULL END,
                :cwe_id, :description, :references, :published_date, :modified_date
            )
        """
        session.execute(text(insert_sql), {
            'cve_id': cve_data['cve_id'],
            'cvss_v3_score': cve_data['cvss_v3_score'],
            'cvss_v3_vector': cve_data['cvss_v3_vector'],
            'cvss_v4_score': cve_data['cvss_v4_score'],
            'cvss_v4_vector': cve_data['cvss_v4_vector'],
            'epss_score': epss_score,
            'epss_percentile': 0.0,  # Placeholder
            'kev': kev,
            'cwe_id': cve_data['cwe_id'],
            'description': cve_data['description'],
            'references': cve_data['references'],
            'published_date': cve_data['published_date'],
            'modified_date': cve_data['modified_date']
        })
        logger.debug(f"Inserted vulnerability {cve_data['cve_id']}")

def main():
    """Main ingestion routine."""
    logger.info("Starting data ingestion process...")
    
    # Fetch KEV set once
    kev_set = fetch_kev_set()
    
    # Fetch CVE records from NVD
    nvd_items = fetch_nvd_cves(last_days=30)
    
    # Process each CVE
    session = SessionLocal()
    try:
        processed = 0
        for i, nvd_item in enumerate(nvd_items):
            try:
                # Parse NVD data
                cve_data = parse_nvd_cve(nvd_item)
                cve_id = cve_data['cve_id']
                
                if not cve_id:
                    logger.warning("Skipping item with no CVE ID")
                    continue
                
                # Fetch EPSS score
                epss_score = fetch_epss_score(cve_id)
                time.sleep(EPSS_RATE_LIMIT)  # Rate limiting for EPSS
                
                # Check KEV
                kev = cve_id in kev_set
                
                # Upsert to database
                upsert_vulnerability(session, cve_data, epss_score, kev)
                
                processed += 1
                if processed % 50 == 0:
                    session.commit()
                    logger.info(f"Processed {processed} CVEs...")
                    
            except Exception as e:
                logger.error(f"Error processing CVE {nvd_item.get('cve', {}).get('id', 'unknown')}: {e}")
                continue
        
        # Final commit
        session.commit()
        logger.info(f"Ingestion complete. Processed {processed} CVEs.")
        
    except Exception as e:
        logger.error(f"Error in main ingestion loop: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    main()