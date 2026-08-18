import uuid
from app.db import database, vulnerabilities
from app.repository import create_vulnerability

# Test data
vulnerability_data = {
    "cve_id": "CVE-2023-12345",
    "cvss_v3_score": 7.5,
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.65,
    "kev": False,
    "cwe_id": "CWE-79",
    "description": "Test vulnerability",
    "exploit_available": False,
    "published_date": "2023-01-01T00:00:00Z",
    "modified_date": "2023-01-01T00:00:00Z"
}

print("Input data:", vulnerability_data)
print("Input data has id?", 'id' in vulnerability_data)

# Call the function
# We need to run it in an async context
import asyncio

async def test():
    try:
        vuln_id = await create_vulnerability(vulnerability_data)
        print("Created vuln_id:", vuln_id)
        print("Type of vuln_id:", type(vuln_id))
    except Exception as e:
        print("Error:", e)
        import traceback
        traceback.print_exc()

asyncio.run(test())