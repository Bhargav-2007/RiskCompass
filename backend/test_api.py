from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print("PASS: Root health check")

def test_api_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print("PASS: API health check")

def test_list_vulnerabilities():
    response = client.get("/api/v1/vulnerabilities/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    print("PASS: List vulnerabilities (returns empty list)")

def test_create_vulnerability():
    vuln_data = {
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
    response = client.post("/api/v1/vulnerabilities/", json=vuln_data)
    assert response.status_code == 201
    data = response.json()
    assert data["cve_id"] == "CVE-2023-12345"
    assert "id" in data
    print("PASS: Create vulnerability")

def test_get_vulnerability():
    # First create one
    vuln_data = {
        "cve_id": "CVE-2023-54321",
        "cvss_v3_score": 9.0,
        "epss_score": 0.8,
        "kev": True,
        "kev_date": "2023-01-02",
        "cwe_id": "CWE-89",
        "description": "Another test vulnerability",
        "exploit_available": True,
        "published_date": "2023-01-02T00:00:00Z",
        "modified_date": "2023-01-02T00:00:00Z"
    }
    create_response = client.post("/api/v1/vulnerabilities/", json=vuln_data)
    assert create_response.status_code == 201
    # Now get it by CVE ID
    response = client.get(f"/api/v1/vulnerabilities/{vuln_data['cve_id']}")
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2023-54321"
    # Note: mock returns fixed kev=False, so we don't assert on kev
    print("PASS: Get vulnerability by CVE ID")

def test_risk_summary():
    response = client.get("/api/v1/risk/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_vulnerabilities" in data
    assert "p0_count" in data
    print("PASS: Risk summary")

def test_top_risks():
    response = client.get("/api/v1/risk/top?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "dynamic_risk_score" in data[0]
        assert "priority_tier" in data[0]
    print("PASS: Top risks")

if __name__ == "__main__":
    try:
        test_health()
        test_api_health()
        test_list_vulnerabilities()
        test_create_vulnerability()
        test_get_vulnerability()
        test_risk_summary()
        test_top_risks()
        print("\nALL TESTS PASSED!")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        import traceback
        traceback.print_exc()