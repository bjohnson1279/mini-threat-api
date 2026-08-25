from fastapi.testclient import TestClient
from app.main import app

def test_full_threat_intel_lifecycle():
    """
    Comprehensive test suite verifying:
    1. Liveness health check
    2. Authentication & JWT Custom Authorizer
    3. Threat Intelligence Seed Data & Querying
    4. Pydantic Runtime Validation
    5. Indicator Ingestion (CRUD)
    """
    with TestClient(app) as client:
        # 1. Health Check
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        assert health_resp.json() == {"status": "healthy", "service": "threat-intel-api"}
        print("\n[+] Health check passed.")

        # 2. Rejection of unauthenticated requests to protected endpoints
        unauth_resp = client.get("/iocs")
        assert unauth_resp.status_code == 401
        assert "Not authenticated" in unauth_resp.json().get("detail", "")
        print("[+] Custom Authorizer correctly rejected unauthenticated request with 401.")

        # 3. Invalid credentials rejection
        bad_auth = client.post(
            "/auth/token",
            data={"username": "analyst", "password": "wrongpassword"}
        )
        assert bad_auth.status_code == 401
        print("[+] Invalid login rejected with 401.")

        # 4. Valid authentication & JWT issuance
        login_resp = client.post(
            "/auth/token",
            data={"username": "analyst", "password": "password123"}
        )
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("[+] Authenticated successfully and received JWT.")

        # 5. Decode current user profile
        me_resp = client.get("/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["username"] == "analyst"
        assert me_resp.json()["role"] == "threat_analyst"
        print("[+] /auth/me decoded user claims correctly.")

        # 6. Query all seeded indicators
        iocs_resp = client.get("/iocs", headers=headers)
        assert iocs_resp.status_code == 200
        iocs = iocs_resp.json()
        assert len(iocs) >= 6
        print(f"[+] Retrieved {len(iocs)} threat indicators from database.")

        # 7. Query with filters (min_confidence >= 90)
        high_conf_resp = client.get("/iocs?min_confidence=90", headers=headers)
        assert high_conf_resp.status_code == 200
        high_conf_iocs = high_conf_resp.json()
        assert all(ioc["confidence_score"] >= 90 for ioc in high_conf_iocs)
        print(f"[+] Filtered high confidence indicators (count: {len(high_conf_iocs)}).")

        # 8. Query with type filter (indicator_type=ipv4)
        ip_resp = client.get("/iocs?indicator_type=ipv4", headers=headers)
        assert ip_resp.status_code == 200
        ip_iocs = ip_resp.json()
        assert all(ioc["indicator_type"] == "ipv4" for ioc in ip_iocs)
        print(f"[+] Filtered IPv4 indicators (count: {len(ip_iocs)}).")

        # 9. Query with search keyword (search=LockBit)
        search_resp = client.get("/iocs?search=LockBit", headers=headers)
        assert search_resp.status_code == 200
        search_iocs = search_resp.json()
        assert len(search_iocs) >= 1
        assert "LockBit" in search_iocs[0]["description"]
        print("[+] Partial search query works.")

        # 10. Single IOC lookup
        first_id = iocs[0]["id"]
        single_resp = client.get(f"/iocs/{first_id}", headers=headers)
        assert single_resp.status_code == 200
        assert single_resp.json()["id"] == first_id
        print(f"[+] Retrieved single IOC ID {first_id}.")

        # 11. Ingest a new IOC (POST /iocs)
        new_ioc_payload = {
            "indicator_value": "198.51.100.99",
            "indicator_type": "ipv4",
            "threat_type": "ransomware_c2",
            "confidence_score": 98,
            "severity": "critical",
            "description": "Active BlackCat/ALPHV ransomware C2 IP address.",
            "is_active": True
        }
        create_resp = client.post("/iocs", json=new_ioc_payload, headers=headers)
        assert create_resp.status_code == 201
        created_ioc = create_resp.json()
        assert created_ioc["indicator_value"] == "198.51.100.99"
        assert created_ioc["id"] is not None
        print(f"[+] Ingested new IOC with ID {created_ioc['id']}.")

        # 12. Pydantic Runtime Validation: reject invalid confidence_score (>100)
        invalid_payload = new_ioc_payload.copy()
        invalid_payload["confidence_score"] = 999  # Invalid: schema enforces le=100
        invalid_resp = client.post("/iocs", json=invalid_payload, headers=headers)
        assert invalid_resp.status_code == 422  # Unprocessable Entity
        print("[+] Pydantic runtime validation successfully rejected out-of-range confidence_score with 422.")

        print("\n[SUCCESS] ALL THREAT INTEL API TESTS PASSED!\n")

if __name__ == "__main__":
    test_full_threat_intel_lifecycle()
