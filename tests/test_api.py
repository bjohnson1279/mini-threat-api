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

        # Verify security headers
        assert health_resp.headers.get("Permissions-Policy") == "geolocation=(), camera=(), microphone=()"
        assert health_resp.headers.get("Content-Security-Policy") == "object-src 'none'; base-uri 'none';"
        print("\n[+] Health check and security headers verification passed.")

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

        # 13. Pydantic Runtime Validation: reject excessive string lengths (DoS/DB error prevention)
        long_payload = new_ioc_payload.copy()
        long_payload["indicator_value"] = "A" * 256  # Invalid: schema enforces max_length=255
        long_resp = client.post("/iocs", json=long_payload, headers=headers)
        assert long_resp.status_code == 422

        long_payload2 = new_ioc_payload.copy()
        long_payload2["threat_type"] = "B" * 101 # Invalid: schema enforces max_length=100
        long_resp2 = client.post("/iocs", json=long_payload2, headers=headers)
        assert long_resp2.status_code == 422

        long_payload3 = new_ioc_payload.copy()
        long_payload3["description"] = "C" * 501 # Invalid: schema enforces max_length=500
        long_resp3 = client.post("/iocs", json=long_payload3, headers=headers)
        assert long_resp3.status_code == 422
        print("[+] Pydantic runtime validation successfully rejected excessive string lengths with 422.")

        # 13.5 Pydantic Runtime Validation: reject malformed data injection
        malformed_payload = new_ioc_payload.copy()
        malformed_payload["indicator_value"] = "Not an IP Address"
        malformed_payload["indicator_type"] = "ipv4"
        malformed_resp = client.post("/iocs", json=malformed_payload, headers=headers)
        assert malformed_resp.status_code == 422
        assert "Invalid IPv4 address format" in str(malformed_resp.json())
        print("[+] Pydantic runtime validation successfully rejected malformed ipv4 value with 422.")

        # 13.6 Pydantic Runtime Validation: reject newline injection in SHA256
        newline_payload = new_ioc_payload.copy()
        newline_payload["indicator_type"] = "sha256"
        # 64-char hex followed by a newline, which passes if regex is `$` instead of `\Z`
        newline_payload["indicator_value"] = "a" * 64 + "\n"
        newline_resp = client.post("/iocs", json=newline_payload, headers=headers)
        assert newline_resp.status_code == 422
        assert "Invalid SHA256 hash format" in str(newline_resp.json())
        print("[+] Pydantic runtime validation successfully rejected newline in SHA256 hash with 422.")

        # 13.7 Pydantic Runtime Validation: reject XSS and CRLF in URL
        xss_payload = new_ioc_payload.copy()
        xss_payload["indicator_type"] = "url"
        xss_payload["indicator_value"] = "http://example.com/<script>alert(1)</script>"
        xss_resp = client.post("/iocs", json=xss_payload, headers=headers)
        assert xss_resp.status_code == 422

        crlf_payload = new_ioc_payload.copy()
        crlf_payload["indicator_type"] = "url"
        crlf_payload["indicator_value"] = "http://example.com\n"
        crlf_resp = client.post("/iocs", json=crlf_payload, headers=headers)
        assert crlf_resp.status_code == 422
        print("[+] Pydantic runtime validation successfully rejected XSS/CRLF in URL with 422.")

        # 13.8 Reject excessively long credentials on authentication endpoint
        long_auth = client.post(
            "/auth/token",
            data={"username": "A" * 256, "password": "password123"}
        )
        assert long_auth.status_code == 400
        assert "payload too large" in str(long_auth.json())
        print("[+] OAuth2 form length validation successfully rejected excessive inputs with 400.")

        # 14. Ensure RBAC authorization is enforced on POST /iocs
        # Login as a guest (does not have "threat_analyst" or "admin" role)
        guest_login = client.post(
            "/auth/token",
            data={"username": "guest", "password": "password123"}  # password for dummy hash is 'password123'
        )
        assert guest_login.status_code == 200
        guest_token = guest_login.json()["access_token"]
        guest_headers = {"Authorization": f"Bearer {guest_token}"}

        # Attempt to create IOC as guest
        guest_create_resp = client.post("/iocs", json=new_ioc_payload, headers=guest_headers)
        assert guest_create_resp.status_code == 403
        assert "Operation not permitted" in guest_create_resp.json().get("detail", "")
        print("[+] RBAC authorization correctly prevented unauthorized IOC creation with 403.")

        # 15. Verify brute force rate limiting
        for _ in range(5):
            res = client.post(
                "/auth/token",
                data={"username": "analyst", "password": "wrongpassword_rate_limit"}
            )
            assert res.status_code in [200, 401, 429]

        rl_res = client.post(
            "/auth/token",
            data={"username": "analyst", "password": "wrongpassword_rate_limit"}
        )
        assert rl_res.status_code == 429
        print("[+] Login endpoint rate limiting DoS protection works.")

        # 16. Verify JWT claim enforcement (require_exp)
        from jose import jwt
        from app.config import settings
        token_no_exp = jwt.encode(
            {"sub": "analyst", "role": "threat_analyst"},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        malicious_headers = {"Authorization": f"Bearer {token_no_exp}"}
        no_exp_resp = client.get("/auth/me", headers=malicious_headers)
        assert no_exp_resp.status_code == 401
        assert "Could not validate credentials or token expired" in no_exp_resp.json().get("detail", "")
        print("[+] Successfully rejected JWT token missing 'exp' claim with 401.")
        # 17. Verify JWT contains iat, nbf, and jti claims
        decoded_token = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        assert "iat" in decoded_token
        assert "nbf" in decoded_token
        assert "jti" in decoded_token
        print("[+] JWT correctly includes iat, nbf, and jti claims.")

        print("\n[SUCCESS] ALL THREAT INTEL API TESTS PASSED!\n")


def test_pydantic_schema_validation_and_sanitization():
    """
    Unit test suite targeting Pydantic schema validation and HTML input sanitization:
    - Domain indicator format validation
    - Email indicator format validation
    - HTML input sanitization (XSS escaping in threat_type and description)
    """
    from app.main import LOGIN_ATTEMPTS, LOGIN_ATTEMPTS_LOCK
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.clear()

    with TestClient(app) as client:
        # Get auth token as threat analyst
        login_resp = client.post(
            "/auth/token",
            data={"username": "analyst", "password": "password123"}
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Reject invalid domain format
        invalid_domain_payload = {
            "indicator_value": "not_a_valid_domain",
            "indicator_type": "domain",
            "threat_type": "phishing",
            "confidence_score": 75,
            "severity": "high"
        }
        resp = client.post("/iocs", json=invalid_domain_payload, headers=headers)
        assert resp.status_code == 422
        assert "Invalid domain format" in str(resp.json())

        # 2. Reject invalid email format
        invalid_email_payload = {
            "indicator_value": "not_an_email_address",
            "indicator_type": "email",
            "threat_type": "phishing",
            "confidence_score": 80,
            "severity": "medium"
        }
        resp = client.post("/iocs", json=invalid_email_payload, headers=headers)
        assert resp.status_code == 422
        assert "Invalid email format" in str(resp.json())

        # 3. Accept valid domain indicator
        valid_domain_payload = {
            "indicator_value": "malicious-c2.example.com",
            "indicator_type": "domain",
            "threat_type": "c2",
            "confidence_score": 90,
            "severity": "critical"
        }
        resp = client.post("/iocs", json=valid_domain_payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["indicator_value"] == "malicious-c2.example.com"

        # 4. Accept valid email indicator
        valid_email_payload = {
            "indicator_value": "phisher@bad-actor.org",
            "indicator_type": "email",
            "threat_type": "spear_phishing",
            "confidence_score": 85,
            "severity": "high"
        }
        resp = client.post("/iocs", json=valid_email_payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["indicator_value"] == "phisher@bad-actor.org"

        # 5. HTML Input Sanitization (XSS prevention)
        xss_sanitization_payload = {
            "indicator_value": "198.51.100.123",
            "indicator_type": "ipv4",
            "threat_type": "<script>alert('xss')</script>c2",
            "description": "<img src=x onerror=alert(1)>Malicious node",
            "confidence_score": 70,
            "severity": "medium"
        }
        resp = client.post("/iocs", json=xss_sanitization_payload, headers=headers)
        assert resp.status_code == 201
        data = resp.json()
        assert "<script>" not in data["threat_type"]
        assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;c2" == data["threat_type"]
        assert "<img" not in data["description"]
        assert "&lt;img src=x onerror=alert(1)&gt;Malicious node" == data["description"]


def test_jwt_security_and_rbac_authorization():
    """
    Unit test suite targeting JWT decoding edge cases and RBAC authorization:
    - JWT token missing 'sub' claim rejection
    - JWT token with invalid signature rejection
    - Disabled user authentication rejection
    - Admin role permission grant for `require_role("threat_analyst")`
    """
    from jose import jwt
    from app.config import settings
    from app.main import LOGIN_ATTEMPTS, LOGIN_ATTEMPTS_LOCK

    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.clear()

    with TestClient(app) as client:
        # 1. JWT token missing 'sub' claim
        token_no_sub = jwt.encode(
            {"role": "threat_analyst", "exp": 9999999999},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token_no_sub}"})
        assert resp.status_code == 401
        assert "Could not validate credentials" in resp.json()["detail"] or "missing subject" in resp.json()["detail"]

        # 2. JWT token with invalid secret / signature
        bad_sig_token = jwt.encode(
            {"sub": "analyst", "role": "threat_analyst", "exp": 9999999999},
            "wrong_secret_key_12345",
            algorithm=settings.JWT_ALGORITHM
        )
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {bad_sig_token}"})
        assert resp.status_code == 401

        # 3. Disabled user authentication rejection
        from app.auth import MOCK_USERS_DB
        MOCK_USERS_DB["disabled_user"] = {
            "username": "disabled_user",
            "password": "$2b$12$v1B3NFjxLnulAxo8hmmE8.wX7DP7pExSaVPCDr74ERGYQm3lkjqc6",
            "role": "threat_analyst",
            "disabled": True
        }
        disabled_login = client.post(
            "/auth/token",
            data={"username": "disabled_user", "password": "password123"}
        )
        assert disabled_login.status_code == 401

        # Also test JWT token for a user that was disabled after token issuance
        disabled_jwt = jwt.encode(
            {"sub": "disabled_user", "role": "threat_analyst", "exp": 9999999999},
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        disabled_jwt_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {disabled_jwt}"})
        assert disabled_jwt_resp.status_code == 400
        assert "Inactive user" in disabled_jwt_resp.json()["detail"]

        # Cleanup mock user
        del MOCK_USERS_DB["disabled_user"]

        # 4. Admin role permission grant in require_role
        admin_login = client.post(
            "/auth/token",
            data={"username": "admin", "password": "adminpassword123"}
        )
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        admin_ioc_payload = {
            "indicator_value": "198.51.100.200",
            "indicator_type": "ipv4",
            "threat_type": "admin_created_c2",
            "confidence_score": 100,
            "severity": "critical"
        }
        admin_create_resp = client.post("/iocs", json=admin_ioc_payload, headers=admin_headers)
        assert admin_create_resp.status_code == 201
        assert admin_create_resp.json()["indicator_value"] == "198.51.100.200"


def test_ioc_query_and_lookup_boundary_conditions():
    """
    Integration test suite targeting IOC querying and lookup boundary conditions:
    - 404 response for non-existent IOC ID lookup
    - 422 Unprocessable Entity for out-of-range path or query parameters (e.g. ioc_id <= 0, offset < 0)
    - SQL wildcard character escaping (`%` and `_`) in search queries
    - Pagination offset and limit edge cases
    """
    from app.main import LOGIN_ATTEMPTS, LOGIN_ATTEMPTS_LOCK

    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.clear()

    with TestClient(app) as client:
        # Get auth token as threat analyst
        login_resp = client.post(
            "/auth/token",
            data={"username": "analyst", "password": "password123"}
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Non-existent IOC ID (404)
        non_existent_resp = client.get("/iocs/9999999", headers=headers)
        assert non_existent_resp.status_code == 404
        assert "Threat indicator with ID 9999999 not found" in non_existent_resp.json()["detail"]

        # 2. Invalid IOC ID boundary (ge=1 enforcement -> 422)
        invalid_id_resp = client.get("/iocs/0", headers=headers)
        assert invalid_id_resp.status_code == 422

        invalid_neg_id_resp = client.get("/iocs/-5", headers=headers)
        assert invalid_neg_id_resp.status_code == 422

        # 3. Invalid offset query parameter boundary (ge=0 enforcement -> 422)
        invalid_offset_resp = client.get("/iocs?offset=-1", headers=headers)
        assert invalid_offset_resp.status_code == 422

        # 4. SQL wildcard character escaping test (% and _)
        # Seed an IOC containing literal '%' and '_' in description
        wildcard_payload = {
            "indicator_value": "198.51.100.150",
            "indicator_type": "ipv4",
            "threat_type": "wildcard_test",
            "confidence_score": 88,
            "severity": "high",
            "description": "Special_pattern_100%_malicious"
        }
        create_resp = client.post("/iocs", json=wildcard_payload, headers=headers)
        assert create_resp.status_code == 201

        # Query searching literal '%'
        percent_search = client.get("/iocs?search=100%", headers=headers)
        assert percent_search.status_code == 200
        results = percent_search.json()
        assert len(results) >= 1
        assert any(i["indicator_value"] == "198.51.100.150" for i in results)

        # Query searching literal '_'
        underscore_search = client.get("/iocs?search=Special_pattern", headers=headers)
        assert underscore_search.status_code == 200
        results_underscore = underscore_search.json()
        assert len(results_underscore) >= 1
        assert any(i["indicator_value"] == "198.51.100.150" for i in results_underscore)

        # 5. Pagination offset & limit edge case
        all_iocs_resp = client.get("/iocs?limit=500", headers=headers)
        assert all_iocs_resp.status_code == 200
        total_iocs = len(all_iocs_resp.json())

        # Offset equal to total count should return empty list
        offset_beyond_resp = client.get(f"/iocs?offset={total_iocs}", headers=headers)
        assert offset_beyond_resp.status_code == 200
        assert offset_beyond_resp.json() == []

        # Partial page with limit=2 and offset=1
        page_resp = client.get("/iocs?limit=2&offset=1", headers=headers)
        assert page_resp.status_code == 200
        page_data = page_resp.json()
        assert len(page_data) == 2
        assert page_data[0] == all_iocs_resp.json()[1]


if __name__ == "__main__":
    test_full_threat_intel_lifecycle()
    test_pydantic_schema_validation_and_sanitization()
    test_jwt_security_and_rbac_authorization()
    test_ioc_query_and_lookup_boundary_conditions()
