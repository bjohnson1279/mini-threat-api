import time
import pytest
from jose import jwt
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app, LOGIN_ATTEMPTS, LOGIN_ATTEMPTS_LOCK
from app.database import get_db
from app.config import settings
from app.schemas import IOCCreate
from app.auth import create_access_token, MOCK_USERS_DB


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear rate limiting dictionary between test cases to ensure test isolation and determinism."""
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.clear()
    yield
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.clear()


# ---------------------------------------------------------------------------
# Unit Tests: Pydantic Schema Validation & Sanitization Edge Cases
# ---------------------------------------------------------------------------

class TestIOCValidationEdgeCases:
    """Test suite targeting boundary conditions and input validation in schemas."""

    def test_valid_domain_types(self):
        # Arrange & Act
        ioc = IOCCreate(
            indicator_value="malicious-subdomain.threat-domain.co.uk",
            indicator_type="domain",
            threat_type="phishing",
            confidence_score=75,
            severity="medium",
            description="Phishing host"
        )
        # Assert
        assert ioc.indicator_value == "malicious-subdomain.threat-domain.co.uk"
        assert ioc.indicator_type == "domain"

    def test_invalid_domain_format_rejected(self):
        # Arrange, Act & Assert: domain without valid TLD or with illegal characters
        with pytest.raises(ValidationError) as exc_info:
            IOCCreate(
                indicator_value="invalid_domain_without_tld",
                indicator_type="domain",
                threat_type="phishing"
            )
        assert "Invalid domain format" in str(exc_info.value)

    def test_valid_email_types(self):
        # Arrange & Act
        ioc = IOCCreate(
            indicator_value="attacker+target@malicious-domain.org",
            indicator_type="email",
            threat_type="spear_phishing",
            confidence_score=90,
            severity="high"
        )
        # Assert
        assert ioc.indicator_value == "attacker+target@malicious-domain.org"
        assert ioc.indicator_type == "email"

    def test_invalid_email_format_rejected(self):
        # Arrange, Act & Assert: invalid email formats
        with pytest.raises(ValidationError) as exc_info:
            IOCCreate(
                indicator_value="plainaddress_no_at",
                indicator_type="email",
                threat_type="phishing"
            )
        assert "Invalid email format" in str(exc_info.value)

    def test_invalid_sha256_format_rejected(self):
        # Arrange, Act & Assert: not 64 hex characters (short or contains non-hex)
        with pytest.raises(ValidationError) as exc_info:
            IOCCreate(
                indicator_value="0123456789abcdef",
                indicator_type="sha256",
                threat_type="malware"
            )
        assert "Invalid SHA256 hash format" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info2:
            IOCCreate(
                indicator_value="z" * 64,
                indicator_type="sha256",
                threat_type="malware"
            )
        assert "Invalid SHA256 hash format" in str(exc_info2.value)

    def test_invalid_url_format_rejected(self):
        # Arrange, Act & Assert: missing scheme or invalid chars
        with pytest.raises(ValidationError) as exc_info:
            IOCCreate(
                indicator_value="ftp://example.com/file.exe",
                indicator_type="url",
                threat_type="malware_download"
            )
        assert "Invalid URL format" in str(exc_info.value)

    def test_html_sanitization_in_threat_type_and_description(self):
        # Arrange: User input with HTML / script injection
        raw_threat_type = "<script>alert('xss')</script>c2"
        raw_description = "<b>Ransomware</b> note found at <img src=x onerror=alert(1)>"

        # Act
        ioc = IOCCreate(
            indicator_value="198.51.100.10",
            indicator_type="ipv4",
            threat_type=raw_threat_type,
            description=raw_description
        )

        # Assert: Dangerous characters escaped
        assert "<script>" not in ioc.threat_type
        assert "&lt;script&gt;" in ioc.threat_type
        assert "<img src=x" not in ioc.description
        assert "&lt;img src=x" in ioc.description

        # Non-string or None inputs handled cleanly
        assert IOCCreate.sanitize_html(None) is None
        assert IOCCreate.sanitize_html(123) == 123

    def test_confidence_score_boundaries(self):
        # Assert lower boundary 0 and upper boundary 100 succeed
        ioc_zero = IOCCreate(
            indicator_value="198.51.100.1",
            indicator_type="ipv4",
            threat_type="test",
            confidence_score=0
        )
        assert ioc_zero.confidence_score == 0

        ioc_hundred = IOCCreate(
            indicator_value="198.51.100.1",
            indicator_type="ipv4",
            threat_type="test",
            confidence_score=100
        )
        assert ioc_hundred.confidence_score == 100

        # Assert negative value fails
        with pytest.raises(ValidationError):
            IOCCreate(
                indicator_value="198.51.100.1",
                indicator_type="ipv4",
                threat_type="test",
                confidence_score=-1
            )


# ---------------------------------------------------------------------------
# Integration Tests: Auth, Token & Endpoint Edge Cases
# ---------------------------------------------------------------------------

class TestAuthAndTokensEdgeCases:
    """Test suite targeting auth failure modes, token decoding and edge cases."""

    def test_login_with_password_exceeding_72_bytes_handled_cleanly(self):
        # Arrange: password with >72 bytes (triggers bcrypt truncation logic in auth)
        with TestClient(app) as client:
            long_password = "P" * 100
            # Act
            response = client.post(
                "/auth/token",
                data={"username": "analyst", "password": long_password}
            )
            # Assert: rejected with 401 Unauthorized without crashing bcrypt
            assert response.status_code == 401
            assert response.json()["detail"] == "Incorrect username or password"

    def test_token_with_nonexistent_user_returns_401(self):
        # Arrange: Token validly signed, but user does not exist in DB
        with TestClient(app) as client:
            token = create_access_token(data={"sub": "ghost_user", "role": "threat_analyst"})
            headers = {"Authorization": f"Bearer {token}"}

            # Act
            response = client.get("/auth/me", headers=headers)

            # Assert
            assert response.status_code == 401
            assert response.json()["detail"] == "User not found"

    def test_token_with_missing_sub_claim_returns_401(self):
        # Arrange: create a token manually without 'sub' or None 'sub'
        with TestClient(app) as client:
            token = jwt.encode(
                {"role": "threat_analyst", "exp": 9999999999},
                settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM
            )
            headers = {"Authorization": f"Bearer {token}"}

            # Act
            response = client.get("/auth/me", headers=headers)

            # Assert
            assert response.status_code == 401

    def test_token_with_disabled_user_returns_400(self):
        # Arrange: temporarily add a disabled user to MOCK_USERS_DB
        MOCK_USERS_DB["inactive_user"] = {
            "username": "inactive_user",
            "password": "$2b$12$v1B3NFjxLnulAxo8hmmE8.wX7DP7pExSaVPCDr74ERGYQm3lkjqc6",
            "role": "threat_analyst",
            "disabled": True
        }
        try:
            with TestClient(app) as client:
                token = create_access_token(data={"sub": "inactive_user", "role": "threat_analyst"})
                headers = {"Authorization": f"Bearer {token}"}

                # Act
                response = client.get("/auth/me", headers=headers)

                # Assert
                assert response.status_code == 400
                assert response.json()["detail"] == "Inactive user"
        finally:
            MOCK_USERS_DB.pop("inactive_user", None)

    def test_malformed_jwt_token_returns_401(self):
        # Arrange
        with TestClient(app) as client:
            headers = {"Authorization": "Bearer not.a.valid.jwt.token"}

            # Act
            response = client.get("/auth/me", headers=headers)

            # Assert
            assert response.status_code == 401
            assert "Could not validate credentials or token expired" in response.json()["detail"]

    def test_expired_jwt_token_returns_401(self):
        # Arrange: create a token with expiration in the past
        with TestClient(app) as client:
            past_exp = int(time.time()) - 100
            expired_token = jwt.encode(
                {"sub": "analyst", "role": "threat_analyst", "exp": past_exp},
                settings.JWT_SECRET_KEY,
                algorithm=settings.JWT_ALGORITHM
            )
            headers = {"Authorization": f"Bearer {expired_token}"}

            # Act
            response = client.get("/auth/me", headers=headers)

            # Assert
            assert response.status_code == 401
            assert "Could not validate credentials or token expired" in response.json()["detail"]

    def test_auth_token_input_length_boundaries(self):
        # Arrange & Act: test boundaries around max_length for username (255) and password (1024)
        with TestClient(app) as client:
            # 255-char username (valid length, though unknown user -> 401)
            resp_user_valid = client.post(
                "/auth/token",
                data={"username": "u" * 255, "password": "password123"}
            )
            assert resp_user_valid.status_code == 401

            # 256-char username (exceeds limit -> 400 Bad Request)
            resp_user_invalid = client.post(
                "/auth/token",
                data={"username": "u" * 256, "password": "password123"}
            )
            assert resp_user_invalid.status_code == 400
            assert "payload too large" in resp_user_invalid.json()["detail"]

            # 1024-char password (valid length -> 401)
            resp_pass_valid = client.post(
                "/auth/token",
                data={"username": "analyst", "password": "p" * 1024}
            )
            assert resp_pass_valid.status_code == 401

            # 1025-char password (exceeds limit -> 400 Bad Request)
            resp_pass_invalid = client.post(
                "/auth/token",
                data={"username": "analyst", "password": "p" * 1025}
            )
            assert resp_pass_invalid.status_code == 400
            assert "payload too large" in resp_pass_invalid.json()["detail"]

    def test_admin_role_can_create_ioc(self):
        # Arrange: login as admin who has role "admin", should satisfy require_role("threat_analyst")
        with TestClient(app) as client:
            login_resp = client.post(
                "/auth/token",
                data={"username": "admin", "password": "adminpassword123"}
            )
            assert login_resp.status_code == 200
            admin_token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {admin_token}"}

            payload = {
                "indicator_value": "198.51.100.200",
                "indicator_type": "ipv4",
                "threat_type": "apt_c2",
                "confidence_score": 95,
                "severity": "critical",
                "description": "Created by admin"
            }

            # Act
            create_resp = client.post("/iocs", json=payload, headers=headers)

            # Assert
            assert create_resp.status_code == 201
            assert create_resp.json()["indicator_value"] == "198.51.100.200"


# ---------------------------------------------------------------------------
# Integration Tests: Query, Search & Pagination Edge Cases
# ---------------------------------------------------------------------------

class TestQueryAndPaginationEdgeCases:
    """Test suite targeting query filtering, SQL escaping and pagination."""

    @pytest.fixture
    def auth_headers(self):
        # Use direct token generation to ensure fixture is fast, deterministic, and avoids hitting login rate limits
        token = create_access_token(data={"sub": "analyst", "role": "threat_analyst"})
        return {"Authorization": f"Bearer {token}"}

    def test_ioc_lookup_not_found(self, auth_headers):
        # Arrange
        with TestClient(app) as client:
            non_existent_id = 9999999

            # Act
            response = client.get(f"/iocs/{non_existent_id}", headers=auth_headers)

            # Assert
            assert response.status_code == 404
            assert f"Threat indicator with ID {non_existent_id} not found." in response.json()["detail"]

    def test_ioc_lookup_invalid_id_boundaries(self, auth_headers):
        # Arrange & Act: ID <= 0 or exceeding max 32-bit int
        with TestClient(app) as client:
            zero_resp = client.get("/iocs/0", headers=auth_headers)
            assert zero_resp.status_code == 422

            overflow_resp = client.get("/iocs/2147483648", headers=auth_headers)
            assert overflow_resp.status_code == 422

    def test_pagination_limit_and_offset_boundaries(self, auth_headers):
        # Arrange & Act: valid pagination parameters
        with TestClient(app) as client:
            page1 = client.get("/iocs?limit=2&offset=0", headers=auth_headers)
            assert page1.status_code == 200
            data1 = page1.json()
            assert len(data1) == 2

            page2 = client.get("/iocs?limit=2&offset=2", headers=auth_headers)
            assert page2.status_code == 200
            data2 = page2.json()
            assert len(data2) <= 2
            # Offset should return distinct items from page 1
            if len(data2) > 0:
                assert data1[0]["id"] != data2[0]["id"]

    def test_pagination_invalid_limit_and_offset(self, auth_headers):
        # Arrange & Act: invalid limit / offset
        with TestClient(app) as client:
            # limit < 1
            res_lim_zero = client.get("/iocs?limit=0", headers=auth_headers)
            assert res_lim_zero.status_code == 422

            # limit > 500
            res_lim_large = client.get("/iocs?limit=501", headers=auth_headers)
            assert res_lim_large.status_code == 422

            # offset < 0
            res_off_neg = client.get("/iocs?offset=-1", headers=auth_headers)
            assert res_off_neg.status_code == 422

    def test_search_special_wildcard_characters(self, auth_headers):
        # Arrange: search with SQL wildcard characters `%`, `_`, `\`
        with TestClient(app) as client:
            res_percent = client.get("/iocs?search=%", headers=auth_headers)
            assert res_percent.status_code == 200
            assert isinstance(res_percent.json(), list)

            res_underscore = client.get("/iocs?search=_", headers=auth_headers)
            assert res_underscore.status_code == 200
            assert isinstance(res_underscore.json(), list)

            res_backslash = client.get("/iocs?search=\\", headers=auth_headers)
            assert res_backslash.status_code == 200
            assert isinstance(res_backslash.json(), list)

    def test_min_confidence_boundary_filtering(self, auth_headers):
        # Arrange & Act: min_confidence=0 exercises the shortcut in list_iocs
        with TestClient(app) as client:
            res_zero = client.get("/iocs?min_confidence=0", headers=auth_headers)
            assert res_zero.status_code == 200
            all_iocs = res_zero.json()
            assert len(all_iocs) >= 1

            # min_confidence=100
            res_max = client.get("/iocs?min_confidence=100", headers=auth_headers)
            assert res_max.status_code == 200
            assert all(ioc["confidence_score"] == 100 for ioc in res_max.json())

            # min_confidence > 100
            res_over = client.get("/iocs?min_confidence=101", headers=auth_headers)
            assert res_over.status_code == 422

    def test_search_parameter_length_boundary(self, auth_headers):
        # Arrange & Act: search with length boundary (max_length=255)
        with TestClient(app) as client:
            # Exactly 255 chars succeeds
            res_valid = client.get(f"/iocs?search={'a' * 255}", headers=auth_headers)
            assert res_valid.status_code == 200

            # 256 chars fails with 422
            res_invalid = client.get(f"/iocs?search={'a' * 256}", headers=auth_headers)
            assert res_invalid.status_code == 422

    def test_indicator_type_case_insensitivity_and_multi_filter(self, auth_headers):
        # Arrange & Act: indicator_type query parameter should be case-insensitive (e.g. IPV4, Domain)
        with TestClient(app) as client:
            res_upper = client.get("/iocs?indicator_type=IPV4", headers=auth_headers)
            assert res_upper.status_code == 200
            results = res_upper.json()
            assert len(results) >= 1
            assert all(ioc["indicator_type"] == "ipv4" for ioc in results)

            # Combined multi-criteria filter: indicator_type + min_confidence
            res_combined = client.get("/iocs?indicator_type=ipv4&min_confidence=90", headers=auth_headers)
            assert res_combined.status_code == 200
            combined_results = res_combined.json()
            assert len(combined_results) >= 1
            assert all(ioc["indicator_type"] == "ipv4" and ioc["confidence_score"] >= 90 for ioc in combined_results)


# ---------------------------------------------------------------------------
# Integration Tests: System, Security Handlers & Rate Limiter Boundaries
# ---------------------------------------------------------------------------

class TestSystemAndSecurityBoundaries:
    """Test suite targeting global error handling, rate limiter store edge cases, and audit logging."""

    def test_global_exception_handler_returns_500_and_sanitizes_stack_trace(self):
        # Arrange: simulate an unhandled server error during request execution using dependency_overrides
        def broken_get_db():
            raise RuntimeError("Unexpected catastrophic database driver failure")

        app.dependency_overrides[get_db] = broken_get_db
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                token = create_access_token(data={"sub": "analyst", "role": "threat_analyst"})
                headers = {"Authorization": f"Bearer {token}"}

                # Act: trigger an endpoint that depends on get_db
                response = client.get("/iocs", headers=headers)

                # Assert: returns 500 with sanitized generic message rather than leaking trace
                assert response.status_code == 500
                assert response.json() == {"detail": "Internal server error"}
        finally:
            app.dependency_overrides.pop(get_db, None)

    def test_rate_limiter_store_capacity_exhaustion(self):
        # Arrange: fill rate limiter store up to MAX_LOGIN_ATTEMPTS_STORE_SIZE
        import app.main as main_mod
        with main_mod.LOGIN_ATTEMPTS_LOCK:
            main_mod.LOGIN_ATTEMPTS.clear()
            # Populate store up to capacity with dummy IPs
            for i in range(main_mod.MAX_LOGIN_ATTEMPTS_STORE_SIZE):
                main_mod.LOGIN_ATTEMPTS[f"10.0.{i // 256}.{i % 256}"] = [time.time()]

        with TestClient(app) as client:
            # Act: attempt login from a new client IP not already in store
            response = client.post(
                "/auth/token",
                data={"username": "analyst", "password": "password123"}
            )
            # Assert: 429 Too Many Requests due to store capacity limit
            assert response.status_code == 429
            assert "Service is currently experiencing high load" in response.json()["detail"]

    def test_rate_limiter_periodic_cleanup_evicts_stale_records(self):
        # Arrange: set up stale attempts and simulate elapsed time > 300s
        import app.main as main_mod
        old_time = time.time() - 400
        active_time = time.time() - 10
        with main_mod.LOGIN_ATTEMPTS_LOCK:
            main_mod.LOGIN_ATTEMPTS.clear()
            main_mod.LOGIN_ATTEMPTS["192.0.2.1"] = [old_time]
            main_mod.LOGIN_ATTEMPTS["192.0.2.2"] = [old_time, active_time]
            main_mod.LAST_CLEANUP_TIME = time.time() - 350

        with TestClient(app) as client:
            # Act: trigger a login request which initiates throttled cleanup
            response = client.post(
                "/auth/token",
                data={"username": "analyst", "password": "password123"}
            )
            assert response.status_code == 200
            # Assert: stale entry was evicted and partially active entry was filtered
            with main_mod.LOGIN_ATTEMPTS_LOCK:
                assert "192.0.2.1" not in main_mod.LOGIN_ATTEMPTS
                assert len(main_mod.LOGIN_ATTEMPTS["192.0.2.2"]) == 1

    def test_rbac_audit_logging_on_unauthorized_access(self, caplog):
        # Arrange: login as guest user without threat_analyst permissions
        import logging
        with TestClient(app) as client:
            login_resp = client.post(
                "/auth/token",
                data={"username": "guest", "password": "password123"}
            )
            assert login_resp.status_code == 200
            guest_token = login_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {guest_token}"}

            payload = {
                "indicator_value": "198.51.100.42",
                "indicator_type": "ipv4",
                "threat_type": "c2",
                "confidence_score": 85,
                "severity": "high"
            }

            # Act: attempt unauthorized IOC creation while capturing audit logs
            with caplog.at_level(logging.WARNING, logger="audit"):
                response = client.post("/iocs", json=payload, headers=headers)

            # Assert
            assert response.status_code == 403
            assert any(
                "Unauthorized access attempt by user 'guest'" in record.message
                for record in caplog.records
            )

    def test_ipv4_validation_invalid_octets(self):
        # Arrange & Act: test invalid IPv4 values (octet > 255, non-numeric octet, missing octet)
        with pytest.raises(ValidationError) as exc1:
            IOCCreate(
                indicator_value="256.100.0.1",
                indicator_type="ipv4",
                threat_type="c2"
            )
        assert "Invalid IPv4 address format" in str(exc1.value)

        with pytest.raises(ValidationError) as exc2:
            IOCCreate(
                indicator_value="192.168.1",
                indicator_type="ipv4",
                threat_type="c2"
            )
        assert "Invalid IPv4 address format" in str(exc2.value)

    def test_seed_threat_data_idempotency(self):
        # Arrange & Act: calling seed_threat_data when indicators already exist does not re-insert duplicates
        from app.seed import seed_threat_data
        from app.models import Indicator
        db_generator = get_db()
        db = next(db_generator)
        try:
            initial_count = db.query(Indicator).count()
            assert initial_count > 0

            # Act: trigger seed_threat_data again
            seed_threat_data(db)
            new_count = db.query(Indicator).count()

            # Assert: count remained identical (idempotent)
            assert new_count == initial_count
        finally:
            db.close()
