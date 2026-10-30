# Mini Threat-Intel API Documentation

Welcome to the **Mini Threat-Intel API** documentation. This service provides high-performance endpoints for threat intelligence indicator ingestion, querying, authentication, and health monitoring.

---

## 📌 Overview

- **Base URL**: `http://localhost:8000`
- **Authentication**: JWT Bearer Token (`Authorization: Bearer <token>`)
- **Data Format**: JSON (`application/json`)
- **Interactive Documentation**:
  - Swagger UI: `http://localhost:8000/docs`
  - ReDoc UI: `http://localhost:8000/redoc`

---

## 🔐 Authentication & Access Control

The API implements role-based access control (RBAC) via JWT Custom Authorizers (`Depends(get_current_user)` and `Depends(require_role(...))`):

| Role | Access Level |
| :--- | :--- |
| `admin` | Full read and write access to all endpoints. |
| `threat_analyst` | Read access to indicators and write access (`POST /iocs`). |
| `guest` | Read-only access (`GET /iocs`, `GET /iocs/{id}`, `GET /auth/me`). |

---

## 📋 Endpoint Reference

### 1. System Health Check

#### `GET /health`
Verifies service liveness and container availability.

- **Authentication**: None (Unauthenticated)
- **Tag**: `System`

##### Parameters
*None*

##### Responses

| Status Code | Description | Content-Type | Payload |
| :--- | :--- | :--- | :--- |
| `200 OK` | Service is healthy. | `application/json` | `{"status": "healthy", "service": "threat-intel-api"}` |

##### Workflow Usage
Called by load balancers, container orchestrators (Docker, Kubernetes), and monitoring tools to verify API availability without authentication overhead.

---

### 2. User Authentication & Token Generation

#### `POST /auth/token`
Exchanges user credentials for a signed JWT access token.

- **Authentication**: None (Unauthenticated)
- **Tag**: `Authentication`

##### Request Headers
- `Content-Type: application/x-www-form-urlencoded` (**Required**)

##### Parameters (Form Data Body)

| Parameter | Type | Required / Optional | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `username` | String | **Required** | Max 255 chars | Registered account username (e.g. `analyst`, `admin`, `guest`). |
| `password` | String | **Required** | Max 1024 chars | User account password (e.g. `password123`, `adminpassword123`). |
| `grant_type` | String | **Optional** | — | OAuth2 grant type (default: `password`). |
| `scope` | String | **Optional** | — | OAuth2 scope string. |
| `client_id` | String | **Optional** | — | OAuth2 client identifier. |
| `client_secret` | String | **Optional** | — | OAuth2 client secret. |

##### Responses

| Status Code | Description | Content-Type | Payload Example |
| :--- | :--- | :--- | :--- |
| `200 OK` | Authentication successful. | `application/json` | `{"access_token": "eyJhbG...", "token_type": "bearer", "expires_in_minutes": 60}` |
| `400 Bad Request` | Payload too large (> 255 char username or > 1024 char password). | `application/json` | `{"detail": "Invalid request: payload too large"}` |
| `401 Unauthorized` | Invalid username or password. | `application/json` | `{"detail": "Incorrect username or password"}` |
| `429 Too Many Requests` | Rate limit exceeded (> 5 attempts per 60s per IP). | `application/json` | `{"detail": "Too many login attempts. Please try again later."}` |

##### Workflow Usage
Clients send a `POST` request with form-encoded credentials to obtain a Bearer JWT. The resulting `access_token` must be included in the `Authorization` header for protected routes.

---

### 3. Read Current User Profile

#### `GET /auth/me`
Retrieves identity claims and role information for the current authenticated user.

- **Authentication**: Bearer Token (**Required**)
- **Tag**: `Authentication`

##### Request Headers
- `Authorization: Bearer <token>` (**Required**)

##### Parameters
*None*

##### Responses

| Status Code | Description | Content-Type | Payload Example |
| :--- | :--- | :--- | :--- |
| `200 OK` | Profile retrieved successfully. | `application/json` | `{"username": "analyst", "role": "threat_analyst", "disabled": false}` |
| `401 Unauthorized` | Invalid, missing, or expired JWT token. | `application/json` | `{"detail": "Could not validate credentials or token expired"}` |

##### Workflow Usage
Used by user interfaces or API clients to inspect the token owner's identity and permissions.

---

### 4. Query Threat Intelligence Indicators

#### `GET /iocs`
Queries and filters Indicators of Compromise stored in the threat database.

- **Authentication**: Bearer Token (**Required**)
- **Tag**: `Indicators of Compromise`

##### Request Headers
- `Authorization: Bearer <token>` (**Required**)

##### Query Parameters

| Parameter | Type | Required / Optional | Constraints / Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `indicator_type` | String | **Optional** | Max 50 chars (`ipv4`, `domain`, `sha256`, `url`, `email`) | Filter indicators by type classification. |
| `min_confidence` | Integer | **Optional** | Min 0, Max 100, Default: `0` | Minimum confidence score threshold. |
| `search` | String | **Optional** | Max 255 chars | Case-insensitive search on `indicator_value` or `description`. |
| `limit` | Integer | **Optional** | Min 1, Max 500, Default: `50` | Maximum number of records returned. |
| `offset` | Integer | **Optional** | Min 0, Max 2147483647, Default: `0` | Number of initial records to skip for pagination. |

##### Responses

| Status Code | Description | Content-Type | Payload Example |
| :--- | :--- | :--- | :--- |
| `200 OK` | Indicators retrieved successfully. | `application/json` | `[{"id": 1, "indicator_value": "198.51.100.24", "indicator_type": "ipv4", "threat_type": "ransomware_c2", "confidence_score": 85, "severity": "high", "description": "BlackCat C2", "is_active": true, "first_seen": "2024-01-15T10:30:00Z", "last_seen": "2024-01-20T14:45:00Z"}]` |
| `401 Unauthorized` | Invalid, missing, or expired JWT token. | `application/json` | `{"detail": "Could not validate credentials or token expired"}` |
| `422 Unprocessable Entity` | Parameter validation failure. | `application/json` | `{"detail": [...]}` |

##### Workflow Usage
Security operations platforms (SIEM, SOAR, EDR, Firewall) query this endpoint to populate blocklists or cross-reference observables.

---

### 5. Get Indicator by ID

#### `GET /iocs/{ioc_id}`
Retrieves a single Indicator of Compromise by its database primary key.

- **Authentication**: Bearer Token (**Required**)
- **Tag**: `Indicators of Compromise`

##### Request Headers
- `Authorization: Bearer <token>` (**Required**)

##### Path Parameters

| Parameter | Type | Required / Optional | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ioc_id` | Integer | **Required** | Min 1, Max 2147483647 | Database primary key ID of the threat indicator. |

##### Responses

| Status Code | Description | Content-Type | Payload Example |
| :--- | :--- | :--- | :--- |
| `200 OK` | Indicator retrieved successfully. | `application/json` | `{"id": 1, "indicator_value": "198.51.100.24", "indicator_type": "ipv4", "threat_type": "ransomware_c2", "confidence_score": 85, "severity": "high", "description": "BlackCat C2", "is_active": true, "first_seen": "2024-01-15T10:30:00Z", "last_seen": "2024-01-20T14:45:00Z"}` |
| `401 Unauthorized` | Invalid, missing, or expired JWT token. | `application/json` | `{"detail": "Could not validate credentials or token expired"}` |
| `404 Not Found` | Indicator ID does not exist. | `application/json` | `{"detail": "Threat indicator with ID 999 not found."}` |
| `422 Unprocessable Entity` | Invalid `ioc_id` type or bounds. | `application/json` | `{"detail": [...]}` |

##### Workflow Usage
Used in analyst investigation workflows when looking up specific indicator record details.

---

### 6. Ingest New Threat Indicator

#### `POST /iocs`
Ingests a new Indicator of Compromise into the threat database.

- **Authentication**: Bearer Token (**Required**, Role: `threat_analyst` or `admin`)
- **Tag**: `Indicators of Compromise`

##### Request Headers
- `Authorization: Bearer <token>` (**Required**)
- `Content-Type: application/json` (**Required**)

##### Request Body (JSON Schema)

| Field | Type | Required / Optional | Constraints / Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `indicator_value` | String | **Required** | Max 255 chars | Threat observable matching format validation (`ipv4`, `domain`, `sha256`, `url`, `email`). |
| `indicator_type` | String | **Required** | `ipv4`, `domain`, `sha256`, `url`, `email` | Indicator classification type. |
| `threat_type` | String | **Required** | Max 100 chars | Category of malicious activity (e.g. `phishing`, `c2`). Automatically sanitized against HTML/XSS. |
| `confidence_score` | Integer | **Optional** | Min 0, Max 100, Default: `50` | Confidence rating score (0 to 100). |
| `severity` | String | **Optional** | `low`, `medium`, `high`, `critical`, Default: `"medium"` | Assessed severity level. |
| `description` | String | **Optional** | Max 500 chars | Context description. Automatically sanitized against HTML/XSS. |
| `is_active` | Boolean | **Optional** | Default: `true` | Whether the indicator is active. |

##### Responses

| Status Code | Description | Content-Type | Payload Example |
| :--- | :--- | :--- | :--- |
| `201 Created` | Indicator ingested successfully. | `application/json` | `{"id": 42, "indicator_value": "198.51.100.77", "indicator_type": "ipv4", "threat_type": "cobalt_strike_beacon", "confidence_score": 96, "severity": "critical", "description": "Active C2 beacon", "is_active": true, "first_seen": "2024-01-20T15:00:00Z", "last_seen": "2024-01-20T15:00:00Z"}` |
| `401 Unauthorized` | Invalid, missing, or expired JWT token. | `application/json` | `{"detail": "Could not validate credentials or token expired"}` |
| `403 Forbidden` | Insufficient permissions (role is not `threat_analyst` or `admin`). | `application/json` | `{"detail": "Operation not permitted. Requires 'threat_analyst' role."}` |
| `422 Unprocessable Entity` | Validation error (e.g. invalid IP/URL/hash format, invalid score range). | `application/json` | `{"detail": [...]}` |

##### Workflow Usage
Used by automated threat ingestion pipelines or security analysts submitting verified IOC observables.
