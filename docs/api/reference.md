# Mini Threat-Intel API Reference

This document provides a comprehensive technical specification of all HTTP routes exposed by the Mini Threat-Intel API.

---

## Table of Contents
- [Authentication Overview](#authentication-overview)
- [System Endpoints](#system-endpoints)
  - [GET /health](#get-health)
- [Authentication Endpoints](#authentication-endpoints)
  - [POST /auth/token](#post-authtoken)
  - [GET /auth/me](#get-authme)
- [Indicators of Compromise (IOC) Endpoints](#indicators-of-compromise-ioc-endpoints)
  - [GET /iocs](#get-iocs)
  - [GET /iocs/{ioc_id}](#get-iocsioc_id)
  - [POST /iocs](#post-iocs)

---

## Authentication Overview

Protected endpoints require a JSON Web Token (JWT) passed in the `Authorization` HTTP header using the `Bearer` scheme:

```http
Authorization: Bearer <access_token>
```

Tokens are obtained via the `POST /auth/token` endpoint. Decoded tokens include user identity (`sub`), assigned role (`role`), standard timestamps (`iat`, `nbf`, `exp`), and a unique token identifier (`jti`).

### Demo User Accounts
- `analyst` / `password123` (Role: `threat_analyst`)
- `admin` / `adminpassword123` (Role: `admin`)
- `guest` / `password123` (Role: `guest`)

---

## System Endpoints

### `GET /health`
Health check endpoint to verify service and container liveness.

- **Authentication**: None (Unauthenticated)
- **Tags**: `System`

#### Request Parameters
*None.*

#### Response
- **Status Code**: `200 OK`
- **Content-Type**: `application/json`
- **Schema**:
```json
{
  "status": "string",
  "service": "string"
}
```
- **Example Response**:
```json
{
  "status": "healthy",
  "service": "threat-intel-api"
}
```

#### Practical Usage
Monitors container liveness and readiness probes in orchestration platforms (e.g. Kubernetes, AWS ECS, Docker Compose).

---

## Authentication Endpoints

### `POST /auth/token`
OAuth2 password flow login endpoint. Authenticates user credentials and issues a signed JWT access token.

- **Authentication**: None (Unauthenticated)
- **Tags**: `Authentication`
- **Rate Limit**: Maximum 5 attempts per 60 seconds per IP address.

#### Request Headers
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Content-Type` | String | **Required** | Must be `application/x-www-form-urlencoded`. |

#### Request Body (Form URL-Encoded)
| Field | Type | Required | Description | Constraints |
| :--- | :--- | :--- | :--- | :--- |
| `username` | String | **Required** | The user's account username. | Maximum 255 characters. |
| `password` | String | **Required** | The user's password. | Maximum 1024 characters. |

#### Responses
- **`200 OK`**: Successfully authenticated. Returns JWT access token.
  - **Schema**:
    ```json
    {
      "access_token": "string",
      "token_type": "string",
      "expires_in_minutes": "integer"
    }
    ```
  - **Example**:
    ```json
    {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "token_type": "bearer",
      "expires_in_minutes": 60
    }
    ```
- **`400 Bad Request`**: Request payload exceeds allowed character limits.
- **`401 Unauthorized`**: Incorrect username or password, or account disabled.
- **`429 Too Many Requests`**: Rate limit exceeded for the client IP address.

#### Practical Usage
Exchange client username and password for a bearer token prior to invoking protected endpoints.

---

### `GET /auth/me`
Retrieves identity and role claims for the currently authenticated user based on the decoded JWT.

- **Authentication**: JWT Bearer token (`get_current_user`)
- **Tags**: `Authentication`

#### Request Headers
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | **Required** | Bearer token format: `Bearer <token>`. |

#### Responses
- **`200 OK`**: Current user details successfully resolved.
  - **Schema**:
    ```json
    {
      "username": "string",
      "role": "string",
      "disabled": "boolean"
    }
    ```
  - **Example**:
    ```json
    {
      "username": "analyst",
      "role": "threat_analyst",
      "disabled": false
    }
    ```
- **`401 Unauthorized`**: Missing, expired, or invalid JWT token.

#### Practical Usage
Used by clients and web applications during session initialization to inspect permissions, display active user details, and enforce UI-level feature gating.

---

## Indicators of Compromise (IOC) Endpoints

### `GET /iocs`
Queries and filters Indicators of Compromise (IOCs) stored in PostgreSQL with support for pagination and full-text keyword search.

- **Authentication**: JWT Bearer token (`get_current_user`)
- **Tags**: `Indicators of Compromise`

#### Request Headers
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | **Required** | Bearer token format: `Bearer <token>`. |

#### Query Parameters
| Parameter | Type | Required | Default | Description | Constraints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `indicator_type` | String | Optional | `null` | Filter by indicator type (`ipv4`, `domain`, `sha256`, `url`, `email`). | Max length: 50 |
| `min_confidence` | Integer | Optional | `0` | Minimum confidence score threshold. | `ge=0`, `le=100` |
| `search` | String | Optional | `null` | Substring search within `indicator_value` or `description`. | Max length: 255 |
| `limit` | Integer | Optional | `50` | Maximum number of records to return. | `ge=1`, `le=500` |
| `offset` | Integer | Optional | `0` | Number of records to skip for pagination. | `ge=0`, `le=2147483647` |

#### Responses
- **`200 OK`**: List of matching IOC records ordered by `confidence_score` descending.
  - **Schema**: Array of `IOCResponse` objects:
    ```json
    [
      {
        "id": 1,
        "indicator_value": "string",
        "indicator_type": "string",
        "threat_type": "string",
        "confidence_score": 50,
        "severity": "string",
        "description": "string",
        "is_active": true,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-01T00:00:00Z"
      }
    ]
    ```
- **`401 Unauthorized`**: Missing or invalid bearer token.
- **`422 Unprocessable Entity`**: Query parameters fail boundary or type validation.

#### Practical Usage
Ingested by security tools (SIEMs, SOAR platforms, EDRs, next-generation firewalls) to periodically pull high-confidence observables for detection rules or automated blocklists.

---

### `GET /iocs/{ioc_id}`
Retrieves a specific Indicator of Compromise by its integer database identifier.

- **Authentication**: JWT Bearer token (`get_current_user`)
- **Tags**: `Indicators of Compromise`

#### Request Headers
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | **Required** | Bearer token format: `Bearer <token>`. |

#### Path Parameters
| Parameter | Type | Required | Description | Constraints |
| :--- | :--- | :--- | :--- | :--- |
| `ioc_id` | Integer | **Required** | Database ID of the IOC record. | `ge=1`, `le=2147483647` |

#### Responses
- **`200 OK`**: Matching IOC found and returned.
  - **Schema**: `IOCResponse` object.
  - **Example**:
    ```json
    {
      "id": 1,
      "indicator_value": "198.51.100.24",
      "indicator_type": "ipv4",
      "threat_type": "ransomware_c2",
      "confidence_score": 95,
      "severity": "critical",
      "description": "Known LockBit 3.0 Command & Control IP",
      "is_active": true,
      "first_seen": "2026-01-01T00:00:00Z",
      "last_seen": "2026-01-01T00:00:00Z"
    }
    ```
- **`401 Unauthorized`**: Missing or invalid bearer token.
- **`404 Not Found`**: No IOC found with the specified ID.
- **`422 Unprocessable Entity`**: `ioc_id` parameter fails integer boundary constraints.

#### Practical Usage
Allows security analysts to inspect full historical metadata for an individual alert observable referenced by a case management ticket.

---

### `POST /iocs`
Creates and registers a new threat indicator in the database.

- **Authentication**: JWT Bearer token with Role-Based Access Control (`require_role("threat_analyst")`)
- **Authorization**: Permitted roles: `threat_analyst`, `admin`. Accounts with `guest` role are rejected.
- **Tags**: `Indicators of Compromise`

#### Request Headers
| Header | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `Authorization` | String | **Required** | Bearer token format: `Bearer <token>`. |
| `Content-Type` | String | **Required** | Must be `application/json`. |

#### Request Body (JSON)
| Field | Type | Required | Default | Description | Constraints / Formats |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `indicator_value` | String | **Required** | — | Observable value (IP, domain, hash, email, URL). | Formats validated according to `indicator_type`. Max length: 255 |
| `indicator_type` | String | **Required** | — | Observable category. | One of: `ipv4`, `domain`, `sha256`, `url`, `email` |
| `threat_type` | String | **Required** | — | Associated threat category (e.g. `ransomware_c2`). | Max length: 100. HTML-escaped. |
| `confidence_score` | Integer | Optional | `50` | Confidence score assessment. | `ge=0`, `le=100` |
| `severity` | String | Optional | `"medium"` | Assessed severity level. | One of: `low`, `medium`, `high`, `critical` |
| `description` | String | Optional | `null` | Contextual investigation notes. | Max length: 500. HTML-escaped. |
| `is_active` | Boolean | Optional | `true` | Current active indicator flag. | — |

##### Type Validation Rules for `indicator_value`:
- **`ipv4`**: Must be a valid IPv4 address (e.g., `198.51.100.24`).
- **`domain`**: Must be a valid domain structure (e.g., `malicious-domain.com`).
- **`sha256`**: Must be a valid 64-character hexadecimal hash.
- **`url`**: Must be a valid HTTP/HTTPS URL (`^https?://[^\s<>"'\`]+\Z`).
- **`email`**: Must be a valid email format.

#### Responses
- **`201 Created`**: Indicator successfully validated and persisted.
  - **Schema**: `IOCResponse` object.
- **`401 Unauthorized`**: Missing or invalid bearer token.
- **`403 Forbidden`**: User authenticated but lacks required role (`threat_analyst` or `admin`).
- **`422 Unprocessable Entity`**: Payload failed schema validation (e.g., malformed IP, invalid enum, confidence out of bounds).

#### Practical Usage
Invoked by threat intelligence analysts or automated threat ingestion pipelines following sandboxing analysis, incident response triage, or third-party intelligence feed sync.
