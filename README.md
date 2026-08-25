# Mini Threat-Intel API (FastAPI + PostgreSQL + JWT)

A minimal, high-performance Threat Intelligence API built with **Python 3.11, FastAPI, SQLAlchemy 2.0, PostgreSQL 16, and JWT Authentication**.

Designed as a rapid, hands-on bridge for engineers transitioning from **Node.js/TypeScript/PHP** to Python backend stacks ahead of technical interviews.

---

## 🚀 Quickstart (Under 60 Seconds)

### 1. Launch Containers
```bash
docker compose up -d --build
```

### 2. Verify Health & OpenAPI Docs
- **Health Check**: `http://localhost:8000/health`
- **Interactive Swagger UI**: `http://localhost:8000/docs`
- **Alternative ReDoc UI**: `http://localhost:8000/redoc`

---

## 🧪 Testing the API via cURL

### 1. Health Check (Unauthenticated)
```bash
curl -s http://localhost:8000/health
```
**Response:**
```json
{"status":"healthy","service":"threat-intel-api"}
```

---

### 2. Attempt Unauthenticated Access (Verify Custom Authorizer Rejection)
```bash
curl -i http://localhost:8000/iocs
```
**Response:** `HTTP/1.1 401 Unauthorized`

---

### 3. Generate JWT Access Token (`POST /auth/token`)
```bash
curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=analyst&password=password123"
```
**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in_minutes": 60
}
```

---

### 4. Query Threat Indicators (`GET /iocs`)
Save your token to a shell variable or paste it directly:

```bash
# Windows PowerShell:
$TOKEN = (Invoke-RestMethod -Method Post -Uri "http://localhost:8000/auth/token" -Body @{username="analyst"; password="password123"}).access_token

# Query all indicators:
Invoke-RestMethod -Uri "http://localhost:8000/iocs" -Headers @{Authorization="Bearer $TOKEN"}

# Query high-confidence IP indicators:
Invoke-RestMethod -Uri "http://localhost:8000/iocs?indicator_type=ipv4&min_confidence=90" -Headers @{Authorization="Bearer $TOKEN"}
```

```bash
# Linux / macOS / Git Bash:
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token -d "username=analyst&password=password123" | jq -r .access_token)

# Query indicators with confidence >= 80:
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8000/iocs?min_confidence=80" | jq .
```

---

### 5. Ingest a New Threat Indicator (`POST /iocs`)
```bash
curl -s -X POST http://localhost:8000/iocs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator_value": "198.51.100.77",
    "indicator_type": "ipv4",
    "threat_type": "cobalt_strike_beacon",
    "confidence_score": 96,
    "severity": "critical",
    "description": "Active C2 beacon observed communicating with staging infrastructure."
  }' | jq .
```

---

## 🧠 Node.js / Express / Laravel $\rightarrow$ FastAPI Rosetta Stone

| Concept | Node.js / Express / Laravel | Python / FastAPI / SQLAlchemy |
| :--- | :--- | :--- |
| **Routing** | `app.get('/iocs', handler)` | `@app.get("/iocs") def list_iocs(...)` |
| **Request Validation** | Joi, Zod, or FormRequests | **Pydantic Models** (`BaseModel`, `Field`) |
| **Type Safety** | TypeScript interfaces *(vanish at runtime)* | **Type Annotations + Pydantic** *(enforced at runtime)* |
| **Middleware / Auth** | `req.user = decodedToken; next()` | **FastAPI `Depends(get_current_user)`** (Dependency Injection graph) |
| **Database ORM** | Eloquent (Active Record) / Prisma | **SQLAlchemy** (Data Mapper / Unit of Work) |
| **API Docs** | Swagger-JSDoc / manual YAML | **Native OpenAPI generation** at `/docs` |
| **Server Engine** | Node Event Loop (V8 libuv) | **ASGI (Asynchronous Server Gateway Interface)** via Uvicorn |

---

## 🎯 Interview Cheat Sheet: Proofpoint Threat Intel Tooling

When discussing this architecture in your interview, highlight these key topics:

### 1. Why FastAPI for Threat Intelligence Workloads?
- **High Concurrency & Low Latency**: Threat APIs receive millions of lookup queries (e.g. firewalls/SIEMs checking if incoming IPs/domains are malicious). FastAPI runs on **Uvicorn (ASGI)**, leveraging Python's `asyncio` event loop for non-blocking I/O.
- **Pydantic Runtime Guarantees**: Unlike TypeScript where types disappear after compilation, Pydantic parses, coerces, and validates threat observables at runtime. If a consumer sends an invalid confidence score (e.g. `150` when `0..100` is expected), FastAPI rejects it with a `422 Unprocessable Entity` before it touches business logic.
- **Automatic OpenAPI Documentation**: Security teams and integration partners consume threat feeds through SDKs. FastAPI automatically generates OpenAPI 3.1 schemas, making API clients instantly generateable.

### 2. Dependency Injection (`Depends`) as Custom Authorizers
- In Express, authentication is imperative: middleware mutates `req` and passes control down a sequential chain.
- In FastAPI, `Depends()` creates an **inversion of control graph**. When a route declares `current_user: User = Depends(get_current_user)`:
  1. FastAPI extracts the `Authorization: Bearer <token>` header.
  2. Decodes the JWT and validates signature & expiration (`exp`).
  3. Verifies user claims/scopes/roles.
  4. Injects a fully-typed `User` object directly into the controller signature.
- This pattern isolates authentication logic, making unit testing trivial (you can override dependencies with `app.dependency_overrides`).

### 3. Threat Intel Data Modeling & Real-World Nuances
- **Confidence Scoring (0–100)**: Security tools require confidence thresholds to avoid false positives (e.g. firewalls only auto-block at $>90$, while SIEM alerts trigger at $>70$).
- **Indicator Decay & TTL**: Malicious IPs change ownership quickly (bulletproof hosting vs legitimate cloud). Production threat databases track `first_seen` and `last_seen` timestamps to calculate decay rates.
- **Compound Indexing**: Filtering queries frequently combine `indicator_type` and `confidence_score` (e.g., `WHERE indicator_type = 'ipv4' AND confidence_score >= 80`). We indexed `ix_indicators_type_confidence` to ensure fast index scans in Postgres.

---

## 🛠️ Project Structure

```
mini-threat-api/
├── docker-compose.yml       # PostgreSQL 16 + FastAPI service definition
├── Dockerfile               # Python 3.11-slim container with hot reloading
├── requirements.txt         # Production dependencies
├── .env.example             # Environment variable template
├── app/
│   ├── __init__.py
│   ├── config.py            # Pydantic BaseSettings for config management
│   ├── database.py          # SQLAlchemy engine, SessionLocal, get_db generator
│   ├── models.py            # SQLAlchemy ORM Model (Indicator table)
│   ├── schemas.py           # Pydantic validation schemas (IOCCreate, IOCResponse, Token)
│   ├── auth.py              # JWT generation, decode, and get_current_user custom authorizer
│   ├── seed.py              # Realistic mock threat intelligence indicators
│   └── main.py              # FastAPI endpoints and lifespan event handler
└── README.md                # Documentation and interview cheat sheet
```
