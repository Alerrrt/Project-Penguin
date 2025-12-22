# Project-Echo — Advanced Security Scanner

A modern web security scanning platform with robust concurrency, safe HTTP policies, and real-time updates. Project-Echo contains comprehensive security scanning capabilities with a focus on performance, reliability, and user experience.

## 🔍 Key Features

- **Concurrent Scanning Architecture**: Scanners run concurrently with adaptive limits and circuit breakers for optimal performance
- **Robust HTTP Client**: Shared HTTP client with retries, exponential backoff + jitter, per‑host throttling, optional SSRF guard, host allow/deny lists, and response size caps
- **Real-time Updates**: WebSocket-based live updates during scanning process
- **Comprehensive Vulnerability Detection**: Multiple specialized scanners covering OWASP Top 10 and common security issues
- **Resilient Operation**: Snapshotting and partial results for resilience during scans
- **Performance Metrics**: Structured logging and runtime metrics (HTTP and concurrency) exposed via API
- **Modern Tech Stack**: FastAPI backend with WebSocket updates; React + Tailwind frontend

## 🚀 Quick Start (Docker)

1) From repo root:
```bash
docker compose up --build
```

2) Backend API: `http://localhost:9000`
   - Docs: `http://localhost:9000/docs`
   - Health: `GET /health`
   - Scans: `POST /api/scans/start`, `GET /api/scans/{scan_id}`
   - Metrics: `GET /api/metrics/http-client`, `GET /api/metrics/concurrency`

3) Frontend: `http://localhost:3002`

## 💻 Local Development

### Backend (Python/FastAPI)

```bash
python -m venv .venv
# On Linux/macOS
source .venv/bin/activate
# On Windows
.venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 9000 --reload
```

### Frontend (React/TypeScript)

```bash
cd frontend
npm install
npm run dev
```

## 🔌 API Reference

### Core APIs

- **Start scan**
```bash
curl -sX POST http://localhost:9000/api/scans/start \
  -H 'content-type: application/json' \
  -d '{"target":"https://example.com","scan_type":"full","options":{}}'
```

- **Scan status**
```bash
curl -s http://localhost:9000/api/scans/{scan_id}
```

- **Results (compact)**
```bash
curl -s http://localhost:9000/api/scans/{scan_id}/results
```

- **Reports**
```bash
curl -s http://localhost:9000/api/reports/scans/{scan_id}/results
```

- **WebSocket Connection**
  - Connect to `ws://localhost:9000/api/ws/{scan_id}` for real-time scan updates

## 🛡️ Security Features

### Network Safety and HTTP Resilience

Environment variables (set in `.env` or docker‑compose):
- `BLOCK_PRIVATE_NETWORKS` (bool): block private/loopback by default
- `HTTP_MAX_RETRIES` (int), `HTTP_BACKOFF_BASE_SECONDS` (float), `HTTP_BACKOFF_MAX_SECONDS` (float)
- `HTTP_PER_HOST_MIN_INTERVAL_MS` (int): min interval between requests to same host
- `HTTP_ALLOWED_HOSTS` (list[str]): allowlist; if non‑empty, other hosts are blocked
- `HTTP_BLOCKED_HOSTS` (list[str]): blocklist
- `HTTP_MAX_RESPONSE_BYTES` (int): truncate response content above limit (0 disables)
- `HTTP_ACCEPT_LANGUAGE` (str): default Accept‑Language

### Concurrency and Stability

- Priority scheduling, adaptive concurrency by memory pressure
- Per‑scanner circuit breaker and global breaker
- Queue fairness and immediate start when capacity exists
- Timeout management for long-running scanners

## 📊 Available Scanners

The platform includes multiple specialized scanners, including:

- XSS (Cross-Site Scripting) Scanner
- SQL Injection Scanner
- CSRF (Cross-Site Request Forgery) Scanner
- Open Redirect Scanner
- Broken Authentication Scanner
- Broken Access Control Scanner
- SSL/TLS Configuration Audit Scanner
- API Fuzzing Scanner
- Subdomain DNS Enumeration Scanner
- Automated CVE Lookup Scanner
- Content Security Policy Scanner
- JavaScript Security Scanner

## 📈 Metrics and Monitoring

- **HTTP client metrics**: cache size, active requests, retries, throttle waits, SSRF blocks
  - `GET /api/metrics/http-client`
- **Concurrency manager metrics**: active/queued/completed/failed, avg exec time, memory usage, circuit breaker status
  - `GET /api/metrics/concurrency`

## 🧪 Testing

Run targeted backend tests:
```bash
python -m pytest -q backend/tests
```

## 📁 Project Structure

- `backend/` - FastAPI application
  - `api/` - API endpoints and routers
  - `scanners/` - Security scanner implementations
  - `utils/` - Utility functions and helpers
  - `types/` - Type definitions and models
  - `plugins/` - Plugin system for extensibility
  - `config/` - Configuration management

- `frontend/` - React application
  - `src/components/` - UI components
  - `src/context/` - React context providers
  - `src/api/` - API client functions
  - `src/types/` - TypeScript type definitions

- `docker-compose.yml` - Docker Compose configuration for local development

## 🔄 WebSocket Communication

The application uses WebSockets for real-time updates during scanning:

- Connection endpoint: `/api/ws/{scan_id}`
- Message types:
  - Scan progress updates
  - Vulnerability discoveries
  - Module status changes
  - Heartbeat messages

## 📄 License

MIT
