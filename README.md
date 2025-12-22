<div align="center">

#  Project-Echo

**The Next Generation of Open-Source Security Scanning**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.1.0-61DAFB.svg)](https://reactjs.org/)

[Features](#-key-features) • [Installation](#-getting-started) • [Architecture](#-project-structure) • [License](#-license)

---

Project-Echo is a unified security scanning platform designed for high-performance vulnerability discovery. 
Equipped with a concurrent scanning engine and a sleek, real-time dashboard, it empowers developers and security researchers to audit their infrastructure with precision and speed.

</div>

##  Key Features

-  **High-Performance Cores**: Asynchronous scanning engine built with FastAPI and HTTPX for extreme concurrency.
-  **Sleek UI/UX**: Modern React dashboard featuring real-time updates and modular control grids.
-  **Deep Scanning Architecture**: 
  - **Injection Attacks**: XSS, SQLi, XXE, and more.
  - **Access Control**: Broken authentication and authorization testers.
  - **OSINT**: Subdomain enumeration, CVE lookups, and WHOIS discovery.
-  **Real-time Metrics**: Built-in monitoring for HTTP client performance and scanner state.
-  **Safe by Design**: Integrated SSRF protection and rate-limiting to ensure responsible scanning.

##  Getting Started

### Prerequisites

- Python 3.12+
- Node.js 18+
- Docker (Optional for containerized deployment)

###  Manual Installation

1. **Clone the Abyss**
   ```bash
   git clone https://github.com/Alerrrt/Project-Echo.git
   cd Project-Echo
   ```

2. **Initialize Backend**
   ```bash
   python -m venv venv
   source venv/bin/activate  # venv\Scripts\activate on Windows
   pip install -r backend/requirements.txt
   ```

3. **Wake up the Frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

##  Project Structure

```bash
 Project-Echo
   backend          # FastAPI Application & Scanning Engine
    api            # Endpoints & Routers
    scanners       # Security module implementations
    utils          # Concurrency, Throttling & HTTP Helpers
   frontend         # Vite + React Dashboard
   docker-compose.yml 
   .gitignore
```

##  License

Distributed under the MIT License. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with  by the Project-Echo Team</sub>
</div>
