from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import logging
import sys

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Scanner API",
    description="API for security scanning and analysis",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:3100", "http://127.0.0.1:3100", 
        "http://localhost:3002", "http://127.0.0.1:3002",
        "http://localhost:3003", "http://127.0.0.1:3003",
        "http://localhost:5173", "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Readiness flag
backend_ready = True

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "backend_ready": backend_ready
    }

@app.get("/api/ready")
async def api_ready():
    """Endpoint to check if the backend is ready."""
    return {
        "ready": backend_ready,
        "timestamp": datetime.now().isoformat(),
        "message": "Minimal backend running"
    }

@app.get("/api/scans/scanners")
async def list_scanners():
    """Minimal scanners endpoint."""
    return {
        "minimal_scanner": {
            "name": "Basic Scanner",
            "description": "Minimal scanner for testing",
            "status": "available"
        }
    }

@app.get("/api/scans/")
async def get_scans():
    """Minimal scans endpoint."""
    return []

@app.on_event("startup")
async def startup_event():
    """Minimal startup."""
    logger.info(" Minimal backend starting...")
    logger.info(" Minimal backend ready!")

@app.on_event("shutdown")
async def shutdown_event():
    """Minimal shutdown."""
    logger.info("Minimal backend shutting down")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main_minimal:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )