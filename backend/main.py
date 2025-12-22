from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import asyncio
from datetime import datetime
import os
import sys

# Ensure 'backend' package is importable whether running as 'backend.main' or 'main'
if __package__ is None or __package__ == "":
    # Add project root (parent of 'backend') to sys.path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Use basic logging initially to avoid complex dependencies
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Import settings with fallback
try:
    from backend.config import settings
    logger.info("Settings imported successfully")
except Exception as e:
    logger.error(f"Failed to import settings: {e}")
    # Create minimal settings fallback
    class Settings:
        CORS_ORIGINS = [
            "http://localhost:3000", "http://127.0.0.1:3000",
            "http://localhost:3100", "http://127.0.0.1:3100",
            "http://localhost:3002", "http://127.0.0.1:3002",
            "http://localhost:3003", "http://127.0.0.1:3003",
            "http://localhost:5173", "http://127.0.0.1:5173"
        ]
        HOST = "0.0.0.0"
        PORT = 8000
        DEBUG = True
    settings = Settings()

# Global state for scanner components
scanner_registry = None
scanner_engine = None
plugin_manager = None
components_loaded = False
loading_in_progress = False

app = FastAPI(
    title="Security Scanner API",
    description="API for security scanning and analysis",
    version="1.0.0"
)

# Add CORS middleware with fallback
try:
    cors_origins = getattr(settings, 'CORS_ORIGINS', [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:3100", "http://127.0.0.1:3100",
        "http://localhost:3002", "http://127.0.0.1:3002",
        "http://localhost:3003", "http://127.0.0.1:3003",
        "http://localhost:5173", "http://127.0.0.1:5173"
    ])
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info(" CORS middleware configured successfully")
except Exception as e:
    logger.error(f" Failed to configure CORS middleware: {e}")

# Deferred initialization - will be set up during startup
app.state.scanner_registry = None
app.state.scanner_engine = None

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error processing request: {exc}", exc_info=True)
    # Note: For custom error handling, use ErrorHandler from backend/utils/error_handler.py
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "backend_ready": backend_ready,
            "scanner_registry": scanner_registry is not None,
            "scanner_engine": scanner_engine is not None
        }
    }

@app.get("/test-root")
async def test_root():
    return {"message": "Hello from root"}

@app.get("/api/test-api")
async def test_api():
    return {"message": "Hello from API"}

# Readiness flag
backend_ready = False

def lazy_import_components():
    """Lazy import of complex components to avoid startup blocking."""
    global scanner_registry, scanner_engine, plugin_manager
    
    try:
        logger.info(" Starting lazy import of components...")
        
        # Import AppConfig
        from backend.config import AppConfig
        app_config = AppConfig.load_from_env()
        logger.info(" AppConfig loaded")
        
        # Import and initialize ScannerRegistry
        from backend.scanners.scanner_registry import ScannerRegistry
        scanner_registry = ScannerRegistry(app_config)
        logger.info(" ScannerRegistry initialized")
        
        # Import and initialize PluginManager
        from backend.plugins.plugin_manager import PluginManager
        plugin_manager = PluginManager()
        logger.info(" PluginManager initialized")
        
        # Import and initialize ScannerEngine
        from backend.scanner_engine import ScannerEngine
        scanner_engine = ScannerEngine(plugin_manager)
        logger.info(" ScannerEngine initialized")
        
        # Attach to app state
        app.state.scanner_registry = scanner_registry
        app.state.scanner_engine = scanner_engine
        
        logger.info(" All components lazy-imported successfully")
        return True
        
    except Exception as e:
        logger.error(f" Lazy import failed: {e}", exc_info=True)
        return False

@app.on_event("startup")
async def startup_event():
    """Ultra-minimal startup - just set ready flag and defer everything else."""
    global backend_ready
    startup_start_time = datetime.now()
    logger.info(f" Starting ultra-minimal initialization at {startup_start_time}")
    
    try:
        # Set backend as ready immediately to allow API access
        backend_ready = True
        logger.info(" Backend marked as ready immediately - components will load on first API call")
        
        total_duration = (datetime.now() - startup_start_time).total_seconds()
        logger.info(f" Ultra-minimal startup complete in {total_duration:.2f}s")

    except Exception as e:
        total_duration = (datetime.now() - startup_start_time).total_seconds()
        logger.error(f" Startup failure after {total_duration:.2f}s: {e}", exc_info=True)
        
        # Set backend ready to allow health checks and debugging
        backend_ready = True
        logger.info(" Backend marked as ready for debugging despite startup issues")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global scanner_engine
    try:
        if scanner_engine:
            await scanner_engine.cleanup()
        logger.info("Application shutdown complete")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)

# Enhanced API router with fallback and lazy loading
@app.get("/api/scans/scanners")
async def list_scanners():
    """Enhanced scanners endpoint with lazy loading."""
    global scanner_registry, scanner_engine
    
    # Ensure components are loaded
    if not components_loaded and scanner_registry is None:
        success = lazy_import_components_sync()
        if success:
            await configure_engine_async()
    
    if scanner_registry:
        try:
            return scanner_registry.get_enhanced_scanner_metadata()
        except Exception as e:
            logger.error(f"Error getting scanner metadata: {e}")
            return {"error": "Scanner metadata unavailable", "scanners": {}}
    else:
        return {"minimal_scanner": {"name": "Basic Scanner", "description": "Minimal scanner for testing", "status": "available"}}

@app.get("/api/scans/")
async def get_scans():
    """Enhanced scans endpoint."""
    global scanner_engine
    
    if not components_loaded and scanner_registry is None:
        success = lazy_import_components_sync()
        if success:
            await configure_engine_async()
    
    if scanner_engine:
        try:
            return await scanner_engine.get_active_scans()
        except Exception as e:
            logger.error(f"Error getting active scans: {e}")
            return []
    else:
        return []

@app.post("/api/scans/start")
async def start_scan(scan_input: dict):
    """Enhanced scan start endpoint."""
    global scanner_engine
    
    if not components_loaded and scanner_registry is None:
        success = lazy_import_components_sync()
        if success:
            await configure_engine_async()
    
    if scanner_engine:
        try:
            from backend.config_types.models import ScanInput
            scan_obj = ScanInput(**scan_input)
            scan_id = await scanner_engine.start_scan(
                target=scan_obj.target,
                scan_type=scan_obj.scan_type,
                options=scan_obj.options or {}
            )
            return {"scan_id": scan_id, "status": "started"}
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            return {"error": str(e), "status": "failed"}
    else:
        return {"error": "Scanner engine not available", "status": "failed"}

# Include API router with fallback
try:
    from backend.api import router as api_router
    app.include_router(api_router, prefix="/api")
    logger.info("API router included successfully")
except Exception as e:
    logger.warning(f"Failed to include full API router: {e}")
    logger.info("Using enhanced fallback endpoints")

@app.get("/api/ready")
async def api_ready():
    """Endpoint to check if the backend is ready with diagnostic information."""
    global scanner_registry, scanner_engine, plugin_manager
    
    # Lazy initialize components on first API call if not already done
    if scanner_registry is None:
        logger.info("Lazy initializing components on first API call...")
        success = lazy_import_components_sync()
        if success:
            await configure_engine_async()
        if not success:
            return {
                "ready": False,
                "error": "Component initialization failed",
                "timestamp": datetime.now().isoformat(),
                "loading_in_progress": loading_in_progress
            }
    
    scanner_count = len(scanner_registry.get_all_scanners()) if scanner_registry else 0
    engine_configured = hasattr(scanner_engine, 'scanner_registry') and scanner_engine.scanner_registry is not None if scanner_engine else False
    
    status_info = {
        "ready": backend_ready,
        "scanner_count": scanner_count,
        "engine_configured": engine_configured,
        "timestamp": datetime.now().isoformat(),
        "diagnostics": {
            "scanner_registry_available": scanner_registry is not None,
            "scanner_engine_available": scanner_engine is not None,
            "plugin_manager_available": plugin_manager is not None,
            "components_lazy_loaded": scanner_registry is not None
        }
    }
    
    logger.info(f"API ready check: {status_info}")
    return status_info

# The following websocket endpoint is a duplicate and conflicts with the main API router.
# The correct endpoint is defined in backend/api/websocket.py and included via api_router.
#
# @app.websocket("/ws/{client_id}")
# async def websocket_endpoint(websocket: WebSocket, client_id: str):
#     print(f"WebSocket handler reached for client_id={client_id}")
#     await websocket.accept()
#     try:
#         while True:
#             try:
#                 data = await websocket.receive_text()
#                 print(f"Received from {client_id}: {data}")
#                 await websocket.send_text(f"Echo: {data}")
#             except WebSocketDisconnect:
#                 print(f"Client {client_id} disconnected")
#                 break
#             except Exception as e:
#                 print(f"Error in message loop: {e}")
#                 break
#     except Exception as e:
#         print(f"WebSocket outer error: {e}")

if __name__ == "__main__":
    import uvicorn
    host = getattr(settings, 'HOST', '0.0.0.0')
    port = int(getattr(settings, 'PORT', None) or 8000)
    debug = getattr(settings, 'DEBUG', True)
    
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=debug
    )
