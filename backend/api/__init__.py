from fastapi import APIRouter
from .scans import router as scans_router
from .websocket import router as websocket_router
from .reports import router as reports_router
from .site_preview import router as preview_router
from .metrics import router as metrics_router

router = APIRouter()

router.include_router(scans_router, prefix="/scans", tags=["scans"])
router.include_router(websocket_router, tags=["websocket"])
router.include_router(reports_router, prefix="/reports", tags=["reports"])
router.include_router(preview_router, prefix="/preview", tags=["preview"])
# Backward-compatible alias to match existing frontend calls
router.include_router(preview_router, prefix="/site_preview", tags=["preview"])
router.include_router(metrics_router, prefix="/metrics", tags=["metrics"])
