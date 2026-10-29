import os
import json
from datetime import datetime
from fastapi import APIRouter
from app.core.config import settings
from app.database.db import db_service

router = APIRouter()
START_TIME = datetime.utcnow()

@router.get("/health")
async def health_check():
    """Health check endpoint indicating service status, ML model readiness, and storage status."""
    ml_available = os.path.exists(settings.ml_model_path)
    metrics_data = None
    if os.path.exists(settings.ml_metrics_path):
        try:
            with open(settings.ml_metrics_path, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception:
            metrics_data = None

    # Test database connectivity
    db_ok = True
    try:
        db_service.get_dashboard_stats()
    except Exception:
        db_ok = False

    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.env,
        "uptime_seconds": round((datetime.utcnow() - START_TIME).total_seconds(), 1),
        "database_connected": db_ok,
        "machine_learning": {
            "model_loaded": ml_available,
            "model_path": settings.ml_model_path if ml_available else None,
            "metrics": metrics_data
        },
        "threat_intelligence": {
            "virustotal_configured": bool(settings.virustotal_api_key),
            "google_safebrowsing_configured": bool(settings.safe_browsing_api_key)
        }
    }
