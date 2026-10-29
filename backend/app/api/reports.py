from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel
from typing import Optional
from app.database.db import db_service
from app.services.report_generator import ReportGenerator

router = APIRouter()

class ExportRequest(BaseModel):
    format: str = "json"  # "json" or "html"
    redact_sensitive: Optional[bool] = False

@router.get("/reports/{scan_id}")
async def get_report_data(scan_id: str):
    """Retrieve structured security assessment report data."""
    scan = db_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
    return ReportGenerator.generate_json_report(scan)

@router.post("/reports/{scan_id}/export")
async def export_report(scan_id: str, request: ExportRequest):
    """Export security report in JSON or HTML/Printable PDF format."""
    scan = db_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")

    if request.format.lower() == "html":
        html_content = ReportGenerator.generate_printable_html(scan)
        return Response(
            content=html_content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=phishguard-report-{scan_id[:8]}.html"}
        )
    else:
        json_data = ReportGenerator.generate_json_report(scan)
        return json_data
