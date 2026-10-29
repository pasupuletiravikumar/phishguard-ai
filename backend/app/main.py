from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from app.core.config import settings
from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.api.reports import router as reports_router

# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("phishguard")

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Production-grade AI-powered phishing, URL, email, and social engineering threat detection platform.",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global Request Size & Security Middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Enforce content-length limit
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_payload_length:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Submitted payload exceeds the maximum permitted size limit (150 KB)."}
        )

    try:
        response = await call_next(request)
        # Apply secure HTTP headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
    except Exception as exc:
        logger.error(f"Unhandled server error: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred while processing the security scan."}
        )

# Register routes
app.include_router(health_router, tags=["Health"])
app.include_router(scan_router, prefix=settings.api_prefix, tags=["Scanning & Detection"])
app.include_router(reports_router, prefix=settings.api_prefix, tags=["Reports & Export"])

@app.get("/")
async def root():
    return {
        "platform": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/health",
        "status": "operational"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
