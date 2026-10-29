import os
from typing import List
from pydantic import BaseModel

class Settings(BaseModel):
    app_name: str = "PhishGuard AI — Phishing Detection Platform"
    app_version: str = "1.0.0"
    api_prefix: str = "/api"
    env: str = os.getenv("ENVIRONMENT", "development")
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ]
    
    # Machine Learning configuration
    ml_model_path: str = os.getenv("ML_MODEL_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models", "phishing_url_rf.joblib")))
    ml_metrics_path: str = os.getenv("ML_METRICS_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml", "models", "metrics.json")))

    # External Threat Intel API Keys (Optional)
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    safe_browsing_api_key: str = os.getenv("SAFE_BROWSING_API_KEY", "")

    # Database & Auth (Optional Supabase)
    supabase_url: str = os.getenv("SUPABASE_URL", "")
    supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    # Security settings
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    max_payload_length: int = int(os.getenv("MAX_PAYLOAD_LENGTH", "150000"))

settings = Settings()
