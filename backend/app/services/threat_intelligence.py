import os
import time
import httpx
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from app.schemas.scan import ThreatIntelResult
from app.core.config import settings

# In-memory simple cache for threat intel queries: {indicator: (result, timestamp)}
_INTEL_CACHE: Dict[str, Tuple[ThreatIntelResult, float]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour

class ThreatIntelligenceService:
    """External threat intelligence connector with local fallback."""

    def __init__(self):
        self.vt_key = settings.virustotal_api_key
        self.gsb_key = settings.safe_browsing_api_key

    async def query_url(self, url: str) -> List[ThreatIntelResult]:
        results: List[ThreatIntelResult] = []

        # 1. VirusTotal Lookup
        vt_res = await self._check_virustotal(url)
        results.append(vt_res)

        # 2. Google Safe Browsing Lookup
        gsb_res = await self._check_google_safebrowsing(url)
        results.append(gsb_res)

        # 3. Local High-Risk Threat DB (Always available, deterministic local heuristics)
        local_res = self._check_local_reputation(url)
        results.append(local_res)

        return results

    async def _check_virustotal(self, url: str) -> ThreatIntelResult:
        if not self.vt_key:
            return ThreatIntelResult(
                provider="VirusTotal v3",
                status="NOT_CONFIGURED",
                indicator=url,
                verdict="UNCHECKED",
                is_live=False,
                details="VirusTotal API key is not configured in server environment (VIRUSTOTAL_API_KEY). Live query skipped."
            )

        # Check cache
        cache_key = f"vt:{url}"
        now = time.time()
        if cache_key in _INTEL_CACHE:
            cached_res, cached_time = _INTEL_CACHE[cache_key]
            if now - cached_time < CACHE_TTL_SECONDS:
                return cached_res

        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.vt_key}

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    status = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
                    result = ThreatIntelResult(
                        provider="VirusTotal v3",
                        status=status,
                        indicator=url,
                        verdict=f"{malicious}/{total} security vendors flagged this URL as malicious",
                        positives=malicious,
                        total_engines=total,
                        is_live=True,
                        details=f"Live VirusTotal API query completed. Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {stats.get('harmless', 0)}."
                    )
                    _INTEL_CACHE[cache_key] = (result, now)
                    return result
                elif resp.status_code == 429:
                    return ThreatIntelResult(
                        provider="VirusTotal v3",
                        status="RATE_LIMITED",
                        indicator=url,
                        verdict="RATE_LIMITED",
                        is_live=False,
                        details="VirusTotal API request rate limit exceeded (429). Using heuristic results."
                    )
                else:
                    return ThreatIntelResult(
                        provider="VirusTotal v3",
                        status="UNAVAILABLE",
                        indicator=url,
                        verdict="ERROR",
                        is_live=False,
                        details=f"VirusTotal lookup returned HTTP {resp.status_code}."
                    )
        except Exception as e:
            return ThreatIntelResult(
                provider="VirusTotal v3",
                status="UNAVAILABLE",
                indicator=url,
                verdict="TIMEOUT_OR_NETWORK_ERROR",
                is_live=False,
                details=f"Network error querying VirusTotal: {str(e)[:100]}"
            )

    async def _check_google_safebrowsing(self, url: str) -> ThreatIntelResult:
        if not self.gsb_key:
            return ThreatIntelResult(
                provider="Google Safe Browsing v4",
                status="NOT_CONFIGURED",
                indicator=url,
                verdict="UNCHECKED",
                is_live=False,
                details="Google Safe Browsing API key not configured (SAFE_BROWSING_API_KEY). Live query skipped."
            )

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}"
        payload = {
            "client": {"clientId": "phishguard-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_types = [m.get("threatType") for m in matches]
                        return ThreatIntelResult(
                            provider="Google Safe Browsing v4",
                            status="MALICIOUS",
                            indicator=url,
                            verdict=f"Flagged as {', '.join(threat_types)}",
                            positives=len(matches),
                            total_engines=1,
                            is_live=True,
                            details=f"Google Safe Browsing match: URL found in threat list ({', '.join(threat_types)})."
                        )
                    else:
                        return ThreatIntelResult(
                            provider="Google Safe Browsing v4",
                            status="CLEAN",
                            indicator=url,
                            verdict="No threat detected",
                            positives=0,
                            total_engines=1,
                            is_live=True,
                            details="URL is not currently listed in Google Safe Browsing threat databases."
                        )
                else:
                    return ThreatIntelResult(
                        provider="Google Safe Browsing v4",
                        status="UNAVAILABLE",
                        indicator=url,
                        verdict="ERROR",
                        is_live=False,
                        details=f"Safe Browsing query failed with HTTP {resp.status_code}."
                    )
        except Exception as e:
            return ThreatIntelResult(
                provider="Google Safe Browsing v4",
                status="UNAVAILABLE",
                indicator=url,
                verdict="TIMEOUT_OR_NETWORK_ERROR",
                is_live=False,
                details=f"Safe Browsing lookup failed: {str(e)[:100]}"
            )

    def _check_local_reputation(self, url: str) -> ThreatIntelResult:
        """Local reputation engine (always available, verified local signatures)."""
        lower = url.lower()
        known_phish_indicators = [
            "paypal-verify-login", "secure-chase-update", "appleid-icloud-security",
            "microsoft365-login-auth", "dhl-redelivery-fee", "usps-package-confirm"
        ]
        is_flagged = any(k in lower for k in known_phish_indicators)
        if is_flagged:
            return ThreatIntelResult(
                provider="PhishGuard Local Threat Signature DB",
                status="MALICIOUS",
                indicator=url,
                verdict="Matches known phishing campaign URL pattern",
                positives=1,
                total_engines=1,
                is_live=True,
                details="URL matches high-confidence local heuristic signatures and targeted impersonation seeds."
            )
        else:
            return ThreatIntelResult(
                provider="PhishGuard Local Threat Signature DB",
                status="CLEAN",
                indicator=url,
                verdict="No known local blacklist matches",
                positives=0,
                total_engines=1,
                is_live=True,
                details="Local signature engine found no explicit match in local phishing database."
            )
