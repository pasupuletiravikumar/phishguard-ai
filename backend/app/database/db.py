import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from app.schemas.scan import ScanResult, ScanHistorySummary, DashboardStats, Severity

DB_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "phishguard.db"))

class DatabaseService:
    """Local SQLite & persistent storage service for scans, history, and dashboard metrics."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    scan_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    input_preview TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    analysis_mode TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    full_result_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_scan(self, result: ScanResult, user_id: Optional[str] = "demo-user") -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO scans (
                        scan_id, user_id, scan_type, timestamp, input_preview,
                        risk_score, severity, analysis_mode, summary,
                        findings_json, full_result_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    user_id,
                    result.scan_type,
                    result.timestamp.isoformat(),
                    result.input_preview[:120],
                    result.risk_score,
                    result.severity.value,
                    result.analysis_mode,
                    result.summary,
                    json.dumps([f.model_dump() for f in result.findings]),
                    result.model_dump_json()
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving scan to DB: {e}")
            return False

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT full_result_json FROM scans WHERE scan_id = ?", (scan_id,))
                row = cursor.fetchone()
                if row:
                    data = json.loads(row["full_result_json"])
                    return ScanResult.model_validate(data)
                return None
        except Exception as e:
            print(f"Error retrieving scan: {e}")
            return None

    def delete_scan(self, scan_id: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting scan: {e}")
            return False

    def list_history(
        self,
        scan_type: Optional[str] = None,
        severity: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 50
    ) -> List[ScanHistorySummary]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                sql = "SELECT scan_id, timestamp, scan_type, input_preview, risk_score, severity, analysis_mode, summary, findings_json FROM scans WHERE 1=1"
                params = []
                if scan_type and scan_type != "ALL":
                    sql += " AND scan_type = ?"
                    params.append(scan_type.lower())
                if severity and severity != "ALL":
                    sql += " AND severity = ?"
                    params.append(severity.upper())
                if query:
                    sql += " AND (input_preview LIKE ? OR summary LIKE ?)"
                    params.extend([f"%{query}%", f"%{query}%"])

                sql += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(sql, params)
                rows = cursor.fetchall()
                history = []
                for r in rows:
                    findings = json.loads(r["findings_json"])
                    history.append(ScanHistorySummary(
                        scan_id=r["scan_id"],
                        timestamp=datetime.fromisoformat(r["timestamp"]),
                        scan_type=r["scan_type"],
                        input_preview=r["input_preview"],
                        risk_score=r["risk_score"],
                        severity=Severity(r["severity"]),
                        finding_count=len(findings),
                        analysis_mode=r["analysis_mode"],
                        summary=r["summary"]
                    ))
                return history
        except Exception as e:
            print(f"Error listing history: {e}")
            return []

    def get_dashboard_stats(self) -> DashboardStats:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT scan_id, scan_type, risk_score, severity, timestamp, findings_json FROM scans")
                rows = cursor.fetchall()

                total_scans = len(rows)
                low_cnt = sum(1 for r in rows if r["severity"] == "LOW")
                mod_cnt = sum(1 for r in rows if r["severity"] == "MODERATE")
                high_cnt = sum(1 for r in rows if r["severity"] == "HIGH")
                crit_cnt = sum(1 for r in rows if r["severity"] == "CRITICAL")

                type_counts = {"url": 0, "email": 0, "message": 0}
                for r in rows:
                    stype = r["scan_type"].lower()
                    type_counts[stype] = type_counts.get(stype, 0) + 1

                rule_freq: Dict[str, Dict[str, Any]] = {}
                for r in rows:
                    try:
                        f_list = json.loads(r["findings_json"])
                        for f in f_list:
                            rid = f.get("rule_id", "UNKNOWN")
                            title = f.get("title", rid)
                            sev = f.get("severity", "LOW")
                            if rid not in rule_freq:
                                rule_freq[rid] = {"rule_id": rid, "title": title, "severity": sev, "count": 0}
                            rule_freq[rid]["count"] += 1
                    except Exception:
                        pass

                top_rules = sorted(rule_freq.values(), key=lambda x: x["count"], reverse=True)[:5]

                # Trend over time (grouped by date)
                date_counts: Dict[str, Dict[str, int]] = {}
                for r in rows:
                    date_str = r["timestamp"][:10]
                    if date_str not in date_counts:
                        date_counts[date_str] = {"date": date_str, "scans": 0, "threats": 0}
                    date_counts[date_str]["scans"] += 1
                    if r["severity"] in ("HIGH", "CRITICAL"):
                        date_counts[date_str]["threats"] += 1

                recent_trend = sorted(date_counts.values(), key=lambda x: x["date"])[-7:]

                return DashboardStats(
                    total_scans=total_scans,
                    low_risk_count=low_cnt,
                    moderate_risk_count=mod_cnt,
                    high_risk_count=high_cnt,
                    critical_risk_count=crit_cnt,
                    scans_by_type=type_counts,
                    severity_distribution={"LOW": low_cnt, "MODERATE": mod_cnt, "HIGH": high_cnt, "CRITICAL": crit_cnt},
                    top_triggered_rules=top_rules,
                    recent_trend=recent_trend
                )
        except Exception as e:
            print(f"Error computing dashboard stats: {e}")
            return DashboardStats(
                total_scans=0, low_risk_count=0, moderate_risk_count=0,
                high_risk_count=0, critical_risk_count=0,
                scans_by_type={"url": 0, "email": 0, "message": 0},
                severity_distribution={"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0},
                top_triggered_rules=[], recent_trend=[]
            )

db_service = DatabaseService()
