"""
CyberGuard Desktop - Threat History Repository
Performs CRUD operations on local SQLite threat history with strict privacy controls.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
import json

from database.database import DatabaseManager
from utils.privacy import redact_sensitive_info
from utils.logger import logger


class ThreatHistoryRepository:
    """
    Handles storage and retrieval of detected threat events without retaining
    screenshots or unredacted raw credentials.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def insert_threat(
        self,
        score: int,
        severity: str,
        categories: List[str],
        explanation: str,
        domain: Optional[str] = None,
        monitor_id: int = 1
    ) -> Optional[int]:
        """
        Inserts a sanitized threat event.
        Screenshots and raw OCR texts are deliberately not recorded.
        """
        # Redact potential sensitive tokens in the explanation
        sanitized_explanation = redact_sensitive_info(explanation)
        cat_str = ", ".join(categories) if isinstance(categories, list) else str(categories)
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        query = """
            INSERT INTO threat_events (timestamp, score, severity, categories, explanation, domain, monitor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    query,
                    (timestamp_str, score, severity, cat_str, sanitized_explanation, domain, monitor_id)
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error persisting threat history: {e}")
            return None

    def get_recent_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent threats ordered by latest first."""
        query = """
            SELECT id, timestamp, score, severity, categories, explanation, domain, monitor_id
            FROM threat_events
            ORDER BY id DESC
            LIMIT ?
        """
        results = []
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (limit,))
                for row in cursor.fetchall():
                    results.append({
                        "id": row["id"],
                        "timestamp": row["timestamp"],
                        "score": row["score"],
                        "severity": row["severity"],
                        "categories": row["categories"],
                        "explanation": row["explanation"],
                        "domain": row["domain"],
                        "monitor_id": row["monitor_id"]
                    })
        except Exception as e:
            logger.error(f"Error retrieving threat history: {e}")
        return results

    def clear_history(self) -> bool:
        """Purge all recorded threat records."""
        query = "DELETE FROM threat_events;"
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error clearing threat history: {e}")
            return False

    def get_threat_counts(self) -> Dict[str, int]:
        """Aggregate detection counts by severity."""
        query = """
            SELECT severity, COUNT(*) as cnt
            FROM threat_events
            GROUP BY severity
        """
        counts = {"total": 0, "Critical": 0, "High": 0, "Suspicious": 0, "Low": 0}
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                for row in cursor.fetchall():
                    sev = row["severity"].capitalize()
                    cnt = row["cnt"]
                    if sev in counts:
                        counts[sev] = cnt
                    counts["total"] += cnt
        except Exception as e:
            logger.error(f"Error counting threat events: {e}")
        return counts

