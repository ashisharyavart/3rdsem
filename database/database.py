"""
CyberGuard Desktop - SQLite Database Manager
Provides connection handling, schema migrations, and secure local persistence.
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional
from config import APP_CONFIG
from utils.logger import logger


class DatabaseManager:
    """
    Manages SQLite database connections and table creation.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or APP_CONFIG.database_path
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables on first application launch."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        severity TEXT NOT NULL,
                        categories TEXT NOT NULL,
                        explanation TEXT NOT NULL,
                        domain TEXT,
                        monitor_id INTEGER DEFAULT 1
                    );
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_threat_timestamp
                    ON threat_events (timestamp DESC);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_threat_severity
                    ON threat_events (severity);
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Error initializing SQLite database: {e}")

