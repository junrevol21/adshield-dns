"""
SQLite Persistent Storage and Analytics for AdShield DNS
High-performance asynchronous batch writer for query logs and historical analytics.
"""

import os
import sqlite3
import threading
import queue
import time
from typing import List, Dict, Optional

class QueryDatabase:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "adshield.db")
        self.write_queue = queue.Queue(maxsize=10000)
        self.running = True

        self._init_db()

        # Start asynchronous batch writer thread
        self.writer_thread = threading.Thread(target=self._writer_worker, name="DB-Writer-Worker", daemon=True)
        self.writer_thread.start()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS query_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                time_str TEXT,
                client_ip TEXT,
                client_name TEXT,
                domain TEXT,
                qtype TEXT,
                status TEXT,
                duration_ms REAL,
                date_day TEXT
            )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_time ON query_logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON query_logs(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_client ON query_logs(client_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON query_logs(status)")
            conn.commit()

    def log_query_async(self, client_ip: str, client_name: str, domain: str, qtype: str, status: str, duration_ms: float):
        """Non-blocking query push to batch queue."""
        now = time.time()
        time_str = time.strftime("%H:%M:%S")
        date_day = time.strftime("%Y-%m-%d")
        item = (now, time_str, client_ip, client_name, domain, qtype, status, duration_ms, date_day)
        try:
            self.write_queue.put_nowait(item)
        except queue.Full:
            pass # Drop under extreme flood to preserve memory

    def _writer_worker(self):
        """Asynchronous batch worker that writes to SQLite every 2s or 50 items."""
        conn = self._get_connection()
        while self.running:
            batch = []
            try:
                # Wait for at least one item
                item = self.write_queue.get(timeout=2.0)
                batch.append(item)
                # Drain remaining available items up to 100
                while len(batch) < 100:
                    try:
                        batch.append(self.write_queue.get_nowait())
                    except queue.Empty:
                        break
            except queue.Empty:
                pass

            if batch:
                try:
                    conn.executemany("""
                    INSERT INTO query_logs (timestamp, time_str, client_ip, client_name, domain, qtype, status, duration_ms, date_day)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    conn.commit()
                except Exception as e:
                    print(f"[QueryDatabase] Batch write error: {e}")

        try:
            conn.close()
        except Exception:
            pass

    def get_recent_logs(self, limit: int = 100, filter_type: str = "ALL", search: str = "") -> List[Dict]:
        """Fetch latest queries from persistent storage."""
        query = "SELECT time_str, client_ip, client_name, domain, qtype, status, duration_ms FROM query_logs WHERE 1=1"
        params = []

        if filter_type == "BLOCKED":
            query += " AND status = 'BLOCKED'"
        elif filter_type == "ALLOWED":
            query += " AND status IN ('FORWARDED', 'CACHED', 'STALE_CACHE', 'REWRITE')"

        if search:
            query += " AND (domain LIKE ? OR client_ip LIKE ? OR client_name LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return [
                {
                    "time": r["time_str"],
                    "client": r["client_ip"],
                    "client_name": r["client_name"] or r["client_ip"],
                    "domain": r["domain"],
                    "type": r["qtype"],
                    "status": r["status"],
                    "duration": r["duration_ms"]
                }
                for r in rows
            ]

    def get_summary_stats(self) -> Dict:
        """Get aggregate counts from database."""
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM query_logs")
            total = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM query_logs WHERE status = 'BLOCKED'")
            blocked = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM query_logs WHERE status = 'CACHED'")
            cached = c.fetchone()[0]

            c.execute("SELECT AVG(duration_ms) FROM query_logs")
            avg_dur = c.fetchone()[0] or 0.0

            return {
                "total_queries": total,
                "blocked_queries": blocked,
                "cached_queries": cached,
                "avg_latency_ms": round(avg_dur, 2)
            }

    def close(self):
        self.running = False
