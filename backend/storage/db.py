"""Storage and Persistence Layer for LOGFORGE ULPF using SQLite.
Guarantees zero-infrastructure air-gapped operation and fast querying.
"""
import sqlite3
import json
import os
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from backend.schema.models import UniversalEvent, FailedEvent, BatchProcessSummary

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logforge.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    conn.execute("PRAGMA mmap_size = 268435456;")
    return conn


def init_db():
    """Initialize database tables and indexes."""
    with get_db_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_vendor TEXT,
            source_device_type TEXT,
            hostname TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            action TEXT,
            severity TEXT,
            normalized_json TEXT NOT NULL,
            raw_event TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(destination_ip);
        CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
        CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_device_type ON events(source_device_type);

        CREATE TABLE IF NOT EXISTS failed_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            raw_event TEXT NOT NULL,
            reason TEXT NOT NULL,
            detected_format TEXT,
            parser_attempted TEXT
        );

        CREATE TABLE IF NOT EXISTS batch_jobs (
            batch_id TEXT PRIMARY KEY,
            total_events INTEGER,
            normalized_count INTEGER,
            failed_count INTEGER,
            processing_time_seconds REAL,
            events_per_second REAL,
            summary_json TEXT,
            created_at TEXT NOT NULL
        );
        """)
        conn.commit()


class EventStore:
    """High-performance repository for normalized events and forensic logs."""

    def __init__(self):
        init_db()

    def insert_batch(self, events: List[UniversalEvent]):
        if not events:
            return
        now_str = datetime.now(timezone.utc).isoformat()
        records = [
            (
                e.event_id,
                e.timestamp,
                e.source.vendor,
                e.source.device_type,
                e.source.hostname,
                e.network.source_ip,
                e.network.destination_ip,
                e.network.source_port,
                e.network.destination_port,
                e.network.protocol,
                e.event.action,
                e.event.severity,
                e.model_dump_json(),
                e.raw_event,
                now_str
            )
            for e in events
        ]
        with get_db_connection() as conn:
            conn.executemany("""
            INSERT OR REPLACE INTO events (
                event_id, timestamp, source_vendor, source_device_type, hostname,
                source_ip, destination_ip, source_port, destination_port, protocol,
                action, severity, normalized_json, raw_event, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()

    def insert_failed_batch(self, failed_events: List[FailedEvent]):
        if not failed_events:
            return
        records = [
            (f.event_id, f.timestamp, f.raw_event, f.reason, f.detected_format, f.parser_attempted)
            for f in failed_events
        ]
        with get_db_connection() as conn:
            conn.executemany("""
            INSERT OR REPLACE INTO failed_events (
                event_id, timestamp, raw_event, reason, detected_format, parser_attempted
            ) VALUES (?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()

    def record_batch_job(self, summary: BatchProcessSummary):
        now_str = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            conn.execute("""
            INSERT OR REPLACE INTO batch_jobs (
                batch_id, total_events, normalized_count, failed_count,
                processing_time_seconds, events_per_second, summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                summary.batch_id,
                summary.total_events,
                summary.normalized_count,
                summary.failed_count,
                summary.processing_time_seconds,
                summary.events_per_second,
                summary.model_dump_json(),
                now_str
            ))
            conn.commit()

    def query_events(
        self,
        page: int = 1,
        page_size: int = 50,
        search: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        device_type: Optional[str] = None,
        vendor: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        conditions = []
        params = []

        if search:
            s_param = f"%{search.strip()}%"
            conditions.append("""(
                event_id LIKE ? OR
                source_ip LIKE ? OR
                destination_ip LIKE ? OR
                protocol LIKE ? OR
                action LIKE ? OR
                source_vendor LIKE ? OR
                raw_event LIKE ?
            )""")
            params.extend([s_param] * 7)

        if source_ip:
            conditions.append("source_ip = ?")
            params.append(source_ip.strip())

        if destination_ip:
            conditions.append("destination_ip = ?")
            params.append(destination_ip.strip())

        if protocol:
            conditions.append("UPPER(protocol) = ?")
            params.append(protocol.strip().upper())

        if action:
            conditions.append("LOWER(action) = ?")
            params.append(action.strip().lower())

        if severity:
            conditions.append("LOWER(severity) = ?")
            params.append(severity.strip().lower())

        if device_type:
            conditions.append("LOWER(source_device_type) = ?")
            params.append(device_type.strip().lower())

        if vendor:
            conditions.append("LOWER(source_vendor) = ?")
            params.append(vendor.strip().lower())

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        with get_db_connection() as conn:
            # Count total matching
            count_cur = conn.execute(f"SELECT COUNT(*) FROM events {where_clause}", params)
            total = count_cur.fetchone()[0]

            # Fetch paginated rows
            offset = (page - 1) * page_size
            query = f"""
            SELECT normalized_json, raw_event FROM events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
            """
            rows = conn.execute(query, params + [page_size, offset]).fetchall()
            events = [json.loads(r["normalized_json"]) for r in rows]

            return events, total

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        with get_db_connection() as conn:
            row = conn.execute("SELECT normalized_json FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if row:
                return json.loads(row["normalized_json"])
            return None

    def get_analytics(self) -> Dict[str, Any]:
        with get_db_connection() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_failed = conn.execute("SELECT COUNT(*) FROM failed_events").fetchone()[0]

            # Top Source IPs
            top_src_ips = conn.execute("""
                SELECT source_ip, COUNT(*) as cnt FROM events
                WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip ORDER BY cnt DESC LIMIT 7
            """).fetchall()

            # Top Destination IPs
            top_dst_ips = conn.execute("""
                SELECT destination_ip, COUNT(*) as cnt FROM events
                WHERE destination_ip IS NOT NULL AND destination_ip != ''
                GROUP BY destination_ip ORDER BY cnt DESC LIMIT 7
            """).fetchall()

            # Protocols
            protocols = conn.execute("""
                SELECT UPPER(COALESCE(protocol, 'OTHER')) as proto, COUNT(*) as cnt
                FROM events GROUP BY proto ORDER BY cnt DESC LIMIT 6
            """).fetchall()

            # Actions
            actions = conn.execute("""
                SELECT LOWER(COALESCE(action, 'unknown')) as act, COUNT(*) as cnt
                FROM events GROUP BY act ORDER BY cnt DESC
            """).fetchall()

            # Severities
            severities = conn.execute("""
                SELECT LOWER(COALESCE(severity, 'informational')) as sev, COUNT(*) as cnt
                FROM events GROUP BY sev ORDER BY cnt DESC
            """).fetchall()

            # Device Types
            devices = conn.execute("""
                SELECT COALESCE(source_device_type, 'other') as dev, COUNT(*) as cnt
                FROM events GROUP BY dev ORDER BY cnt DESC
            """).fetchall()

            # Recent Batches
            recent_batches = conn.execute("""
                SELECT batch_id, total_events, normalized_count, failed_count,
                       events_per_second, processing_time_seconds, created_at
                FROM batch_jobs ORDER BY created_at DESC LIMIT 5
            """).fetchall()

            return {
                "total_events": total_events,
                "normalized_events": total_events,
                "failed_events": total_failed,
                "active_sources": len(devices),
                "top_source_ips": [{"ip": r["source_ip"], "count": r["cnt"]} for r in top_src_ips],
                "top_destination_ips": [{"ip": r["destination_ip"], "count": r["cnt"]} for r in top_dst_ips],
                "protocols": [{"protocol": r["proto"], "count": r["cnt"]} for r in protocols],
                "actions": [{"action": r["act"], "count": r["cnt"]} for r in actions],
                "severities": [{"severity": r["sev"], "count": r["cnt"]} for r in severities],
                "device_types": [{"device_type": r["dev"], "count": r["cnt"]} for r in devices],
                "recent_batches": [dict(r) for r in recent_batches]
            }

    def get_all_for_export(self, limit: int = 50000) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT normalized_json FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [json.loads(r["normalized_json"]) for r in rows]

    def get_failed_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM failed_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def clear_database(self):
        with get_db_connection() as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM failed_events")
            conn.execute("DELETE FROM batch_jobs")
            conn.commit()


store = EventStore()
