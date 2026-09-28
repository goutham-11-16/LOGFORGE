"""Export and SIEM/Data Lake/ML Integration Layer for LOGFORGE ULPF.
Enhanced with threat intelligence fields, user/process context,
and STIX-compatible JSON export option.
"""
import json
import csv
import io
from typing import List, Dict, Any
from backend.storage.db import store


class DataExporter:
    """Exports normalized events in standard enterprise, big-data, and AI/ML formats."""

    @staticmethod
    def export_jsonl(events: List[Dict[str, Any]]) -> str:
        """Export as newline-delimited JSON for BigQuery, Elasticsearch, and SIEM ingestion."""
        output = io.StringIO()
        for evt in events:
            output.write(json.dumps(evt, default=str) + "\n")
        return output.getvalue()

    @staticmethod
    def export_json(events: List[Dict[str, Any]]) -> str:
        """Export as pretty formatted JSON array."""
        return json.dumps(events, indent=2, default=str)

    @staticmethod
    def export_csv(events: List[Dict[str, Any]]) -> str:
        """Export flat tabular representation suitable for Pandas, Spark, and ML model training."""
        output = io.StringIO()
        fieldnames = [
            "event_id", "timestamp", "vendor", "device_type", "hostname",
            "category", "event_type", "action", "severity",
            "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
            "bytes_sent", "bytes_received",
            "threat_detected", "threat_type", "mitre_technique_id", "risk_score",
            "geo_source", "geo_destination",
            "user", "process",
            "parser", "source_format", "confidence", "raw_event"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for evt in events:
            src = evt.get("source", {})
            event_sec = evt.get("event", {})
            net = evt.get("network", {})
            meta = evt.get("metadata", {})
            threat = evt.get("threat_intel", {})
            user_ctx = evt.get("user", {})
            proc_ctx = evt.get("process", {})

            writer.writerow({
                "event_id": evt.get("event_id"),
                "timestamp": evt.get("timestamp"),
                "vendor": src.get("vendor"),
                "device_type": src.get("device_type"),
                "hostname": src.get("hostname"),
                "category": event_sec.get("category"),
                "event_type": event_sec.get("type"),
                "action": event_sec.get("action"),
                "severity": event_sec.get("severity"),
                "source_ip": net.get("source_ip"),
                "destination_ip": net.get("destination_ip"),
                "source_port": net.get("source_port"),
                "destination_port": net.get("destination_port"),
                "protocol": net.get("protocol"),
                "bytes_sent": net.get("bytes_sent"),
                "bytes_received": net.get("bytes_received"),
                "threat_detected": threat.get("threat_detected", False),
                "threat_type": threat.get("threat_type"),
                "mitre_technique_id": threat.get("mitre_technique_id"),
                "risk_score": threat.get("risk_score", 0),
                "geo_source": threat.get("geo_source"),
                "geo_destination": threat.get("geo_destination"),
                "user": user_ctx.get("name") if isinstance(user_ctx, dict) else str(user_ctx) if user_ctx else "",
                "process": proc_ctx.get("name") if isinstance(proc_ctx, dict) else str(proc_ctx) if proc_ctx else "",
                "parser": meta.get("parser"),
                "source_format": meta.get("source_format"),
                "confidence": meta.get("confidence"),
                "raw_event": evt.get("raw_event")
            })

        return output.getvalue()

    @staticmethod
    def export_failed_csv(failed: List[Dict[str, Any]]) -> str:
        """Export quarantined/failed logs for forensic analysis."""
        output = io.StringIO()
        fieldnames = ["event_id", "timestamp", "reason", "detected_format", "parser_attempted", "raw_event"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for f in failed:
            writer.writerow({k: f.get(k) for k in fieldnames})
        return output.getvalue()


exporter = DataExporter()
