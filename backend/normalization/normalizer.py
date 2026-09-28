"""Configurable Field Normalization Engine for LOGFORGE ULPF.
Transforms vendor-specific and format-specific attributes into the Universal Event Schema.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import re
from backend.schema.models import UniversalEvent, SourceInfo, EventInfo, NetworkInfo, ProcessingMetadata

# Mapping dictionaries
IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

ACTION_MAPPINGS = {
    # Allow variants
    "allow": "allow",
    "permit": "allow",
    "pass": "allow",
    "accept": "allow",
    "built": "allow",
    "allowed": "allow",
    "success": "allow",
    "connected": "allow",
    # Deny/Block variants
    "deny": "deny",
    "drop": "deny",
    "block": "deny",
    "blocked": "deny",
    "reject": "deny",
    "teardown": "deny",
    "reset": "deny",
    "failed": "deny",
    # Alert variants
    "alert": "alert",
    "warn": "alert",
    "warning": "alert",
    "flagged": "alert",
}

SEVERITY_MAPPINGS = {
    # Text strings
    "emergency": "critical",
    "emerg": "critical",
    "alert": "critical",
    "critical": "critical",
    "crit": "critical",
    "error": "high",
    "err": "high",
    "high": "high",
    "warning": "medium",
    "warn": "medium",
    "medium": "medium",
    "med": "medium",
    "notice": "low",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "debug": "informational",
}

PROTOCOL_NUMBERS = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "IPv6-ICMP",
}

SOURCE_IP_FIELDS = [
    "src", "src_ip", "srcip", "sourceaddress", "sourceip", "src_addr", "source", 
    "c-ip", "source_address", "s_ip", "src_host"
]

DEST_IP_FIELDS = [
    "dst", "dst_ip", "dstip", "destinationaddress", "destinationip", "dst_addr", 
    "destination", "cs-ip", "dest_address", "d_ip", "dest_ip", "target_ip"
]

SOURCE_PORT_FIELDS = ["sport", "spt", "src_port", "sourceport", "srcport", "s_port"]
DEST_PORT_FIELDS = ["dport", "dpt", "dst_port", "destinationport", "dstport", "d_port", "target_port"]

PROTOCOL_FIELDS = ["proto", "protocol", "app_proto", "transport", "trans_protocol"]
ACTION_FIELDS = ["action", "act", "status", "decision", "event_action", "result"]
SEVERITY_FIELDS = ["severity", "severity_code", "pri", "level", "cef_severity", "priority"]


def parse_timestamp_safe(ts_str: Any) -> str:
    """Safely convert various timestamp formats to standard ISO-8601 UTC."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()
        
    ts_str = str(ts_str).strip()
    
    # Try ISO formats
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        pass

    # Try Syslog BSD formats (e.g. Sep 28 14:15:00 or Sep 28 14:15:00 2026)
    for fmt in ("%b %d %H:%M:%S", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            pass

    # Try Unix epoch (seconds or milliseconds)
    try:
        val = float(ts_str)
        if val > 1e11:  # milliseconds
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except Exception:
        pass

    return datetime.now(timezone.utc).isoformat()


class EventNormalizer:
    """Normalizes extracted raw parser dictionary into standard UniversalEvent."""

    def normalize(
        self,
        extracted: Dict[str, Any],
        raw_line: str,
        parser_name: str,
        source_format: str,
        confidence: float,
        duration_ms: float
    ) -> UniversalEvent:
        
        # 1. Network Field Extraction & Normalization
        source_ip = None
        for f in SOURCE_IP_FIELDS:
            if f in extracted and extracted[f]:
                val = str(extracted[f]).strip()
                if IP_REGEX.match(val):
                    source_ip = val
                    break

        dest_ip = None
        for f in DEST_IP_FIELDS:
            if f in extracted and extracted[f]:
                val = str(extracted[f]).strip()
                if IP_REGEX.match(val):
                    dest_ip = val
                    break

        source_port = None
        for f in SOURCE_PORT_FIELDS:
            if f in extracted and extracted[f]:
                try:
                    p = int(extracted[f])
                    if 1 <= p <= 65535:
                        source_port = p
                        break
                except (ValueError, TypeError):
                    pass

        dest_port = None
        for f in DEST_PORT_FIELDS:
            if f in extracted and extracted[f]:
                try:
                    p = int(extracted[f])
                    if 1 <= p <= 65535:
                        dest_port = p
                        break
                except (ValueError, TypeError):
                    pass

        # Protocol
        raw_proto = None
        for f in PROTOCOL_FIELDS:
            if f in extracted and extracted[f]:
                raw_proto = str(extracted[f]).strip()
                break

        protocol = None
        if raw_proto:
            raw_proto_upper = raw_proto.upper()
            if raw_proto in PROTOCOL_NUMBERS:
                protocol = PROTOCOL_NUMBERS[raw_proto]
            elif raw_proto_upper in ("TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH", "TLS", "IP"):
                protocol = raw_proto_upper
            else:
                protocol = raw_proto_upper

        # 2. Action Normalization
        raw_action = None
        for f in ACTION_FIELDS:
            if f in extracted and extracted[f]:
                raw_action = str(extracted[f]).strip().lower()
                break

        action = "unknown"
        if raw_action:
            action = ACTION_MAPPINGS.get(raw_action, raw_action)

        # 3. Severity Normalization
        raw_sev = None
        for f in SEVERITY_FIELDS:
            if f in extracted and extracted[f] is not None:
                raw_sev = extracted[f]
                break

        severity = "informational"
        if raw_sev is not None:
            sev_str = str(raw_sev).strip().lower()
            if sev_str.isdigit():
                code = int(sev_str)
                # Syslog severity (0=Emergency to 7=Debug)
                if code in (0, 1):
                    severity = "critical"
                elif code in (2, 3):
                    severity = "high"
                elif code == 4:
                    severity = "medium"
                elif code == 5:
                    severity = "low"
                else:
                    severity = "informational"
            else:
                severity = SEVERITY_MAPPINGS.get(sev_str, "medium" if "alert" in sev_str else "informational")

        # 4. Source & Device Normalization
        vendor = extracted.get("vendor", "Generic")
        device_type = extracted.get("device_type", "network_device")
        hostname = extracted.get("hostname") or extracted.get("host") or extracted.get("devname")
        device_ip = extracted.get("ip") or extracted.get("device_ip")

        # 5. Timestamp Normalization
        raw_ts = extracted.get("timestamp") or extracted.get("rt") or extracted.get("time") or extracted.get("date")
        normalized_timestamp = parse_timestamp_safe(raw_ts)

        # 6. Construct Metadata
        metadata = ProcessingMetadata(
            schema_version="1.0",
            parser=parser_name,
            source_format=source_format,
            confidence=round(confidence, 2),
            processing_time_ms=round(duration_ms, 3),
            tags=[source_format.lower(), device_type]
        )

        # 7. Construct Universal Event
        return UniversalEvent(
            timestamp=normalized_timestamp,
            source=SourceInfo(
                vendor=vendor,
                device_type=device_type,
                hostname=hostname,
                ip=device_ip
            ),
            event=EventInfo(
                category="network",
                type=extracted.get("event_name") or extracted.get("event_type") or "connection",
                action=action,
                severity=severity
            ),
            network=NetworkInfo(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=source_port,
                destination_port=dest_port,
                protocol=protocol,
                bytes_sent=extracted.get("bytes_sent") or extracted.get("out") or extracted.get("sentbyte"),
                bytes_received=extracted.get("bytes_received") or extracted.get("in") or extracted.get("rcvdbyte"),
                packets=extracted.get("packets")
            ),
            metadata=metadata,
            raw_event=raw_line.strip()
        )


normalizer = EventNormalizer()
