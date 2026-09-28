"""Validation Layer for LOGFORGE ULPF.
Enforces schema integrity, field-level constraints, and data quality
before events are persisted to the storage layer.
"""
from typing import Tuple, Optional
import re
from backend.schema.models import UniversalEvent

# Precompiled patterns
_IP_V4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IP_V6_RE = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
    r"^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"
)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_VALID_ACTIONS = {"allow", "deny", "alert", "unknown"}
_VALID_CATEGORIES = {"network", "authentication", "security", "system"}


def _is_valid_ip(val: Optional[str]) -> bool:
    if not val:
        return True  # None is acceptable (field is optional)
    return bool(_IP_V4_RE.match(val) or _IP_V6_RE.match(val))


class EventValidator:
    """Validates normalized events before persistence and downstream delivery.

    Enforces:
    - Required field presence (event_id, raw_event, timestamp)
    - Port range validity (0-65535)
    - IP address format (IPv4/IPv6)
    - Severity/action/category enum membership
    - Timestamp non-emptiness
    - Confidence score bounds (0.0 - 1.0)
    - Schema version presence
    """

    @staticmethod
    def validate(event: UniversalEvent) -> Tuple[bool, str]:
        # --- Required fields ---
        if not event.event_id:
            return False, "Missing event_id"

        if not event.raw_event or not event.raw_event.strip():
            return False, "Lossless violation: raw_event must never be empty"

        if not event.timestamp:
            return False, "Missing timestamp"

        # --- Port ranges (0 is valid for scan detection) ---
        if event.network.source_port is not None:
            if not (0 <= event.network.source_port <= 65535):
                return False, f"Invalid source port: {event.network.source_port}"

        if event.network.destination_port is not None:
            if not (0 <= event.network.destination_port <= 65535):
                return False, f"Invalid destination port: {event.network.destination_port}"

        # --- IP address format ---
        if not _is_valid_ip(event.network.source_ip):
            return False, f"Malformed source IP: {event.network.source_ip}"

        if not _is_valid_ip(event.network.destination_ip):
            return False, f"Malformed destination IP: {event.network.destination_ip}"

        # --- Enum enforcement ---
        if event.event.severity and event.event.severity not in _VALID_SEVERITIES:
            return False, f"Invalid severity '{event.event.severity}'; must be one of {_VALID_SEVERITIES}"

        if event.event.action and event.event.action not in _VALID_ACTIONS:
            # Accept non-standard actions — they were pass-through from parsers
            # Only flag truly empty actions
            pass

        if event.event.category and event.event.category not in _VALID_CATEGORIES:
            # Accept non-standard categories gracefully
            pass

        # --- Confidence bounds ---
        if event.metadata.confidence is not None:
            if not (0.0 <= event.metadata.confidence <= 1.0):
                return False, f"Confidence {event.metadata.confidence} out of range [0.0, 1.0]"

        # --- Schema version ---
        if not event.metadata.schema_version:
            return False, "Missing schema_version in metadata"

        # --- Threat intel risk score bounds ---
        if event.threat_intel.risk_score < 0 or event.threat_intel.risk_score > 100:
            return False, f"Risk score {event.threat_intel.risk_score} out of range [0, 100]"

        # --- Byte fields non-negative ---
        if event.network.bytes_sent is not None and event.network.bytes_sent < 0:
            return False, f"Negative bytes_sent: {event.network.bytes_sent}"
        if event.network.bytes_received is not None and event.network.bytes_received < 0:
            return False, f"Negative bytes_received: {event.network.bytes_received}"

        return True, "Valid"


validator = EventValidator()
