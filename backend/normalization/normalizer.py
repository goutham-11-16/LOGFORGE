"""Configurable Field Normalization Engine for LOGFORGE ULPF.
Transforms vendor-specific and format-specific attributes into the Universal Event Schema.
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import re
import hashlib
from backend.schema.models import (
    UniversalEvent, SourceInfo, EventInfo, NetworkInfo,
    ProcessingMetadata, ThreatIntelligence
)

# --------------------------------------------------------------------------- #
#  Regex Patterns
# --------------------------------------------------------------------------- #
IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

IPV6_REGEX = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"       # Full
    r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"                      # Trailing ::
    r"^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|"    # Leading ::
    r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"      # Middle ::
)

# --------------------------------------------------------------------------- #
#  Mapping Dictionaries
# --------------------------------------------------------------------------- #
ACTION_MAPPINGS = {
    # Allow variants
    "allow": "allow", "permit": "allow", "pass": "allow",
    "accept": "allow", "built": "allow", "allowed": "allow",
    "success": "allow", "connected": "allow", "granted": "allow",
    "established": "allow", "open": "allow", "login": "allow",
    # Deny/Block variants
    "deny": "deny", "drop": "deny", "block": "deny",
    "blocked": "deny", "reject": "deny", "teardown": "deny",
    "reset": "deny", "failed": "deny", "refused": "deny",
    "discard": "deny", "close": "deny", "timeout": "deny",
    "terminated": "deny", "aborted": "deny",
    # Alert variants
    "alert": "alert", "warn": "alert", "warning": "alert",
    "flagged": "alert", "detected": "alert", "quarantine": "alert",
    "suspicious": "alert",
}

SEVERITY_MAPPINGS = {
    # Text strings
    "emergency": "critical", "emerg": "critical",
    "alert": "critical", "critical": "critical", "crit": "critical",
    "error": "high", "err": "high", "high": "high", "major": "high",
    "warning": "medium", "warn": "medium", "medium": "medium", "med": "medium",
    "notice": "low", "low": "low", "minor": "low",
    "info": "informational", "informational": "informational",
    "debug": "informational", "trace": "informational",
}

PROTOCOL_NUMBERS = {
    "1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE",
    "50": "ESP", "51": "AH", "58": "IPv6-ICMP", "89": "OSPF",
    "132": "SCTP", "2": "IGMP",
}

# --------------------------------------------------------------------------- #
#  Field name aliases for multi-vendor normalization
# --------------------------------------------------------------------------- #
SOURCE_IP_FIELDS = [
    "src", "src_ip", "srcip", "sourceaddress", "sourceip", "src_addr",
    "source", "c-ip", "source_address", "s_ip", "src_host",
    "client_ip", "clientip", "originator_ip",
]
DEST_IP_FIELDS = [
    "dst", "dst_ip", "dstip", "destinationaddress", "destinationip",
    "dst_addr", "destination", "cs-ip", "dest_address", "d_ip",
    "dest_ip", "target_ip", "server_ip", "responder_ip",
]
SOURCE_PORT_FIELDS = [
    "sport", "spt", "src_port", "sourceport", "srcport", "s_port", "client_port",
]
DEST_PORT_FIELDS = [
    "dport", "dpt", "dst_port", "destinationport", "dstport",
    "d_port", "target_port", "server_port",
]
PROTOCOL_FIELDS = [
    "proto", "protocol", "app_proto", "transport", "trans_protocol", "service",
]
ACTION_FIELDS = [
    "action", "act", "status", "decision", "event_action", "result", "disposition",
]
SEVERITY_FIELDS = [
    "severity", "severity_code", "pri", "level", "cef_severity",
    "priority", "threat_level", "risk",
]
TIMESTAMP_FIELDS = [
    "timestamp", "rt", "time", "date", "datetime", "event_time",
    "start", "end", "logged", "received_at", "generated_time",
]
USER_FIELDS = [
    "user", "username", "usr", "srcuser", "dstuser", "login",
    "account", "user_name", "uid", "user_id",
]
HOSTNAME_FIELDS = [
    "hostname", "host", "devname", "device_name", "syslog_host",
    "node", "computer_name", "machine",
]

# --------------------------------------------------------------------------- #
#  Known bad / suspicious ports
# --------------------------------------------------------------------------- #
_C2_PORTS = {4444, 5555, 8888, 1234, 31337, 6667, 6668, 6669}  # Common C2 / IRC
_RECON_PORTS = {0}  # Port 0 scan
_HIGH_RISK_SERVICES = {445, 3389, 22, 23, 1433, 3306, 5432, 5900, 27017}

# --------------------------------------------------------------------------- #
#  MITRE ATT&CK mapping table (heuristic)
# --------------------------------------------------------------------------- #
_MITRE_MAP = {
    "BruteForce":       ("T1110", "Credential Access"),
    "PortScan":         ("T1046", "Discovery"),
    "C2Beaconing":      ("T1071", "Command and Control"),
    "DataExfiltration": ("T1041", "Exfiltration"),
    "Reconnaissance":   ("T1595", "Reconnaissance"),
    "LateralMovement":  ("T1021", "Lateral Movement"),
    "PrivilegeEsc":     ("T1068", "Privilege Escalation"),
}


# --------------------------------------------------------------------------- #
#  RFC 1918 / private IP detection
# --------------------------------------------------------------------------- #
def _is_private_ip(ip: Optional[str]) -> bool:
    """Check if an IPv4 address is RFC-1918 private."""
    if not ip:
        return True  # Unknown → assume internal
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def _is_valid_ip(val: str) -> bool:
    """Return True if val is a valid IPv4 or IPv6 address."""
    return bool(IP_REGEX.match(val) or IPV6_REGEX.match(val))


# --------------------------------------------------------------------------- #
#  Timestamp parser
# --------------------------------------------------------------------------- #
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

    # Try Syslog BSD formats
    for fmt in (
        "%b %d %H:%M:%S", "%b %d %H:%M:%S %Y",
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",  # Apache CLF
        "%Y-%m-%dT%H:%M:%S",     # ISO without tz
        "%Y-%m-%d %H:%M:%S.%f",  # microseconds
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            pass

    # Try Unix epoch (seconds or milliseconds)
    try:
        val = float(ts_str)
        if val > 1e15:       # nanoseconds
            val /= 1e9
        elif val > 1e12:     # microseconds
            val /= 1e6
        elif val > 1e11:     # milliseconds
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except Exception:
        pass

    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
#  Helper: extract first matching field
# --------------------------------------------------------------------------- #
def _first_match(extracted: Dict[str, Any], field_list: List[str]) -> Optional[str]:
    """Return the first non-empty string value found in extracted for any field in the list."""
    for f in field_list:
        val = extracted.get(f)
        if val is not None and str(val).strip():
            return str(val).strip()
    return None


# --------------------------------------------------------------------------- #
#  Event category classification
# --------------------------------------------------------------------------- #
def _classify_category(extracted: Dict[str, Any], action: str) -> str:
    """Infer event category from extracted fields and normalised action."""
    raw_cat = extracted.get("category") or extracted.get("event_type") or ""
    lower_cat = str(raw_cat).lower()

    # Explicit category mapping
    if any(k in lower_cat for k in ("auth", "login", "logon", "logout", "logoff", "credential")):
        return "authentication"
    if any(k in lower_cat for k in ("threat", "alert", "intrusion", "malware", "attack", "anomaly")):
        return "security"
    if any(k in lower_cat for k in ("system", "audit", "config", "startup", "shutdown")):
        return "system"

    # Infer from action
    if action in ("login", "logon", "logout", "logoff"):
        return "authentication"
    if action in ("alert", "quarantine", "detected"):
        return "security"

    # Check for authentication keywords in raw message
    msg = str(extracted.get("message", "") or extracted.get("msg", "")).lower()
    if any(k in msg for k in ("login", "authentication", "password", "credential", "session")):
        return "authentication"

    return "network"


# --------------------------------------------------------------------------- #
#  Threat Intelligence Heuristic Engine
# --------------------------------------------------------------------------- #
class ThreatAnalyzer:
    """Rule-based heuristic threat intelligence engine.
    Assigns threat_type, MITRE ATT&CK mapping, and risk_score based on
    observable indicators in the normalized event fields.
    """

    @staticmethod
    def analyze(
        action: str,
        severity: str,
        source_ip: Optional[str],
        dest_ip: Optional[str],
        source_port: Optional[int],
        dest_port: Optional[int],
        protocol: Optional[str],
        extracted: Dict[str, Any],
    ) -> ThreatIntelligence:
        threat_type: Optional[str] = None
        risk_score = 0
        indicators: List[str] = []

        # ---- 1. Action-based risk ------------------------------------------
        if action == "deny":
            risk_score += 15
            indicators.append("denied_traffic")
        elif action == "alert":
            risk_score += 30
            indicators.append("alert_triggered")

        # ---- 2. Severity-based risk ----------------------------------------
        sev_weight = {
            "critical": 40, "high": 25, "medium": 10, "low": 5, "informational": 0,
        }
        risk_score += sev_weight.get(severity, 0)

        # ---- 3. Port-based heuristics --------------------------------------
        if dest_port is not None:
            if dest_port in _C2_PORTS:
                threat_type = "C2Beaconing"
                risk_score += 35
                indicators.append(f"c2_port:{dest_port}")
            elif dest_port in _RECON_PORTS:
                threat_type = "Reconnaissance"
                risk_score += 20
                indicators.append("port_zero_scan")
            elif dest_port in _HIGH_RISK_SERVICES and action == "deny":
                if not threat_type:
                    threat_type = "BruteForce"
                risk_score += 15
                indicators.append(f"denied_high_risk_port:{dest_port}")

        # ---- 4. Data exfiltration signal: large outbound bytes -------------
        bytes_sent = extracted.get("bytes_sent") or extracted.get("out") or extracted.get("sentbyte")
        if bytes_sent:
            try:
                bs = int(bytes_sent)
                if bs > 10_000_000:  # >10 MB single event
                    if not threat_type:
                        threat_type = "DataExfiltration"
                    risk_score += 25
                    indicators.append(f"large_egress:{bs}")
            except (ValueError, TypeError):
                pass

        # ---- 5. Message keyword heuristics ----------------------------------
        msg = str(
            extracted.get("message", "")
            or extracted.get("msg", "")
            or extracted.get("event_name", "")
        ).lower()
        if any(k in msg for k in ("scan", "probe", "sweep", "fingerprint")):
            if not threat_type:
                threat_type = "PortScan"
            risk_score += 20
        if any(k in msg for k in ("brute", "failed password", "invalid user", "authentication fail")):
            threat_type = "BruteForce"
            risk_score += 25
        if any(k in msg for k in ("lateral", "psexec", "wmi ", "smb ")):
            if not threat_type:
                threat_type = "LateralMovement"
            risk_score += 20
        if any(k in msg for k in ("privilege", "escalat", "root", "admin")):
            if not threat_type:
                threat_type = "PrivilegeEsc"
            risk_score += 15

        # ---- 6. Geo heuristic (RFC-1918) ------------------------------------
        src_private = _is_private_ip(source_ip)
        dst_private = _is_private_ip(dest_ip)
        geo_source = "Internal LAN" if src_private else "External"
        geo_dest = "Internal LAN" if dst_private else "External"

        # External-to-internal with denied action → increase risk
        if not src_private and dst_private and action == "deny":
            risk_score += 10
            indicators.append("external_to_internal_denied")

        # ---- Clamp risk score to 0-100 -------------------------------------
        risk_score = max(0, min(100, risk_score))

        # ---- Build MITRE reference -----------------------------------------
        mitre_id: Optional[str] = None
        if threat_type and threat_type in _MITRE_MAP:
            mitre_id = _MITRE_MAP[threat_type][0]

        return ThreatIntelligence(
            threat_detected=risk_score >= 30 or threat_type is not None,
            threat_type=threat_type,
            mitre_technique_id=mitre_id,
            risk_score=risk_score,
            geo_source=geo_source,
            geo_destination=geo_dest,
        )


_threat_analyzer = ThreatAnalyzer()


# --------------------------------------------------------------------------- #
#  Main Normalizer
# --------------------------------------------------------------------------- #
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

        # 1. Network Field Extraction & Normalization -------------------------
        source_ip = None
        for f in SOURCE_IP_FIELDS:
            if f in extracted and extracted[f]:
                val = str(extracted[f]).strip()
                if _is_valid_ip(val):
                    source_ip = val
                    break

        dest_ip = None
        for f in DEST_IP_FIELDS:
            if f in extracted and extracted[f]:
                val = str(extracted[f]).strip()
                if _is_valid_ip(val):
                    dest_ip = val
                    break

        source_port = None
        for f in SOURCE_PORT_FIELDS:
            if f in extracted and extracted[f]:
                try:
                    p = int(extracted[f])
                    if 0 <= p <= 65535:
                        source_port = p
                        break
                except (ValueError, TypeError):
                    pass

        dest_port = None
        for f in DEST_PORT_FIELDS:
            if f in extracted and extracted[f]:
                try:
                    p = int(extracted[f])
                    if 0 <= p <= 65535:
                        dest_port = p
                        break
                except (ValueError, TypeError):
                    pass

        # Protocol
        raw_proto = _first_match(extracted, PROTOCOL_FIELDS)
        protocol = None
        if raw_proto:
            raw_proto_upper = raw_proto.upper()
            if raw_proto in PROTOCOL_NUMBERS:
                protocol = PROTOCOL_NUMBERS[raw_proto]
            elif raw_proto_upper in (
                "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS",
                "SSH", "TLS", "IP", "SCTP", "GRE", "ESP", "AH",
            ):
                protocol = raw_proto_upper
            else:
                protocol = raw_proto_upper

        # 2. Action Normalization ---------------------------------------------
        raw_action = _first_match(extracted, ACTION_FIELDS)
        action = "unknown"
        if raw_action:
            action = ACTION_MAPPINGS.get(raw_action.lower(), raw_action.lower())

        # 3. Severity Normalization -------------------------------------------
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
                severity = SEVERITY_MAPPINGS.get(
                    sev_str,
                    "medium" if "alert" in sev_str else "informational"
                )

        # 4. Source & Device Normalization ------------------------------------
        vendor = extracted.get("vendor", "Generic")
        device_type = extracted.get("device_type", "network_device")
        hostname = _first_match(extracted, HOSTNAME_FIELDS)
        device_ip = extracted.get("ip") or extracted.get("device_ip")

        # 5. Timestamp Normalization ------------------------------------------
        raw_ts = _first_match(extracted, TIMESTAMP_FIELDS)
        normalized_timestamp = parse_timestamp_safe(raw_ts)

        # 6. Event Category Classification ------------------------------------
        category = _classify_category(extracted, action)

        # 7. User Context Extraction ------------------------------------------
        user_ctx: Dict[str, Any] = {}
        user_val = _first_match(extracted, USER_FIELDS)
        if user_val:
            user_ctx["name"] = user_val
            # Check for source/dest user differentiation
            src_user = extracted.get("srcuser") or extracted.get("src_user")
            dst_user = extracted.get("dstuser") or extracted.get("dst_user")
            if src_user:
                user_ctx["source_user"] = str(src_user).strip()
            if dst_user:
                user_ctx["destination_user"] = str(dst_user).strip()

        # 8. Process Context Extraction ---------------------------------------
        process_ctx: Dict[str, Any] = {}
        app_name = extracted.get("app_name") or extracted.get("app") or extracted.get("application")
        if app_name:
            process_ctx["name"] = str(app_name).strip()
        pid = extracted.get("pid") or extracted.get("proc_id") or extracted.get("process_id")
        if pid and str(pid).strip() not in ("-", ""):
            process_ctx["pid"] = str(pid).strip()

        # 9. Bytes normalization (safe int cast) ------------------------------
        def _safe_int(val: Any) -> Optional[int]:
            if val is None:
                return None
            try:
                return int(val)
            except (ValueError, TypeError):
                return None

        bytes_sent = _safe_int(
            extracted.get("bytes_sent") or extracted.get("out") or extracted.get("sentbyte")
        )
        bytes_received = _safe_int(
            extracted.get("bytes_received") or extracted.get("in") or extracted.get("rcvdbyte")
        )
        packets = _safe_int(extracted.get("packets"))

        # 10. Threat Intelligence Analysis ------------------------------------
        threat_intel = _threat_analyzer.analyze(
            action=action,
            severity=severity,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            extracted=extracted,
        )

        # 11. Construct Processing Metadata -----------------------------------
        tags = [source_format.lower(), device_type]
        if threat_intel.threat_detected:
            tags.append("threat")
        if threat_intel.threat_type:
            tags.append(threat_intel.threat_type.lower())
        if category != "network":
            tags.append(category)

        metadata = ProcessingMetadata(
            schema_version="1.0",
            parser=parser_name,
            source_format=source_format,
            confidence=round(confidence, 2),
            processing_time_ms=round(duration_ms, 3),
            tags=tags
        )

        # 12. Construct Universal Event ---------------------------------------
        return UniversalEvent(
            timestamp=normalized_timestamp,
            source=SourceInfo(
                vendor=vendor,
                device_type=device_type,
                hostname=hostname,
                ip=device_ip
            ),
            event=EventInfo(
                category=category,
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
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets=packets
            ),
            threat_intel=threat_intel,
            user=user_ctx,
            process=process_ctx,
            metadata=metadata,
            raw_event=raw_line.strip()
        )


normalizer = EventNormalizer()
