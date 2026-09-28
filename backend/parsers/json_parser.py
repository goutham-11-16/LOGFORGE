"""JSON and JSONL log parser.
Enhanced with deeper vendor fingerprinting, nested object handling,
array flattening, and richer field aliasing for multi-vendor support.
"""
import json
from typing import Dict, Any, Tuple, List
from backend.parsers.base import BaseParser


def _flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Recursively flatten nested dicts and lists into dot-notation keys."""
    items: List[tuple] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Flatten list elements: store the list as-is and also index items
            items.append((new_key, v))
            for idx, elem in enumerate(v):
                if isinstance(elem, dict):
                    items.extend(_flatten_dict(elem, f"{new_key}.{idx}", sep=sep).items())
                else:
                    items.append((f"{new_key}.{idx}", elem))
        else:
            items.append((new_key, v))
    return dict(items)


# ---- Vendor fingerprint keywords (case-insensitive checks on raw JSON) -----
_VENDOR_SIGNATURES = [
    # (keywords_in_data, vendor, device_type)
    (["event_type", "alert", "signature_id"], "Suricata", "ids"),
    (["alert", "category", "signature"], "Suricata", "ids"),
    (["snort"], "Snort", "ids"),
    (["zeek", "uid", "conn"], "Zeek", "ids"),
    (["fortigate", "devname"], "Fortinet", "firewall"),
    (["paloalto", "pan-os"], "PaloAlto", "firewall"),
    (["checkpoint"], "CheckPoint", "firewall"),
    (["cisco", "asa"], "Cisco", "firewall"),
    (["f5", "bigip", "big-ip"], "F5", "load_balancer"),
    (["waf", "web application firewall"], "WAF", "waf"),
    (["cloudflare"], "Cloudflare", "cdn"),
    (["aws", "cloudtrail"], "AWS", "cloud"),
    (["azure", "entra"], "Microsoft", "cloud"),
    (["gcp", "google_cloud"], "Google", "cloud"),
]


class JSONParser(BaseParser):
    name = "json-universal-v1"
    format_name = "JSON"
    default_device_type = "network_device"
    default_vendor = "JSON-Source"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if not line:
            return False, 0.0

        # Must start with { and end with }
        if not (line.startswith("{") and line.endswith("}")):
            return False, 0.0

        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                # Higher confidence if it has recognized log-like keys
                keys_lower = {k.lower() for k in parsed.keys()}
                log_keys = {"timestamp", "time", "datetime", "event_type", "src_ip",
                            "dst_ip", "action", "severity", "message", "msg",
                            "source", "destination", "alert", "host", "hostname"}
                overlap = keys_lower & log_keys
                if len(overlap) >= 2:
                    return True, 0.99
                return True, 0.92  # Valid JSON but fewer recognizable keys
        except (json.JSONDecodeError, ValueError):
            pass
        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        data = json.loads(line)
        if not isinstance(data, dict):
            raise ValueError("Parsed JSON is not a key-value object")

        flat = _flatten_dict(data)
        result: Dict[str, Any] = {
            "format": "JSON",
            **flat
        }

        # ---- Vendor fingerprinting ----
        self._fingerprint_vendor(data, flat, result)

        return result

    @staticmethod
    def _fingerprint_vendor(
        data: Dict[str, Any],
        flat: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """Detect vendor and device type from JSON structure and content."""
        # Build a lowercase representation for keyword matching
        all_keys = {k.lower() for k in flat.keys()}
        data_str_lower = json.dumps(data).lower()

        # Check Suricata EVE first (most common JSON IDS format)
        if "event_type" in data or "alert" in data:
            result["vendor"] = "Suricata"
            result["device_type"] = "ids"
            # Extract Suricata-specific fields
            if isinstance(data.get("alert"), dict):
                alert = data["alert"]
                if "signature" in alert:
                    result["event_name"] = alert["signature"]
                if "category" in alert:
                    result["category"] = alert["category"]
                if "severity" in alert:
                    result["severity"] = str(alert["severity"])
            return

        # Check Zeek (Bro) logs
        if "uid" in data and "id.orig_h" in flat:
            result["vendor"] = "Zeek"
            result["device_type"] = "ids"
            # Map Zeek fields to standard names
            if "id.orig_h" in flat:
                result["src_ip"] = flat["id.orig_h"]
            if "id.resp_h" in flat:
                result["dst_ip"] = flat["id.resp_h"]
            if "id.orig_p" in flat:
                result["sport"] = flat["id.orig_p"]
            if "id.resp_p" in flat:
                result["dport"] = flat["id.resp_p"]
            if "proto" in data:
                result["protocol"] = data["proto"]
            return

        # Generic keyword-based vendor detection
        for keywords, vendor, dev_type in _VENDOR_SIGNATURES:
            match_count = sum(1 for kw in keywords if kw in data_str_lower)
            if match_count >= 2 or (len(keywords) == 1 and match_count == 1):
                result["vendor"] = vendor
                result["device_type"] = dev_type
                return

        # Fallback: check for firewall-ish keys
        if any(k in all_keys for k in ("firewall", "fw_action", "rule_name")):
            result["device_type"] = "firewall"
        elif any(k in all_keys for k in ("vpn", "tunnel")):
            result["device_type"] = "vpn"
