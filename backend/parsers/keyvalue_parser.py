"""Key-Value & Perimeter Device Specific Log Parser (Cisco ASA, Palo Alto, Fortinet)."""
import re
from typing import Dict, Any, Tuple
from backend.parsers.base import BaseParser

# Regex to extract key=value pairs, handling quotes: key="val" or key=val
KV_REGEX = re.compile(r'([a-zA-Z0-9_\-\.]+)=(?:\"([^\"]*)\"|([^\s,]+))')

# Cisco ASA syslog message pattern: %ASA-4-106023: Deny tcp src outside:1.2.3.4/5000 dst inside:10.0.0.1/80 by access-group ...
CISCO_ASA_PATTERN = re.compile(
    r"%(?P<facility>ASA|PIX|FWSM)-(?P<severity>\d)-(?P<code_id>\d+):\s+"
    r"(?P<action>Deny|Built|Teardown|Permit|Drop)\s+"
    r"(?:(?P<protocol>\w+)\s+)?"
    r"src\s+(?:(?P<src_if>[\w\-]+):)?(?P<src_ip>[\d\.]+)(?:/(?P<src_port>\d+))?\s+"
    r"dst\s+(?:(?P<dst_if>[\w\-]+):)?(?P<dst_ip>[\d\.]+)(?:/(?P<dst_port>\d+))?",
    re.IGNORECASE
)


class KeyValueNetworkParser(BaseParser):
    name = "keyvalue-network-v1"
    format_name = "KEY_VALUE"
    default_device_type = "firewall"
    default_vendor = "Network-Firewall"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        # Cisco ASA check
        if "%ASA-" in line or "%PIX-" in line:
            return True, 0.98

        # Fortinet / Palo Alto key-value check (e.g. type=traffic subtype=forward srcip=... or devname=...)
        kv_matches = KV_REGEX.findall(line)
        if len(kv_matches) >= 3:
            # Check for common firewall keys
            keys = [m[0].lower() for m in kv_matches]
            firewall_keys = {"src", "srcip", "dst", "dstip", "proto", "action", "status", "sport", "dport", "spt", "dpt"}
            if len(set(keys).intersection(firewall_keys)) >= 2:
                return True, 0.95
            return True, 0.85

        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        result: Dict[str, Any] = {
            "format": "KEY_VALUE",
            "raw_message": line
        }

        # Check Cisco ASA pattern
        cisco_match = CISCO_ASA_PATTERN.search(line)
        if cisco_match:
            d = cisco_match.groupdict()
            result["vendor"] = "Cisco"
            result["product"] = f"ASA-{d.get('facility', 'ASA')}"
            result["device_type"] = "firewall"
            result["action"] = d.get("action")
            result["protocol"] = d.get("protocol")
            result["src_ip"] = d.get("src_ip")
            result["src_port"] = d.get("src_port")
            result["dst_ip"] = d.get("dst_ip")
            result["dst_port"] = d.get("dst_port")
            result["severity_code"] = int(d.get("severity", 4))
            result["cisco_message_id"] = d.get("code_id")
            return result

        # Key-Value pair extraction
        matches = KV_REGEX.findall(line)
        for k, v_quoted, v_unquoted in matches:
            val = v_quoted if v_quoted else v_unquoted
            result[k.lower()] = val

        # Vendor and device inference
        lower_line = line.lower()
        if "fortigate" in lower_line or "devname=fg" in lower_line or "fortinet" in lower_line:
            result["vendor"] = "Fortinet"
            result["device_type"] = "firewall"
        elif "pan-os" in lower_line or "paloalto" in lower_line:
            result["vendor"] = "PaloAlto"
            result["device_type"] = "firewall"
        elif "checkpoint" in lower_line:
            result["vendor"] = "CheckPoint"
            result["device_type"] = "firewall"
        elif "router" in lower_line:
            result["device_type"] = "router"
        elif "vpn" in lower_line:
            result["device_type"] = "vpn"

        return result
