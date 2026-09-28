"""CEF (Common Event Format) Parser."""
import re
from typing import Dict, Any, Tuple
from backend.parsers.base import BaseParser

# CEF standard: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
CEF_HEADER_PATTERN = re.compile(
    r"^CEF:(?P<cef_version>\d+)\|"
    r"(?P<device_vendor>[^|]*)\|"
    r"(?P<device_product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|"
    r"(?P<signature_id>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|"
    r"(?P<extension>.*)$"
)

# Extension keys in CEF: key=value
CEF_EXT_PATTERN = re.compile(r'([a-zA-Z0-9_\.]+)=((?:\\=|[^=])+?)(?=\s+[a-zA-Z0-9_\.]+=|$)')


class CEFParser(BaseParser):
    name = "cef-arcsight-v1"
    format_name = "CEF"
    default_device_type = "network_security"
    default_vendor = "ArcSight-CEF"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        # Might have leading syslog header or start directly with CEF:
        if "CEF:0" in line or "CEF:1" in line or line.startswith("CEF:"):
            return True, 0.99
        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        
        # If CEF is embedded within a syslog prefix, locate CEF:
        cef_idx = line.find("CEF:")
        prefix = ""
        if cef_idx > 0:
            prefix = line[:cef_idx].strip()
            cef_part = line[cef_idx:]
        else:
            cef_part = line

        m = CEF_HEADER_PATTERN.match(cef_part)
        if not m:
            raise ValueError(f"Line does not conform to CEF format: {cef_part[:50]}")

        header = m.groupdict()
        result: Dict[str, Any] = {
            "format": "CEF",
            "cef_version": header["cef_version"],
            "vendor": header["device_vendor"],
            "product": header["device_product"],
            "device_version": header["device_version"],
            "signature_id": header["signature_id"],
            "event_name": header["name"],
            "cef_severity": header["severity"],
            "prefix": prefix
        }

        # Parse extension key-values
        ext = header.get("extension", "")
        if ext:
            matches = CEF_EXT_PATTERN.findall(ext)
            for k, v in matches:
                clean_v = v.strip().replace(r"\=", "=").replace(r"\\", "\\")
                result[k.lower()] = clean_v

        # Device type heuristic based on product/name
        prod = (header["device_product"] or "").lower()
        name = (header["name"] or "").lower()
        if "firewall" in prod or "firewall" in name or "asa" in prod or "palo" in prod or "forti" in prod:
            result["device_type"] = "firewall"
        elif "ids" in prod or "ips" in prod or "snort" in prod or "suricata" in prod:
            result["device_type"] = "ids"
        elif "vpn" in prod or "vpn" in name:
            result["device_type"] = "vpn"
        elif "proxy" in prod or "bluecoat" in prod:
            result["device_type"] = "proxy"
        else:
            result["device_type"] = "network_device"

        return result
