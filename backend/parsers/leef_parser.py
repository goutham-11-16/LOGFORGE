"""LEEF (Log Event Extended Format) Parser."""
import re
from typing import Dict, Any, Tuple
from backend.parsers.base import BaseParser

# LEEF:Version|Vendor|Product|Version|EventID|Delimiter(optional)|Attributes
LEEF_HEADER_PATTERN = re.compile(
    r"^LEEF:(?P<version>1\.0|2\.0)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<version_id>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|"
    r"(?:(?P<delimiter>[^|]*)\|)?"
    r"(?P<attributes>.*)$"
)


class LEEFParser(BaseParser):
    name = "leef-qradar-v1"
    format_name = "LEEF"
    default_device_type = "network_security"
    default_vendor = "LEEF-QRadar"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if "LEEF:1.0" in line or "LEEF:2.0" in line or line.startswith("LEEF:"):
            return True, 0.99
        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        idx = line.find("LEEF:")
        if idx > 0:
            leef_part = line[idx:]
        else:
            leef_part = line

        m = LEEF_HEADER_PATTERN.match(leef_part)
        if not m:
            raise ValueError(f"Line does not conform to LEEF format: {leef_part[:50]}")

        header = m.groupdict()
        result: Dict[str, Any] = {
            "format": "LEEF",
            "leef_version": header["version"],
            "vendor": header["vendor"],
            "product": header["product"],
            "device_version": header["version_id"],
            "event_name": header["event_id"],
        }

        attrs = header.get("attributes", "")
        delimiter = header.get("delimiter")
        if not delimiter or delimiter.strip() == "":
            delimiter = "\t" if "\t" in attrs else "\x09"
            if delimiter not in attrs and "^" in attrs:
                delimiter = "^"

        # Split attributes
        parts = [p.strip() for p in attrs.split(delimiter) if p.strip()]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                result[k.strip().lower()] = v.strip()

        prod = (header["product"] or "").lower()
        if "firewall" in prod:
            result["device_type"] = "firewall"
        elif "vpn" in prod:
            result["device_type"] = "vpn"
        elif "ids" in prod or "ips" in prod:
            result["device_type"] = "ids"
        else:
            result["device_type"] = "network_device"

        return result
