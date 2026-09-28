"""JSON and JSONL log parser."""
import json
from typing import Dict, Any, Tuple
from backend.parsers.base import BaseParser


def _flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


class JSONParser(BaseParser):
    name = "json-universal-v1"
    format_name = "JSON"
    default_device_type = "network_device"
    default_vendor = "JSON-Source"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            return False, 0.0
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                return True, 0.99
        except Exception:
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

        # Check for Suricata EVE signatures
        if "event_type" in data or "alert" in data:
            result["vendor"] = "Suricata"
            result["device_type"] = "ids"
        elif "firewall" in str(data).lower():
            result["device_type"] = "firewall"

        return result
