"""Syslog Parser for RFC 3164 and RFC 5424 formats."""
import re
from typing import Dict, Any, Tuple
from backend.parsers.base import BaseParser

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>[^\s]+)\s+"
    r"(?P<hostname>[^\s]+)\s+"
    r"(?P<app_name>[^\s]+)\s+"
    r"(?P<proc_id>[^\s]+)\s+"
    r"(?P<msg_id>[^\s]+)\s*"
    r"(?P<structured_data>\[.*?\]|-)?\s*"
    r"(?P<msg>.*)$"
)

# RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG/APP: MSG
RFC3164_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)\s+"
    r"(?P<hostname>[^\s:]+)\s+"
    r"(?:(?P<tag>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<msg>.*)$"
)

# Generic Key-Value extractor for message body
KV_PATTERN = re.compile(r'(?:([a-zA-Z0-9_\.\-]+)=([^\s",]+|"[^"]*"))')


class SyslogParser(BaseParser):
    name = "syslog-rfc3164-5424"
    format_name = "SYSLOG"
    default_device_type = "network_device"
    default_vendor = "Generic-Syslog"

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if not line:
            return False, 0.0
            
        # Check RFC 5424
        if RFC5424_PATTERN.match(line):
            return True, 0.98
            
        # Check RFC 3164
        if RFC3164_PATTERN.match(line):
            return True, 0.95
            
        # Check standard leading priority <PRI>
        if line.startswith("<") and ">" in line[:6]:
            return True, 0.85
            
        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        result: Dict[str, Any] = {
            "raw_message": line,
            "format": "SYSLOG"
        }

        # Try RFC 5424 first
        m = RFC5424_PATTERN.match(line)
        if m:
            data = m.groupdict()
            result["pri"] = int(data["pri"])
            result["facility"] = result["pri"] >> 3
            result["severity_code"] = result["pri"] & 7
            result["timestamp"] = data["timestamp"]
            result["hostname"] = data["hostname"] if data["hostname"] != "-" else None
            result["app_name"] = data["app_name"] if data["app_name"] != "-" else None
            msg = data.get("msg", "")
            result["message"] = msg
        else:
            # Try RFC 3164
            m = RFC3164_PATTERN.match(line)
            if m:
                data = m.groupdict()
                if data.get("pri"):
                    result["pri"] = int(data["pri"])
                    result["facility"] = result["pri"] >> 3
                    result["severity_code"] = result["pri"] & 7
                result["timestamp"] = data["timestamp"]
                result["hostname"] = data["hostname"]
                result["app_name"] = data.get("tag")
                msg = data.get("msg", "")
                result["message"] = msg
            else:
                # Fallback: line starts with <PRI>
                if line.startswith("<") and ">" in line[:6]:
                    pri_end = line.find(">")
                    try:
                        pri = int(line[1:pri_end])
                        result["pri"] = pri
                        result["facility"] = pri >> 3
                        result["severity_code"] = pri & 7
                    except ValueError:
                        pass
                    msg = line[pri_end + 1:].strip()
                    result["message"] = msg
                else:
                    msg = line
                    result["message"] = msg

        # Parse key-value pairs embedded in message body (e.g. src=... dst=... action=...)
        if msg:
            pairs = KV_PATTERN.findall(msg)
            for k, v in pairs:
                v = v.strip('"')
                result[k.lower()] = v
                
        # Also detect vendor keywords in message/app_name
        lower_line = line.lower()
        if "cisco" in lower_line or "%asa-" in lower_line or "%ftd-" in lower_line:
            result["vendor"] = "Cisco"
            result["device_type"] = "firewall"
        elif "paloalto" in lower_line or "pan-os" in lower_line or "traffic" in lower_line and "threat" in lower_line:
            result["vendor"] = "PaloAlto"
            result["device_type"] = "firewall"
        elif "fortigate" in lower_line or "fortinet" in lower_line:
            result["vendor"] = "Fortinet"
            result["device_type"] = "firewall"
        elif "suricata" in lower_line or "snort" in lower_line:
            result["vendor"] = "OpenSource"
            result["device_type"] = "ids"

        return result
