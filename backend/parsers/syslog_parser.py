"""Syslog Parser for RFC 3164 and RFC 5424 formats.
Enhanced with deeper vendor fingerprinting, structured-data parsing,
and more resilient fallback extraction.
"""
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

# Structured-data element parser (RFC 5424 SD-ELEMENT)
SD_ELEMENT_RE = re.compile(r'\[(?P<sd_id>[^\s\]]+)\s+(?P<sd_params>[^\]]*)\]')
SD_PARAM_RE = re.compile(r'(\w+)="([^"]*)"')

# ----- Vendor fingerprint patterns -----
_CISCO_ASA_RE = re.compile(r"%(?:ASA|PIX|FWSM|FTD)-(\d)-(\d+)", re.IGNORECASE)
_FORTI_RE = re.compile(r"(?:devname|devid)=[\"']?(?:FG|FW)", re.IGNORECASE)
_PALO_RE = re.compile(r"(?:TRAFFIC|THREAT|SYSTEM),\d{4}/\d{2}/\d{2}", re.IGNORECASE)
_CHECKPOINT_RE = re.compile(r"(?:product|fw)=.*(?:SmartDefense|Check\s*Point|VPN-1)", re.IGNORECASE)
_JUNIPER_RE = re.compile(r"(?:RT_FLOW|RT_UTM|KERN|UI_)", re.IGNORECASE)


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
        msg = ""

        # Try RFC 5424 first
        m = RFC5424_PATTERN.match(line)
        if m:
            data = m.groupdict()
            pri = int(data["pri"])
            result["pri"] = pri
            result["facility"] = pri >> 3
            result["severity_code"] = pri & 7
            result["timestamp"] = data["timestamp"]
            result["hostname"] = data["hostname"] if data["hostname"] != "-" else None
            result["app_name"] = data["app_name"] if data["app_name"] != "-" else None
            result["proc_id"] = data.get("proc_id", "-")
            result["msg_id"] = data.get("msg_id", "-")
            msg = data.get("msg", "")
            result["message"] = msg

            # Parse structured-data elements
            sd_raw = data.get("structured_data", "-")
            if sd_raw and sd_raw != "-":
                for sd_match in SD_ELEMENT_RE.finditer(sd_raw):
                    sd_id = sd_match.group("sd_id")
                    for param_match in SD_PARAM_RE.finditer(sd_match.group("sd_params")):
                        pkey = param_match.group(1).lower()
                        pval = param_match.group(2)
                        result[f"{sd_id}.{pkey}"] = pval
                        # Also store flat key for normalizer lookup
                        result[pkey] = pval
        else:
            # Try RFC 3164
            m = RFC3164_PATTERN.match(line)
            if m:
                data = m.groupdict()
                if data.get("pri"):
                    pri = int(data["pri"])
                    result["pri"] = pri
                    result["facility"] = pri >> 3
                    result["severity_code"] = pri & 7
                result["timestamp"] = data["timestamp"]
                result["hostname"] = data["hostname"]
                result["app_name"] = data.get("tag")
                if data.get("pid"):
                    result["pid"] = data["pid"]
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

        # Parse key-value pairs embedded in message body
        if msg:
            pairs = KV_PATTERN.findall(msg)
            for k, v in pairs:
                v = v.strip('"')
                result[k.lower()] = v

        # ---- Vendor & device fingerprinting ----
        self._fingerprint_vendor(line, result)

        return result

    @staticmethod
    def _fingerprint_vendor(line: str, result: Dict[str, Any]) -> None:
        """Apply vendor fingerprint patterns to classify the source device."""
        lower_line = line.lower()

        # Cisco ASA / FTD / PIX
        cisco_m = _CISCO_ASA_RE.search(line)
        if cisco_m:
            result["vendor"] = "Cisco"
            result["device_type"] = "firewall"
            result["cisco_severity"] = cisco_m.group(1)
            result["cisco_message_id"] = cisco_m.group(2)
            return

        if "cisco" in lower_line:
            result["vendor"] = "Cisco"
            if "asa" in lower_line or "ftd" in lower_line:
                result["device_type"] = "firewall"
            elif "ios" in lower_line or "router" in lower_line:
                result["device_type"] = "router"
            elif "switch" in lower_line or "catalyst" in lower_line:
                result["device_type"] = "switch"
            return

        # Fortinet / FortiGate
        if _FORTI_RE.search(line) or "fortigate" in lower_line or "fortinet" in lower_line:
            result["vendor"] = "Fortinet"
            result["device_type"] = "firewall"
            return

        # Palo Alto
        if "paloalto" in lower_line or "pan-os" in lower_line or _PALO_RE.search(line):
            result["vendor"] = "PaloAlto"
            result["device_type"] = "firewall"
            return

        # Check Point
        if _CHECKPOINT_RE.search(line) or "checkpoint" in lower_line:
            result["vendor"] = "CheckPoint"
            result["device_type"] = "firewall"
            return

        # Juniper
        if _JUNIPER_RE.search(line) or "juniper" in lower_line or "srx" in lower_line:
            result["vendor"] = "Juniper"
            if "srx" in lower_line:
                result["device_type"] = "firewall"
            else:
                result["device_type"] = "router"
            return

        # Suricata / Snort
        if "suricata" in lower_line or "snort" in lower_line:
            result["vendor"] = "OpenSource"
            result["device_type"] = "ids"
            return

        # F5 / BIG-IP
        if "f5" in lower_line or "big-ip" in lower_line or "bigip" in lower_line:
            result["vendor"] = "F5"
            result["device_type"] = "load_balancer"
            return

        # Sophos
        if "sophos" in lower_line or "xg firewall" in lower_line:
            result["vendor"] = "Sophos"
            result["device_type"] = "firewall"
            return

        # Generic VPN detection
        if "vpn" in lower_line:
            result["device_type"] = "vpn"
