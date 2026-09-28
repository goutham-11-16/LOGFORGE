"""CSV and Delimited Log Parser.
Enhanced with automatic header detection, multi-vendor positional mapping,
and intelligent delimiter sniffing.
"""
import csv
import io
from typing import Dict, Any, Tuple, List, Optional
from backend.parsers.base import BaseParser

# Common log-related header keywords for auto-detection
_HEADER_KEYWORDS = {
    "timestamp", "time", "date", "datetime", "src_ip", "dst_ip",
    "source", "destination", "action", "protocol", "port",
    "severity", "hostname", "user", "message", "type", "status",
    "bytes", "packets", "duration", "srcip", "dstip", "sport", "dport",
}


class CSVParser(BaseParser):
    name = "csv-delimited-v1"
    format_name = "CSV"
    default_device_type = "network_device"
    default_vendor = "CSV-Source"

    def __init__(self, headers: Optional[List[str]] = None, delimiter: str = ","):
        self.headers = headers
        self.delimiter = delimiter
        self._auto_headers: Optional[List[str]] = None

    def set_headers(self, headers: List[str]):
        self.headers = [h.strip().lower() for h in headers]

    def _detect_delimiter(self, line: str) -> str:
        """Sniff the best delimiter from comma, semicolon, tab, and pipe."""
        counts = {
            ",": line.count(","),
            ";": line.count(";"),
            "\t": line.count("\t"),
            "|": line.count("|"),
        }
        # Return the one with the highest count, minimum 2 occurrences
        best = max(counts, key=counts.get)
        if counts[best] >= 2:
            return best
        return self.delimiter

    def _is_header_row(self, row: List[str]) -> bool:
        """Heuristic: a header row has mostly non-numeric, short, keyword-like cells."""
        if not row or len(row) < 3:
            return False
        keyword_hits = 0
        non_numeric = 0
        for cell in row:
            cell_clean = cell.strip().lower().replace("_", "").replace("-", "")
            if not cell_clean:
                continue
            if not cell_clean.replace(".", "").isdigit():
                non_numeric += 1
            if cell.strip().lower() in _HEADER_KEYWORDS:
                keyword_hits += 1
        # If >60% non-numeric and at least 2 keyword hits, it's likely a header
        ratio = non_numeric / max(len(row), 1)
        return ratio > 0.6 and keyword_hits >= 2

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if not line:
            return False, 0.0

        # Exclude other known formats
        if (line.startswith("<") or line.startswith("{") or
                line.startswith("CEF:") or line.startswith("LEEF:")):
            return False, 0.0

        # Check delimiter counts
        commas = line.count(",")
        semicolons = line.count(";")
        tabs = line.count("\t")
        pipes = line.count("|")

        max_delim = max(commas, semicolons, tabs, pipes)

        if max_delim >= 3 and not ("=" in line and " " in line and commas < 3):
            # Higher confidence if it looks like a data row with IPs or numbers
            confidence = 0.80
            if any(c.isdigit() and "." in line for c in line):
                confidence = 0.85
            return True, confidence

        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        delim = self._detect_delimiter(line)

        reader = csv.reader(io.StringIO(line), delimiter=delim)
        row = next(reader, None)
        if not row:
            raise ValueError("Empty or invalid CSV row")

        result: Dict[str, Any] = {"format": "CSV"}

        # Check if this row is a header row
        if self._is_header_row(row):
            self._auto_headers = [h.strip().lower() for h in row]
            result["_is_header"] = True
            # Store columns anyway
            for idx, col in enumerate(row):
                result[f"col_{idx}"] = col.strip()
            return result

        # Use headers: explicit > auto-detected > positional
        effective_headers = self.headers or self._auto_headers

        if effective_headers and len(effective_headers) == len(row):
            for h, v in zip(effective_headers, row):
                result[h] = v.strip()
        else:
            # Positional fallback
            for idx, col in enumerate(row):
                result[f"col_{idx}"] = col.strip()

        # ---- Vendor-specific positional mapping ----
        self._infer_vendor(row, line, result)

        return result

    @staticmethod
    def _infer_vendor(row: List[str], line: str, result: Dict[str, Any]) -> None:
        """Heuristic vendor detection from row structure and content."""
        lower_line = line.lower()

        # Palo Alto CSV traffic: typically 40+ columns
        if len(row) > 20 and ("allow" in lower_line or "deny" in lower_line or "drop" in lower_line):
            result["vendor"] = "PaloAlto-CSV"
            result["device_type"] = "firewall"
            if len(row) > 7:
                result["src_ip"] = row[7].strip()
            if len(row) > 8:
                result["dst_ip"] = row[8].strip()
            if len(row) > 24 and row[24].strip().isdigit():
                result["src_port"] = row[24].strip()
            if len(row) > 25 and row[25].strip().isdigit():
                result["dst_port"] = row[25].strip()
            if len(row) > 29:
                result["proto"] = row[29].strip()
            if len(row) > 30:
                result["action"] = row[30].strip()
            return

        # Check Point CSV export
        if "checkpoint" in lower_line or "smartlog" in lower_line:
            result["vendor"] = "CheckPoint"
            result["device_type"] = "firewall"
            return

        # VPN logs (Pulse Secure, Cisco AnyConnect, etc.)
        if "vpn" in lower_line or "tunnel" in lower_line or "pulse" in lower_line:
            result["device_type"] = "vpn"
            if "pulse" in lower_line:
                result["vendor"] = "PulseSecure"
            elif "anyconnect" in lower_line or "cisco" in lower_line:
                result["vendor"] = "Cisco"
            return

        # Proxy logs
        if "proxy" in lower_line or "bluecoat" in lower_line or "squid" in lower_line:
            result["device_type"] = "proxy"
            return
