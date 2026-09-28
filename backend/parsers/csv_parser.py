"""CSV and Delimited Log Parser."""
import csv
import io
from typing import Dict, Any, Tuple, List, Optional
from backend.parsers.base import BaseParser


class CSVParser(BaseParser):
    name = "csv-delimited-v1"
    format_name = "CSV"
    default_device_type = "network_device"
    default_vendor = "CSV-Source"

    def __init__(self, headers: Optional[List[str]] = None, delimiter: str = ","):
        self.headers = headers
        self.delimiter = delimiter

    def set_headers(self, headers: List[str]):
        self.headers = [h.strip().lower() for h in headers]

    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        line = raw_line.strip()
        if not line or line.startswith("<") or line.startswith("{") or line.startswith("CEF:") or line.startswith("LEEF:"):
            return False, 0.0

        # Check comma count vs words
        commas = line.count(",")
        semicolons = line.count(";")
        tabs = line.count("\t")

        if commas >= 3 and not ("=" in line and " " in line):
            return True, 0.80
        if semicolons >= 3:
            return True, 0.80
        if tabs >= 3:
            return True, 0.80

        return False, 0.0

    def parse(self, raw_line: str) -> Dict[str, Any]:
        line = raw_line.strip()
        delim = self.delimiter
        if delim not in line:
            if ";" in line:
                delim = ";"
            elif "\t" in line:
                delim = "\t"

        reader = csv.reader(io.StringIO(line), delimiter=delim)
        row = next(reader, None)
        if not row:
            raise ValueError("Empty or invalid CSV row")

        result: Dict[str, Any] = {"format": "CSV"}
        if self.headers and len(self.headers) == len(row):
            for h, v in zip(self.headers, row):
                result[h] = v.strip()
        else:
            # Check if this row itself is a header row (all non-numeric, contains keywords)
            for idx, col in enumerate(row):
                result[f"col_{idx}"] = col.strip()
                
            # If standard 5-tuple position or common Palo Alto CSV positions exist
            # Palo Alto CSV traffic: col 6=time, 7=src_ip, 8=dst_ip, 24=sport, 25=dport, 29=proto, 30=action
            if len(row) > 20 and ("allow" in line.lower() or "deny" in line.lower()):
                result["vendor"] = "PaloAlto-CSV"
                result["device_type"] = "firewall"
                if len(row) > 7: result["src_ip"] = row[7].strip()
                if len(row) > 8: result["dst_ip"] = row[8].strip()
                if len(row) > 24 and row[24].isdigit(): result["src_port"] = row[24].strip()
                if len(row) > 25 and row[25].isdigit(): result["dst_port"] = row[25].strip()
                if len(row) > 29: result["proto"] = row[29].strip()
                if len(row) > 30: result["action"] = row[30].strip()

        return result
