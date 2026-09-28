"""Parser Registry and Format Detection Engine for LOGFORGE ULPF."""
from typing import List, Dict, Any, Tuple, Optional
from backend.parsers.base import BaseParser
from backend.parsers.syslog_parser import SyslogParser
from backend.parsers.cef_parser import CEFParser
from backend.parsers.leef_parser import LEEFParser
from backend.parsers.json_parser import JSONParser
from backend.parsers.csv_parser import CSVParser
from backend.parsers.keyvalue_parser import KeyValueNetworkParser


class ParserRegistry:
    """Central registry and intelligent dispatcher for all log parsers."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        # Order of evaluation matters for format detection
        self.register(CEFParser())
        self.register(LEEFParser())
        self.register(JSONParser())
        self.register(KeyValueNetworkParser())
        self.register(SyslogParser())
        self.register(CSVParser())

    def register(self, parser: BaseParser):
        self._parsers[parser.name] = parser

    def get_parser(self, name: str) -> Optional[BaseParser]:
        return self._parsers.get(name)

    def list_parsers(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "format": p.format_name,
                "vendor": p.default_vendor,
                "device_type": p.default_device_type,
            }
            for p in self._parsers.values()
        ]

    def detect_format(self, raw_line: str) -> Tuple[Optional[BaseParser], float]:
        """
        Evaluate all registered parsers against the sample line and return
        the parser with the highest confidence score.
        """
        best_parser: Optional[BaseParser] = None
        highest_confidence: float = 0.0

        for parser in self._parsers.values():
            can_parse, confidence = parser.can_parse(raw_line)
            if can_parse and confidence > highest_confidence:
                highest_confidence = confidence
                best_parser = parser
                # Short-circuit on absolute confidence
                if confidence >= 0.99:
                    break

        return best_parser, highest_confidence


# Global instance
registry = ParserRegistry()
