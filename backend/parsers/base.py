"""Base parser interface for LOGFORGE ULPF."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional


class BaseParser(ABC):
    """Abstract Base Class for all format-specific log parsers."""
    
    name: str = "base"
    format_name: str = "GENERIC"
    default_device_type: str = "network_device"
    default_vendor: str = "Generic"

    @abstractmethod
    def can_parse(self, raw_line: str) -> Tuple[bool, float]:
        """
        Evaluate if this parser can handle the given log line.
        Returns:
            (can_parse: bool, confidence: float between 0.0 and 1.0)
        """
        pass

    @abstractmethod
    def parse(self, raw_line: str) -> Dict[str, Any]:
        """
        Extract structured fields from the raw line.
        Must return a dictionary containing extracted vendor/source fields
        such as timestamp, src_ip, dst_ip, action, protocol, etc.
        Raises ValueError or Exception if parsing fails.
        """
        pass
