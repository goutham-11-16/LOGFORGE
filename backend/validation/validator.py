"""Validation Layer for LOGFORGE ULPF."""
from typing import Tuple
from backend.schema.models import UniversalEvent


class EventValidator:
    """Validates normalized events before persistence and downstream delivery."""

    @staticmethod
    def validate(event: UniversalEvent) -> Tuple[bool, str]:
        if not event.event_id:
            return False, "Missing event_id"

        if not event.raw_event or not event.raw_event.strip():
            return False, "Lossless violation: raw_event must never be empty"

        if not event.timestamp:
            return False, "Missing timestamp"

        # Validate port ranges if present
        if event.network.source_port is not None:
            if not (1 <= event.network.source_port <= 65535):
                return False, f"Invalid source port: {event.network.source_port}"

        if event.network.destination_port is not None:
            if not (1 <= event.network.destination_port <= 65535):
                return False, f"Invalid destination port: {event.network.destination_port}"

        return True, "Valid"


validator = EventValidator()
