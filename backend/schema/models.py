"""Universal Log Pre-processing Framework (ULPF) - Models & Schema
Standardized Universal Event Schema for heterogeneous network & perimeter device logs.
"""
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import uuid


class SourceInfo(BaseModel):
    vendor: Optional[str] = Field(default="Generic", description="Detected device vendor (e.g. PaloAlto, Cisco, Fortinet)")
    device_type: Optional[str] = Field(default="network_device", description="Type of device (firewall, router, vpn, ids, proxy)")
    hostname: Optional[str] = Field(default=None, description="Host or device name originating the log")
    ip: Optional[str] = Field(default=None, description="Management or reporting IP of device")


class EventInfo(BaseModel):
    category: Optional[str] = Field(default="network", description="Category: network, authentication, security, system")
    type: Optional[str] = Field(default="traffic", description="Event type: connection, alert, auth, audit")
    action: Optional[str] = Field(default="unknown", description="Standardized action: allow, deny, drop, alert, reset")
    severity: Optional[str] = Field(default="informational", description="Standardized severity: low, medium, high, critical, informational")


class NetworkInfo(BaseModel):
    source_ip: Optional[str] = Field(default=None, description="Originating IPv4/IPv6 address")
    destination_ip: Optional[str] = Field(default=None, description="Target IPv4/IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Source port (1-65535)")
    destination_port: Optional[int] = Field(default=None, description="Destination port (1-65535)")
    protocol: Optional[str] = Field(default=None, description="Standardized transport/app protocol (TCP, UDP, ICMP, DNS, etc.)")
    bytes_sent: Optional[int] = Field(default=None, description="Bytes transmitted")
    bytes_received: Optional[int] = Field(default=None, description="Bytes received")
    packets: Optional[int] = Field(default=None, description="Total packet count")


class ProcessingMetadata(BaseModel):
    schema_version: str = Field(default="1.0", description="Universal Event Schema version")
    parser: str = Field(..., description="Parser identifier used to process this event")
    source_format: str = Field(..., description="Detected format: Syslog, CEF, LEEF, JSON, CSV, KeyValue")
    confidence: float = Field(default=1.0, description="Format detection confidence (0.0 - 1.0)")
    processed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO-8601 processing time")
    processing_time_ms: float = Field(default=0.0, description="Processing duration in milliseconds")
    tags: List[str] = Field(default_factory=list, description="Categorization or forensic tags")


class UniversalEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}", description="Unique identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="Normalized ISO-8601 UTC timestamp")
    source: SourceInfo = Field(default_factory=SourceInfo)
    event: EventInfo = Field(default_factory=EventInfo)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    user: Dict[str, Any] = Field(default_factory=dict, description="User context if available")
    process: Dict[str, Any] = Field(default_factory=dict, description="Process context if available")
    metadata: ProcessingMetadata
    raw_event: str = Field(..., description="Lossless, exact original raw log entry for forensic traceability")


class FailedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"fail_{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_event: str
    reason: str
    detected_format: Optional[str] = "unknown"
    parser_attempted: Optional[str] = None


class BatchProcessSummary(BaseModel):
    batch_id: str = Field(default_factory=lambda: f"batch_{uuid.uuid4().hex[:8]}")
    total_events: int = 0
    normalized_count: int = 0
    failed_count: int = 0
    processing_time_seconds: float = 0.0
    events_per_second: float = 0.0
    sources_breakdown: Dict[str, int] = Field(default_factory=dict)
    formats_breakdown: Dict[str, int] = Field(default_factory=dict)
    actions_breakdown: Dict[str, int] = Field(default_factory=dict)
