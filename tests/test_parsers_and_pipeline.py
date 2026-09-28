"""Comprehensive Automated Test Suite for LOGFORGE ULPF."""
import pytest
from backend.parsers.syslog_parser import SyslogParser
from backend.parsers.cef_parser import CEFParser
from backend.parsers.leef_parser import LEEFParser
from backend.parsers.json_parser import JSONParser
from backend.parsers.csv_parser import CSVParser
from backend.parsers.keyvalue_parser import KeyValueNetworkParser
from backend.parsers.registry import registry
from backend.normalization.normalizer import normalizer
from backend.processing.engine import engine
from backend.storage.db import store
from backend.export.exporter import exporter


def test_syslog_rfc5424_parsing():
    raw = "<14>1 2026-09-28T14:00:00Z fw01 traffic - - - src=10.0.0.5 dst=8.8.8.8 sport=53200 dport=443 proto=tcp action=allow"
    p = SyslogParser()
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    assert conf > 0.8
    extracted = p.parse(raw)
    assert extracted["src"] == "10.0.0.5"
    assert extracted["dst"] == "8.8.8.8"
    assert extracted["sport"] == "53200"
    assert extracted["dport"] == "443"
    assert extracted["action"] == "allow"


def test_cef_parsing():
    raw = "CEF:0|CheckPoint|SmartDefense|R81.20|threat:401|Packet dropped|8|src=192.168.1.50 dst=10.0.0.1 spt=45000 dpt=80 proto=TCP act=deny"
    p = CEFParser()
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    extracted = p.parse(raw)
    assert extracted["vendor"] == "CheckPoint"
    assert extracted["src"] == "192.168.1.50"
    assert extracted["dst"] == "10.0.0.1"
    assert extracted["spt"] == "45000"
    assert extracted["dpt"] == "80"
    assert extracted["act"] == "deny"


def test_leef_parsing():
    raw = "LEEF:1.0|Fortinet|FortiGate|7.0|10203|\tsrc=172.16.0.2\tdst=10.10.10.10\tspt=514\tdpt=514\tproto=17\tact=allow"
    p = LEEFParser()
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    extracted = p.parse(raw)
    assert extracted["vendor"] == "Fortinet"
    assert extracted["src"] == "172.16.0.2"
    assert extracted["dst"] == "10.10.10.10"
    assert extracted["act"] == "allow"


def test_cisco_asa_keyvalue_parsing():
    raw = "%ASA-4-106023: Deny tcp src outside:198.51.100.5/45678 dst inside:10.0.0.25/80 by access-group outside_in"
    p = KeyValueNetworkParser()
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    extracted = p.parse(raw)
    assert extracted["vendor"] == "Cisco"
    assert extracted["src_ip"] == "198.51.100.5"
    assert extracted["src_port"] == "45678"
    assert extracted["dst_ip"] == "10.0.0.25"
    assert extracted["dst_port"] == "80"
    assert extracted["action"] == "Deny"


def test_json_parsing():
    raw = '{"timestamp":"2026-09-28T14:20:00Z","src_ip":"192.168.1.200","dest_ip":"1.1.1.1","src_port":54321,"dest_port":53,"proto":"UDP","action":"allow"}'
    p = JSONParser()
    can_parse, conf = p.can_parse(raw)
    assert can_parse is True
    extracted = p.parse(raw)
    assert extracted["src_ip"] == "192.168.1.200"
    assert extracted["dest_ip"] == "1.1.1.1"


def test_normalization_and_lossless_traceability():
    raw = "CEF:0|PaloAlto|PAN-OS|10.1|traffic:allow|Permit web|3|sourceAddress=10.1.2.3 destinationAddress=172.217.16.206 sourcePort=60000 destinationPort=443 proto=tcp act=Permit"
    event, failed = engine.process_line(raw)
    assert failed is None
    assert event is not None
    
    # Check normalized standard fields
    assert event.network.source_ip == "10.1.2.3"
    assert event.network.destination_ip == "172.217.16.206"
    assert event.network.source_port == 60000
    assert event.network.destination_port == 443
    assert event.network.protocol == "TCP"
    assert event.event.action == "allow"  # Normalized from Permit
    
    # CRITICAL: Verify lossless raw preservation
    assert event.raw_event == raw


def test_malformed_event_resilience():
    corrupt_line = "Completely invalid nonsense line !@#$%^&*() without any structure"
    event, failed = engine.process_line(corrupt_line)
    assert event is None
    assert failed is not None
    assert failed.raw_event == corrupt_line
    assert "unknown format" in failed.reason.lower()


def test_exporter_formats():
    raw = '{"timestamp":"2026-09-28T14:30:00Z","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","action":"allow"}'
    event, _ = engine.process_line(raw)
    data = [event.model_dump()]
    
    # JSON
    json_out = exporter.export_json(data)
    assert "10.0.0.1" in json_out
    
    # JSONL
    jsonl_out = exporter.export_jsonl(data)
    assert "10.0.0.1" in jsonl_out
    assert jsonl_out.endswith("\n")
    
    # CSV
    csv_out = exporter.export_csv(data)
    assert "source_ip,destination_ip" in csv_out
    assert "10.0.0.1" in csv_out
