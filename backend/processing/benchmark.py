"""High-Volume Synthetic Benchmark & Stress Testing Generator.
Enables testing ingestion throughput from 1,000 to 1,000,000 events without RAM explosion.
"""
import random
from datetime import datetime, timedelta, timezone
from typing import Generator

IPS = [
    "192.168.1.105", "10.0.4.15", "172.16.2.88", "192.168.50.21", 
    "203.0.113.45", "198.51.100.12", "8.8.8.8", "1.1.1.1", 
    "185.220.101.5", "45.33.32.156", "10.200.1.50", "192.168.1.1"
]

PORTS = [80, 443, 22, 53, 8080, 8443, 3389, 500, 4500, 25, 123]


def generate_benchmark_stream(count: int = 10000) -> Generator[str, None, None]:
    """
    Generator yielding realistic multi-vendor log strings on the fly.
    Produces 0 RAM overhead for up to 1,000,000 lines.
    """
    base_time = datetime.now(timezone.utc) - timedelta(hours=5)

    for i in range(count):
        t = base_time + timedelta(milliseconds=i * 20)
        src_ip = IPS[i % len(IPS)]
        dst_ip = IPS[(i + 3) % len(IPS)]
        src_port = PORTS[i % len(PORTS)]
        dst_port = PORTS[(i + 1) % len(PORTS)]
        mod = i % 5

        if mod == 0:
            # Palo Alto Syslog RFC 5424
            proto = "tcp" if i % 2 == 0 else "udp"
            act = "allow" if i % 3 != 0 else "deny"
            yield f"<14>1 {t.strftime('%Y-%m-%dT%H:%M:%SZ')} PA-5220-FW01 1 {t.strftime('%Y/%m/%d')} TRAFFIC - - - src={src_ip} dst={dst_ip} sport={src_port} dport={dst_port} proto={proto} action={act} bytes_sent={500 + i % 1000}"

        elif mod == 1:
            # Cisco ASA Syslog
            act = "Deny" if i % 4 == 0 else "Built"
            sev = 4 if act == "Deny" else 6
            code = "106023" if act == "Deny" else "302013"
            t_str = t.strftime("%b %d %H:%M:%S")
            yield f"<164>{t_str} cisco-asa-edge : %ASA-{sev}-{code}: {act} tcp src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port} by access-group \"outside_in\""

        elif mod == 2:
            # ArcSight CEF
            act = "allow" if i % 5 != 0 else "drop"
            yield f"CEF:0|CheckPoint|SmartDefense|R81.20|threat:{100 + i % 50}|Packet inspected|{3 + (i % 7)}|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto=TCP act={act} msg=Perimeter boundary filter"

        elif mod == 3:
            # Suricata EVE JSON
            act = "alert" if i % 10 == 0 else "allow"
            yield f'{{"timestamp":"{t.isoformat()}","event_type":"traffic","src_ip":"{src_ip}","dest_ip":"{dst_ip}","src_port":{src_port},"dest_port":{dst_port},"proto":"TCP","action":"{act}","app_proto":"tls"}}'

        else:
            # Fortinet LEEF
            act = "allow" if i % 6 != 0 else "blocked"
            yield f"LEEF:1.0|Fortinet|FortiGate|7.0|10203|\tsrc={src_ip}\tdst={dst_ip}\tspt={src_port}\tdpt={dst_port}\tproto=6\tact={act}\tdevname=FGT-CORE-01"
